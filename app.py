#!/usr/bin/env python3
"""soju Log Search — web app for searching soju's on-disk message logs.

Users log in with their soju credentials (verified against soju itself via
SASL PLAIN) and can only search the logs that belong to their soju account.

Configuration is done with environment variables, see README.md.
"""

import base64
import collections
import os
import re
import secrets
import socket
import ssl
import threading
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

import regex
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, session, url_for)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_ROOT = Path(os.environ.get("SOJU_LOG_ROOT", "/var/lib/soju/logs"))
SOJU_HOST = os.environ.get("SOJU_HOST", "127.0.0.1")
SOJU_PORT = int(os.environ.get("SOJU_PORT", "6697"))
SOJU_TLS = _env_bool("SOJU_TLS", True)
# Name used for SNI and certificate verification when SOJU_HOST is an IP.
SOJU_TLS_NAME = os.environ.get("SOJU_TLS_NAME", SOJU_HOST)
SOJU_TLS_VERIFY = _env_bool("SOJU_TLS_VERIFY", True)
SOJU_TIMEOUT = float(os.environ.get("SOJU_TIMEOUT", "10"))

DATA_DIR = Path(os.environ.get("SLS_DATA_DIR", "./data"))
# Requests from these addresses may set the client IP via CF-Connecting-IP /
# X-Forwarded-For (reverse proxy in front of the app).
TRUSTED_PROXIES = {
    ip.strip() for ip in os.environ.get("SLS_TRUSTED_PROXIES", "").split(",") if ip.strip()
}
COOKIE_SECURE = _env_bool("SLS_COOKIE_SECURE", True)
SESSION_DAYS = int(os.environ.get("SLS_SESSION_DAYS", "7"))

MAX_QUERY_LEN = 200
MAX_BLOCKS = 2000
SEARCH_TIME_BUDGET = 20.0   # seconds per search request
REGEX_LINE_TIMEOUT = 0.05   # seconds per line, guards against catastrophic backtracking

LOGIN_WINDOW = 15 * 60
LOGIN_MAX_PER_IP = 10
LOGIN_MAX_PER_USER = 5

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DATE_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.log$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _load_secret_key() -> bytes:
    env = os.environ.get("SLS_SECRET_KEY")
    if env:
        return env.encode()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / "secret_key"
    if not key_file.exists():
        key_file.write_bytes(secrets.token_bytes(32))
        key_file.chmod(0o600)
    return key_file.read_bytes()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_NAME="sls_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=SESSION_DAYS),
)


# ---------------------------------------------------------------------------
# Authentication against soju (SASL PLAIN)
# ---------------------------------------------------------------------------

class SojuUnavailable(Exception):
    """soju could not be reached or spoke an unexpected protocol."""


def base_username(login: str) -> str:
    """Strip soju's "/network" and "@client" suffixes from a login name."""
    return login.split("/", 1)[0].split("@", 1)[0]


def soju_check_credentials(username: str, password: str) -> bool:
    """Return True if soju accepts *username*/*password* via SASL PLAIN.

    The connection is closed before IRC registration completes, so soju never
    treats it as a real client.
    """
    try:
        raw = socket.create_connection((SOJU_HOST, SOJU_PORT), timeout=SOJU_TIMEOUT)
    except OSError as exc:
        raise SojuUnavailable(str(exc)) from exc
    try:
        if SOJU_TLS:
            ctx = ssl.create_default_context()
            if not SOJU_TLS_VERIFY:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=SOJU_TLS_NAME)
        else:
            sock = raw
        sock.settimeout(SOJU_TIMEOUT)
        return _sasl_exchange(sock, username, password)
    except (OSError, ssl.SSLError) as exc:
        raise SojuUnavailable(str(exc)) from exc
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _sasl_exchange(sock, username: str, password: str) -> bool:
    buf = b""
    deadline = time.monotonic() + SOJU_TIMEOUT

    def send(line: str):
        sock.sendall(line.encode("utf-8") + b"\r\n")

    def lines():
        nonlocal buf
        while True:
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                yield line.decode("utf-8", errors="replace")
            if time.monotonic() > deadline:
                raise SojuUnavailable("timeout talking to soju")
            chunk = sock.recv(4096)
            if not chunk:
                raise SojuUnavailable("soju closed the connection")
            buf += chunk

    send("CAP REQ :sasl")
    send("NICK sojulogsearch")
    send("USER sojulogsearch 0 * :sojulogsearch")
    for line in lines():
        parts = line.split(" ")
        if parts and parts[0].startswith(":"):
            parts = parts[1:]
        if not parts:
            continue
        cmd = parts[0].upper()
        if cmd == "PING":
            send("PONG " + " ".join(parts[1:]))
        elif cmd == "CAP" and len(parts) >= 3 and parts[2].upper() == "ACK":
            send("AUTHENTICATE PLAIN")
        elif cmd == "CAP" and len(parts) >= 3 and parts[2].upper() == "NAK":
            raise SojuUnavailable("soju refused the sasl capability")
        elif cmd == "AUTHENTICATE" and len(parts) >= 2 and parts[1] == "+":
            payload = base64.b64encode(
                b"\0" + username.encode("utf-8") + b"\0" + password.encode("utf-8")
            ).decode("ascii")
            send("AUTHENTICATE " + payload)
        elif cmd == "903":          # RPL_SASLSUCCESS
            _quit(send)
            return True
        elif cmd in ("902", "904", "905", "906"):  # SASL failure numerics
            _quit(send)
            return False
        elif cmd == "ERROR":
            raise SojuUnavailable(line)
    return False


def _quit(send):
    try:
        send("QUIT")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Login rate limiting (in memory; run with a single worker process)
# ---------------------------------------------------------------------------

_failures = collections.defaultdict(collections.deque)
_failures_lock = threading.Lock()


def _prune(q: collections.deque, now: float):
    while q and now - q[0] > LOGIN_WINDOW:
        q.popleft()


def login_blocked(ip: str, user: str) -> bool:
    now = time.monotonic()
    with _failures_lock:
        qi, qu = _failures[("ip", ip)], _failures[("user", user.lower())]
        _prune(qi, now)
        _prune(qu, now)
        return len(qi) >= LOGIN_MAX_PER_IP or len(qu) >= LOGIN_MAX_PER_USER


def record_failure(ip: str, user: str):
    now = time.monotonic()
    with _failures_lock:
        _failures[("ip", ip)].append(now)
        _failures[("user", user.lower())].append(now)


def client_ip() -> str:
    remote = request.remote_addr or ""
    if remote in TRUSTED_PROXIES:
        cf = request.headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return remote


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf(token):
    expected = session.get("csrf")
    if not expected or not token or not secrets.compare_digest(expected, token):
        abort(403)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            if request.method == "GET" and not request.path.startswith("/api/"):
                return redirect(url_for("login"))
            return jsonify({"error": "Not logged in"}), 401
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    )
    return resp


# ---------------------------------------------------------------------------
# Log catalog
# ---------------------------------------------------------------------------

def user_root(user: str) -> Path:
    if not USERNAME_RE.match(user):
        abort(403)
    return LOG_ROOT / user


def is_irc_channel(name: str) -> bool:
    """True for RFC channel names (#, &, +, !). Nicks are queries."""
    return bool(name) and name[0] in "#&+!"


def _visible_dirs(path: Path):
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return []
    return [e for e in entries if e.is_dir() and not e.is_symlink()]


def collect_targets(user: str) -> dict:
    """Return {network: {target: [date, ...]}} with dates sorted ascending."""
    root = user_root(user)
    catalog: dict = {}
    for net_dir in _visible_dirs(root):
        targets = {}
        for target_dir in _visible_dirs(net_dir):
            dates = []
            try:
                for f in target_dir.iterdir():
                    m = DATE_FILE_RE.match(f.name)
                    if m and f.is_file() and not f.is_symlink():
                        dates.append(m.group(1))
            except OSError:
                continue
            if dates:
                targets[target_dir.name] = sorted(dates)
        if targets:
            catalog[net_dir.name] = targets
    return catalog


def sidebar_tree(user: str) -> dict:
    tree = {}
    for network, targets in collect_targets(user).items():
        items = [{
            "target": target,
            "kind": "channel" if is_irc_channel(target) else "query",
            "file_count": len(dates),
            "date_from": dates[0],
            "date_to": dates[-1],
        } for target, dates in targets.items()]
        tree[network] = {
            "channels": [i for i in items if i["kind"] == "channel"],
            "queries": [i for i in items if i["kind"] == "query"],
        }
    return tree


def log_path(user: str, network: str, target: str, date: str) -> Path:
    """Resolve a log file for the given user, or 404 if it doesn't exist.

    Network and target must be real directory names from the user's catalog,
    so no user-supplied string is ever joined into a path unchecked.
    """
    if not DATE_RE.match(date or ""):
        abort(404)
    dates = collect_targets(user).get(network, {}).get(target)
    if not dates or date not in dates:
        abort(404)
    root = user_root(user).resolve()
    path = (user_root(user) / network / target / f"{date}.log").resolve()
    if root not in path.parents:
        abort(404)
    return path


# ---------------------------------------------------------------------------
# Searching
# ---------------------------------------------------------------------------

def build_matcher(pattern: str, use_regex: bool, case_sensitive: bool):
    if use_regex:
        flags = 0 if case_sensitive else regex.IGNORECASE
        rx = regex.compile(pattern, flags)

        def match(line):
            try:
                return rx.search(line, timeout=REGEX_LINE_TIMEOUT) is not None
            except TimeoutError:
                return False
        return match

    needle = pattern if case_sensitive else pattern.lower()
    if case_sensitive:
        return lambda line: needle in line
    return lambda line: needle in line.lower()


def search_file(path: Path, match, context: int):
    """Search one file; return a list of match-block dicts."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []

    matched = [i for i, line in enumerate(lines) if match(line)]
    if not matched:
        return []

    # Group nearby matches to avoid duplicated context
    raw_blocks = [[matched[0]]]
    for m in matched[1:]:
        if m - raw_blocks[-1][-1] <= context * 2:
            raw_blocks[-1].append(m)
        else:
            raw_blocks.append([m])

    matched_set = set(matched)
    results = []
    for block in raw_blocks:
        start = max(0, block[0] - context)
        end = min(len(lines), block[-1] + context + 1)
        results.append({
            "first_match_line": block[0] + 1,
            "lines": [
                {"lineno": i + 1, "text": lines[i].rstrip("\n"), "is_match": i in matched_set}
                for i in range(start, end)
            ],
        })
    return results


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    return "ok\n", 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("user"):
            return redirect(url_for("index"))
        return render_template("login.html", error=None)

    check_csrf(request.form.get("csrf"))
    login_name = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = base_username(login_name)
    ip = client_ip()

    def fail(msg, status=401):
        return render_template("login.html", error=msg, username=login_name), status

    if not USERNAME_RE.match(user) or not password or len(password) > 256:
        return fail("Invalid username or password.")
    if login_blocked(ip, user):
        app.logger.warning("login rate-limited user=%s ip=%s", user, ip)
        return fail("Too many failed attempts. Try again later.", 429)

    try:
        ok = soju_check_credentials(user, password)
    except SojuUnavailable as exc:
        app.logger.error("soju unavailable during login: %s", exc)
        return fail("The bouncer is not reachable right now. Try again later.", 503)

    if not ok:
        record_failure(ip, user)
        app.logger.warning("login failed user=%s ip=%s", user, ip)
        return fail("Invalid username or password.")

    app.logger.info("login ok user=%s ip=%s", user, ip)
    session.clear()
    session.permanent = True
    session["user"] = user
    csrf_token()
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf(request.form.get("csrf"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    user = session["user"]
    return render_template("index.html", tree=sidebar_tree(user), user=user)


@app.route("/api/search", methods=["POST"])
@login_required
def api_search():
    check_csrf(request.headers.get("X-CSRF-Token"))
    user = session["user"]
    data = request.get_json(silent=True) or {}
    query = str(data.get("query", "")).strip()
    selected = data.get("targets") or []
    use_regex = bool(data.get("use_regex", False))
    case_sensitive = bool(data.get("case_sensitive", False))
    date_from = str(data.get("date_from") or "").strip() or None
    date_to = str(data.get("date_to") or "").strip() or None
    try:
        context = min(max(int(data.get("context", 5)), 0), 50)
    except (TypeError, ValueError):
        context = 5

    if not query or not isinstance(selected, list):
        return jsonify({"results": [], "truncated": False})
    if len(query) > MAX_QUERY_LEN:
        return jsonify({"error": f"Search term is longer than {MAX_QUERY_LEN} characters."}), 400
    for d in (date_from, date_to):
        if d and not DATE_RE.match(d):
            return jsonify({"error": "Invalid date."}), 400
    try:
        match = build_matcher(query, use_regex, case_sensitive)
    except regex.error as exc:
        return jsonify({"error": f"Invalid regex: {exc}"}), 400

    catalog = collect_targets(user)
    root = user_root(user)
    deadline = time.monotonic() + SEARCH_TIME_BUDGET
    total_blocks = 0
    truncated = False
    results = []

    for item in selected:
        if not isinstance(item, dict):
            continue
        network, target = item.get("network"), item.get("target")
        dates = catalog.get(network, {}).get(target)
        if not dates:
            continue
        days = []
        # Newest first, so a truncated search still shows recent hits
        for date in reversed(dates):
            if (date_from and date < date_from) or (date_to and date > date_to):
                continue
            if time.monotonic() > deadline or total_blocks >= MAX_BLOCKS:
                truncated = True
                break
            blocks = search_file(root / network / target / f"{date}.log", match, context)
            if blocks:
                total_blocks += len(blocks)
                days.append({"date": date, "blocks": blocks})
        if days:
            results.append({"network": network, "target": target, "days": days})
        if truncated:
            break

    results.sort(key=lambda r: (r["network"].lower(), r["target"].lower()))
    return jsonify({"results": results, "truncated": truncated})


@app.route("/view/<network>/<target>/<date>")
@login_required
def view_log(network, target, date):
    user = session["user"]
    path = log_path(user, network, target, date)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        abort(404)
    dates = collect_targets(user)[network][target]
    idx = dates.index(date)
    try:
        line = int(request.args.get("line", 0))
    except ValueError:
        line = 0
    return render_template(
        "view.html",
        user=user,
        network=network,
        target=target,
        date=date,
        lines=lines,
        line=line,
        query=request.args.get("q", ""),
        use_regex=request.args.get("regex") == "1",
        case_sensitive=request.args.get("case") == "1",
        prev_date=dates[idx - 1] if idx > 0 else None,
        next_date=dates[idx + 1] if idx + 1 < len(dates) else None,
    )


@app.route("/raw/<network>/<target>/<date>.log")
@login_required
def raw_log(network, target, date):
    path = log_path(session["user"], network, target, date)
    try:
        body = path.read_bytes()
    except OSError:
        abort(404)
    filename = re.sub(r"[^A-Za-z0-9._#-]", "_", f"{network}_{target}_{date}.log")
    return Response(body, mimetype="text/plain; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
    })


if __name__ == "__main__":
    app.run(host=os.environ.get("SLS_HOST", "127.0.0.1"),
            port=int(os.environ.get("SLS_PORT", "8090")), debug=False)
