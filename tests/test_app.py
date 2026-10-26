import base64
import os
import re
import socket
import threading

import pytest

os.environ.setdefault("SLS_SECRET_KEY", "test-secret")
os.environ.setdefault("SLS_COOKIE_SECURE", "0")

import app as sls  # noqa: E402


@pytest.fixture
def logs(tmp_path, monkeypatch):
    def write(user, network, target, date, text):
        d = tmp_path / user / network / target
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{date}.log").write_text(text, encoding="utf-8")

    write("alice", "libera", "#chan", "2026-10-01", "[10:00:00] <bob> hello world\n[10:00:05] <alice> hi\n")
    write("alice", "libera", "#chan", "2026-10-02", "[09:00:00] <bob> another HELLO\n")
    write("alice", "libera", "carol", "2026-10-02", "[09:30:00] <carol> secret hello\n")
    write("mallory", "libera", "#chan", "2026-10-02", "[11:00:00] <mallory> hello from mallory\n")
    monkeypatch.setattr(sls, "LOG_ROOT", tmp_path)
    return tmp_path


@pytest.fixture
def client(logs):
    sls.app.config["TESTING"] = True
    sls._failures.clear()
    return sls.app.test_client()


def csrf_of(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(client, monkeypatch, user="alice", ok=True):
    monkeypatch.setattr(sls, "soju_check_credentials", lambda u, p: ok)
    return client.post("/login", data={"username": user, "password": "pw", "csrf": csrf_of(client)})


def api_csrf(client):
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def search(client, token, **body):
    body.setdefault("targets", [{"network": "libera", "target": "#chan"}])
    return client.post("/api/search", json=body, headers={"X-CSRF-Token": token})


def test_index_requires_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")


def test_login_and_search(client, monkeypatch):
    assert login(client, monkeypatch).status_code == 302
    token = api_csrf(client)
    data = search(client, token, query="hello").get_json()
    days = data["results"][0]["days"]
    assert [d["date"] for d in days] == ["2026-10-02", "2026-10-01"]
    assert days[1]["blocks"][0]["first_match_line"] == 1


def test_login_strips_network_and_client_suffix(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(sls, "soju_check_credentials",
                        lambda u, p: seen.setdefault("user", u) == "alice")
    client.post("/login", data={"username": "alice/libera@phone", "password": "pw",
                                "csrf": csrf_of(client)})
    assert seen["user"] == "alice"
    assert client.get("/").status_code == 200


def test_failed_login(client, monkeypatch):
    resp = login(client, monkeypatch, ok=False)
    assert resp.status_code == 401
    assert client.get("/").status_code == 302


def test_login_rate_limit(client, monkeypatch):
    for _ in range(sls.LOGIN_MAX_PER_USER):
        login(client, monkeypatch, ok=False)
    assert login(client, monkeypatch, ok=True).status_code == 429


def test_login_requires_csrf(client, monkeypatch):
    monkeypatch.setattr(sls, "soju_check_credentials", lambda u, p: True)
    client.get("/login")
    resp = client.post("/login", data={"username": "alice", "password": "pw"})
    assert resp.status_code == 403


def test_search_requires_csrf_header(client, monkeypatch):
    login(client, monkeypatch)
    resp = client.post("/api/search", json={"query": "hello", "targets": []})
    assert resp.status_code == 403


def test_user_cannot_search_other_users_logs(client, monkeypatch):
    login(client, monkeypatch, user="alice")
    token = api_csrf(client)
    data = search(client, token, query="mallory").get_json()
    assert data["results"] == []
    data = search(client, token, query="hello",
                  targets=[{"network": "../mallory/libera", "target": "#chan"}]).get_json()
    assert data["results"] == []


def test_case_sensitive_and_regex(client, monkeypatch):
    login(client, monkeypatch)
    token = api_csrf(client)
    data = search(client, token, query="HELLO", case_sensitive=True).get_json()
    assert [d["date"] for d in data["results"][0]["days"]] == ["2026-10-02"]
    data = search(client, token, query=r"hel+o\s+world", use_regex=True).get_json()
    assert [d["date"] for d in data["results"][0]["days"]] == ["2026-10-01"]
    resp = search(client, token, query="(", use_regex=True)
    assert resp.status_code == 400


def test_date_filter(client, monkeypatch):
    login(client, monkeypatch)
    token = api_csrf(client)
    data = search(client, token, query="hello", date_from="2026-10-02").get_json()
    assert [d["date"] for d in data["results"][0]["days"]] == ["2026-10-02"]


def test_view_and_raw(client, monkeypatch):
    login(client, monkeypatch)
    resp = client.get("/view/libera/%23chan/2026-10-01?line=2&q=hi")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert 'id="L2"' in html
    assert "/view/libera/%23chan/2026-10-02" in html  # link to the next day
    raw = client.get("/raw/libera/%23chan/2026-10-01.log")
    assert raw.status_code == 200
    assert b"hello world" in raw.data
    assert "attachment" in raw.headers["Content-Disposition"]


def test_view_rejects_unknown_and_foreign_paths(client, monkeypatch):
    login(client, monkeypatch, user="alice")
    assert client.get("/view/libera/%23chan/2026-10-03").status_code == 404
    assert client.get("/view/libera/%23chan/..%2F..%2Fx").status_code == 404
    assert client.get("/raw/..%2Fmallory/%23chan/2026-10-02.log").status_code == 404


def test_logs_are_escaped_in_view(client, monkeypatch, logs):
    d = logs / "alice" / "libera" / "#chan"
    (d / "2026-10-03.log").write_text("[10:00:00] <x> <script>alert(1)</script>\n")
    login(client, monkeypatch)
    html = client.get("/view/libera/%23chan/2026-10-03").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# SASL exchange against a fake soju
# ---------------------------------------------------------------------------

def fake_soju(valid_user, valid_pw):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        f = conn.makefile("rb")

        def send(s):
            conn.sendall(s.encode() + b"\r\n")

        for raw in f:
            line = raw.decode().strip()
            if line == "CAP REQ :sasl":
                send(":soju CAP * ACK :sasl")
            elif line == "AUTHENTICATE PLAIN":
                send("AUTHENTICATE +")
            elif line.startswith("AUTHENTICATE "):
                _, user, pw = base64.b64decode(line.split(" ", 1)[1]).split(b"\0")
                if (user.decode(), pw.decode()) == (valid_user, valid_pw):
                    send(":soju 903 * :SASL authentication successful")
                else:
                    send(":soju 904 * :SASL authentication failed")
            elif line == "QUIT":
                break
        conn.close()
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


@pytest.mark.parametrize("pw,expected", [("right", True), ("wrong", False)])
def test_sasl_exchange(monkeypatch, pw, expected):
    port = fake_soju("alice", "right")
    monkeypatch.setattr(sls, "SOJU_TLS", False)
    monkeypatch.setattr(sls, "SOJU_HOST", "127.0.0.1")
    monkeypatch.setattr(sls, "SOJU_PORT", port)
    assert sls.soju_check_credentials("alice", pw) is expected


def test_soju_unreachable(monkeypatch):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    monkeypatch.setattr(sls, "SOJU_TLS", False)
    monkeypatch.setattr(sls, "SOJU_PORT", port)
    with pytest.raises(sls.SojuUnavailable):
        sls.soju_check_credentials("alice", "pw")
