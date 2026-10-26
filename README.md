# soju Log Search

A small web app for searching the message logs of a [soju](https://soju.im/) IRC bouncer.

- Full-text and regex search across all of your networks, channels and queries
- Filter by network and channel (multi-select sidebar) and by date range
- Results show matched lines with configurable context (3 / 5 / 10 / 20 lines)
- Open any result as a full-day log in the browser, jump to the matched line, step to the previous or next day
- Download the raw `.log` file of a day
- Log in with your **soju account**: no separate user management, and every user only sees their own logs

Based on [adilogsearch](https://github.com/adieball/adilogsearch) (MIT), the same idea for local AdiIRC logs.

---

## How it works

**Logs.** The app reads soju's log files directly (read-only) and searches them on every request. soju writes one file per day and conversation:

```
<message-store dir>/<soju user>/<network>/<channel or nick>/<YYYY-MM-DD>.log
```

There is no index to build or maintain. Searching tens of megabytes of logs takes about a second.

**Login.** The app stores no passwords. When you log in, it connects to soju, authenticates with SASL PLAIN using the username and password you entered, and disconnects before IRC registration completes. If soju accepts the credentials, you get a session cookie.

- Login names in soju's `user/network@client` form are accepted; only the user part is used.
- Each user only sees the logs under `<message-store dir>/<their soju user>/`.
- Failed logins are rate-limited per client IP and per username.

---

## Requirements

- **soju with the file message store.** In soju's config (usually `/etc/soju/config`):

  ```
  message-store fs /var/lib/soju/logs/
  ```

  The `db` and `memory` stores are not supported, because the app reads the log files directly.
  Older soju versions call this directive `log fs …`; it works the same way.

- **A soju listener the app can reach for the login check**, normally the regular IRC port. Any of these works:

  ```
  listen ircs://                     # TLS on port 6697 (most common)
  listen ircs://0.0.0.0:6697
  listen irc+insecure://127.0.0.1:6667
  ```

- **Docker** on the machine that runs soju. The app needs read access to soju's log directory, so it has to run on the same host.

- **An HTTPS reverse proxy** (Caddy, nginx, Traefik, …). The session cookie only works over HTTPS.

---

## Installation

### 1. Check your soju setup

```bash
grep -E '^(message-store|log|listen|tls|hostname)' /etc/soju/config
ls -ld /var/lib/soju/logs        # or whatever your message-store points to
getent group soju
```

Note down:

- the **log directory** from `message-store fs …`,
- the **port** soju listens on (`ircs://` without a port means 6697) and whether it uses TLS,
- the **hostname on soju's TLS certificate** (the domain in your `tls` certificate path, or the `hostname` directive),
- that the log directory is readable by the **`soju` group** (`drwxr-x--- soju soju` is fine).

With the Debian/Ubuntu package, soju creates the log directories as `drwxr-x---` and the files as `-rw-r-----`, owned by `soju:soju`, so this works out of the box. If yours aren't group-readable, make the existing ones readable with `sudo chmod -R g+rX /var/lib/soju/logs` and set `UMask=0027` for the soju service (`sudo systemctl edit soju`) so new files are too.

### 2. Get the code

```bash
git clone https://github.com/adieball/sojulogsearch.git
cd sojulogsearch
```

### 3. Configure

```bash
cp deploy.env.example deploy.env
```

Edit `deploy.env`. For a typical setup (soju and the reverse proxy on the same machine, soju on `ircs://` port 6697) you only need to change `SOJU_TLS_NAME`:

```
SLS_BIND=127.0.0.1:8090
SOJU_HOST=127.0.0.1
SOJU_PORT=6697
SOJU_TLS=1
SOJU_TLS_NAME=irc.example.org
SOJU_LOG_DIR=/var/lib/soju/logs
```

- `SOJU_TLS_NAME` must match soju's certificate, otherwise every login fails with a certificate error.
- If soju only listens on a plain-text port, set `SOJU_TLS=0` and `SOJU_PORT` to that port.
- If your reverse proxy runs on **another host**, bind to an internal address the proxy can reach (`SLS_BIND=10.0.0.2:8090`) and set `SLS_TRUSTED_PROXIES` to the proxy's IP. Then failed logins are counted per real client IP, taken from `CF-Connecting-IP` (Cloudflare) or `X-Forwarded-For`.

### 4. Start it

```bash
./deploy.sh
```

This builds the image and starts a container named `sojulogsearch` that

- uses host networking, so it can reach soju on `127.0.0.1`,
- mounts the log directory read-only,
- runs as an unprivileged user that's added to the `soju` group, so it can read the logs,
- keeps its session secret in the Docker volume `sojulogsearch-data`, so logins survive restarts,
- restarts automatically after a reboot.

Check that it's up:

```bash
docker ps --filter name=sojulogsearch
curl http://127.0.0.1:8090/healthz     # → ok
```

### 5. Put a reverse proxy in front

**Caddy:**

```
logs.example.org {
	reverse_proxy 127.0.0.1:8090
}
```

**nginx:**

```nginx
server {
    listen 443 ssl;
    server_name logs.example.org;
    # ssl_certificate / ssl_certificate_key …

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Behind Cloudflare, use the proxied (orange cloud) mode and SSL mode "Full (strict)".

### 6. Log in

Open `https://logs.example.org` and log in with your soju username and password. Users you add to soju later (`sojuctl user create …`) can log in right away.

---

## Updating

```bash
cd sojulogsearch
git pull
./deploy.sh
```

`deploy.sh` rebuilds the image and replaces the container. Sessions are kept.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "The bouncer is not reachable right now" on login | The app can't reach soju. Check `SOJU_HOST`/`SOJU_PORT`/`SOJU_TLS` against soju's `listen` lines, and `SOJU_TLS_NAME` against soju's certificate. `docker logs sojulogsearch` shows the exact error. |
| Login always says "Invalid username or password" | soju rejected the credentials. `journalctl -u soju` shows why (`user not found`, `wrong password`). |
| "Too many failed attempts" | Rate limit after 5 failed logins per user or 10 per IP within 15 minutes. Wait, or restart the container to reset it. |
| Logged in, but "No logs found for this account" | The container can't read the logs, or the user has none yet. Check `SOJU_LOG_DIR` and that the directory is readable by the `soju` group. If your soju group isn't called `soju`, set `SOJU_GID` in `deploy.env`. |
| Login form reloads without logging in | The site is served over plain HTTP. The session cookie requires HTTPS. |
| Everyone gets "Too many failed attempts" at once | The proxy runs on another host and all logins are counted against its IP. Set `SLS_TRUSTED_PROXIES` to the proxy's IP. |

---

## Configuration reference

All settings can go into `deploy.env` or be passed as environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `SLS_BIND` | `127.0.0.1:8090` | Address and port the app listens on |
| `SLS_TRUSTED_PROXIES` | *(empty)* | Comma-separated proxy IPs allowed to pass the client IP |
| `SOJU_HOST` | `127.0.0.1` | Where to reach soju for the login check |
| `SOJU_PORT` | `6697` | soju's IRC port |
| `SOJU_TLS` | `1` | Use TLS to talk to soju |
| `SOJU_TLS_NAME` | host's FQDN | Hostname on soju's certificate (SNI and verification) |
| `SOJU_TLS_VERIFY` | `1` | Verify soju's certificate. Only turn off for self-signed setups. |
| `SOJU_LOG_DIR` | `/var/lib/soju/logs` | soju's `message-store fs` directory on the host |
| `SOJU_GID` | GID of `soju` | Group that can read the log directory |
| `SLS_SESSION_DAYS` | `7` | How long a login stays valid |
| `SLS_SECRET_KEY` | *(generated)* | Session signing key; generated and stored in the data volume if unset |

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
SLS_COOKIE_SECURE=0 SOJU_LOG_ROOT=/path/to/logs python app.py
```

The tests use a temporary log tree and a fake soju for the SASL exchange.

---

## License

GPL-3.0, see [LICENSE](LICENSE). Parts of the search and UI code come from [adilogsearch](https://github.com/adieball/adilogsearch), MIT-licensed.
