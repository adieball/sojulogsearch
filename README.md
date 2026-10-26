# soju Log Search

A small web app for searching the message logs of a [soju](https://soju.im/) IRC bouncer.

- Full-text and regex search across all of your networks, channels and queries
- Filter by network and channel (multi-select sidebar) and by date range
- Results show matched lines with configurable context (3 / 5 / 10 / 20 lines)
- Open any result as a full-day log in the browser, jump to the matched line, step to the previous or next day
- Download the raw `.log` file of a day
- Log in with your **soju account** — no separate user management

Based on [adilogsearch](https://github.com/adieball/adilogsearch) (MIT), the same idea for local AdiIRC logs.

---

## How it works

**Logs.** soju must use the file message store:

```
message-store fs /var/lib/soju/logs/
```

soju writes one file per day and conversation:
`<logs>/<soju user>/<network>/<channel or nick>/<YYYY-MM-DD>.log`.
The app reads these files directly (read-only) and searches them on every request. That's fast enough for tens of megabytes of logs; there is no index to maintain.

**Login.** The app doesn't store any passwords. When you log in, it opens a connection to soju, authenticates with SASL PLAIN using the username and password you entered, and disconnects again before IRC registration completes. If soju accepts the credentials, you get a session cookie.

- Login names in soju's `user/network@client` form are accepted; only the user part is used.
- Each user only sees the logs under `<logs>/<their soju user>/`.
- Failed logins are rate-limited per client IP and per username.

**"Open in editor"** from adilogsearch doesn't exist here, because the app runs on the server. It is replaced by the in-browser day view and the download button.

---

## Running with Docker

```bash
git clone https://github.com/adieball/sojulogsearch.git
cd sojulogsearch
SLS_BIND=127.0.0.1:8090 SOJU_TLS_NAME=soju.example.org ./deploy.sh
```

`deploy.sh` builds the image and starts a container that

- uses host networking, so it can reach soju on `127.0.0.1:6697`,
- mounts soju's log directory read-only,
- runs as an unprivileged user that's added to the `soju` group, so it can read the logs,
- keeps its session secret in the `sojulogsearch-data` volume, so sessions survive restarts.

Then put an HTTPS reverse proxy in front of `SLS_BIND`. The session cookie is marked `Secure`, so the app must be served over HTTPS.

Example for Caddy:

```
logs.example.org {
	reverse_proxy 127.0.0.1:8090
}
```

If the proxy runs on another host, bind to an internal address (`SLS_BIND=10.0.0.2:8090`) and set `SLS_TRUSTED_PROXIES` to the proxy's IP, so failed logins are counted per real client IP (taken from `CF-Connecting-IP` or `X-Forwarded-For`).

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SLS_BIND` | `127.0.0.1:8090` | Address and port the app listens on |
| `SLS_TRUSTED_PROXIES` | *(empty)* | Comma-separated proxy IPs allowed to pass the client IP |
| `SOJU_HOST` | `127.0.0.1` | Where to reach soju for the login check |
| `SOJU_PORT` | `6697` | soju's IRC port |
| `SOJU_TLS` | `1` | Use TLS to talk to soju |
| `SOJU_TLS_NAME` | `SOJU_HOST` | Hostname on soju's certificate (SNI + verification) |
| `SOJU_TLS_VERIFY` | `1` | Verify soju's certificate |
| `SOJU_LOG_ROOT` | `/logs` in Docker | soju's `message-store fs` directory |
| `SLS_SESSION_DAYS` | `7` | How long a login stays valid |
| `SLS_COOKIE_SECURE` | `1` | Set to `0` only for local testing over plain HTTP |
| `SLS_SECRET_KEY` | *(generated)* | Session signing key; generated and stored in `/data` if unset |

`deploy.sh` additionally reads `SOJU_LOG_DIR` (host path of the logs, default `/var/lib/soju/logs`) and `SOJU_GID` (default: the `soju` group).

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
