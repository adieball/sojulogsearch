#!/bin/sh
# Build and (re)start sojulogsearch next to soju.
#
# Environment overrides (defaults match a Debian soju package install):
#   SLS_BIND          address:port to listen on (put the reverse proxy in front)
#   SLS_TRUSTED_PROXIES  comma-separated proxy IPs allowed to set the client IP
#   SOJU_TLS_NAME     hostname on soju's TLS certificate
#   SOJU_LOG_DIR      soju's "message-store fs" directory
set -eu

SLS_BIND=${SLS_BIND:-127.0.0.1:8090}
SLS_TRUSTED_PROXIES=${SLS_TRUSTED_PROXIES:-}
SOJU_TLS_NAME=${SOJU_TLS_NAME:-$(hostname -f)}
SOJU_LOG_DIR=${SOJU_LOG_DIR:-/var/lib/soju/logs}
SOJU_GID=${SOJU_GID:-$(getent group soju | cut -d: -f3)}

cd "$(dirname "$0")"
docker build -q -t sojulogsearch .
docker rm -f sojulogsearch >/dev/null 2>&1 || true
docker run -d --name sojulogsearch --restart unless-stopped \
  --network host \
  --group-add "$SOJU_GID" \
  -v "$SOJU_LOG_DIR":/logs:ro \
  -v sojulogsearch-data:/data \
  -e SLS_BIND="$SLS_BIND" \
  -e SLS_TRUSTED_PROXIES="$SLS_TRUSTED_PROXIES" \
  -e SOJU_TLS_NAME="$SOJU_TLS_NAME" \
  sojulogsearch
