#!/bin/sh
# Build and (re)start sojulogsearch next to soju.
#
# Settings come from the environment or from a deploy.env file next to this
# script (see deploy.env.example). Defaults match a Debian soju package install.
set -eu

cd "$(dirname "$0")"
if [ -f deploy.env ]; then
  set -a
  . ./deploy.env
  set +a
fi

SLS_BIND=${SLS_BIND:-127.0.0.1:8090}
SLS_TRUSTED_PROXIES=${SLS_TRUSTED_PROXIES:-}
SOJU_HOST=${SOJU_HOST:-127.0.0.1}
SOJU_PORT=${SOJU_PORT:-6697}
SOJU_TLS=${SOJU_TLS:-1}
SOJU_TLS_NAME=${SOJU_TLS_NAME:-$(hostname -f)}
SOJU_TLS_VERIFY=${SOJU_TLS_VERIFY:-1}
SOJU_LOG_DIR=${SOJU_LOG_DIR:-/var/lib/soju/logs}
SOJU_GID=${SOJU_GID:-$(getent group soju | cut -d: -f3)}
SLS_SESSION_DAYS=${SLS_SESSION_DAYS:-7}
SLS_SECRET_KEY=${SLS_SECRET_KEY:-}

if [ -z "$SOJU_GID" ]; then
  echo "Could not find the soju group; set SOJU_GID to the group that can read $SOJU_LOG_DIR." >&2
  exit 1
fi

docker build -q -t sojulogsearch .
docker rm -f sojulogsearch >/dev/null 2>&1 || true
docker run -d --name sojulogsearch --restart unless-stopped \
  --network host \
  --group-add "$SOJU_GID" \
  -v "$SOJU_LOG_DIR":/logs:ro \
  -v sojulogsearch-data:/data \
  -e SLS_BIND="$SLS_BIND" \
  -e SLS_TRUSTED_PROXIES="$SLS_TRUSTED_PROXIES" \
  -e SOJU_HOST="$SOJU_HOST" \
  -e SOJU_PORT="$SOJU_PORT" \
  -e SOJU_TLS="$SOJU_TLS" \
  -e SOJU_TLS_NAME="$SOJU_TLS_NAME" \
  -e SOJU_TLS_VERIFY="$SOJU_TLS_VERIFY" \
  -e SLS_SESSION_DAYS="$SLS_SESSION_DAYS" \
  ${SLS_SECRET_KEY:+-e SLS_SECRET_KEY="$SLS_SECRET_KEY"} \
  sojulogsearch
