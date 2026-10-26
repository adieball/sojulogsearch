FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOJU_LOG_ROOT=/logs \
    SLS_DATA_DIR=/data \
    SLS_BIND=127.0.0.1:8090

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates templates

RUN useradd --system --uid 10001 --create-home app \
    && mkdir -p /data && chown app /data
USER app
VOLUME /data

HEALTHCHECK --interval=60s --timeout=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://' + os.environ['SLS_BIND'] + '/healthz', timeout=4)"

# One worker on purpose: login rate limiting is kept in memory.
CMD exec gunicorn --workers 1 --threads 8 --bind "$SLS_BIND" --access-logfile - app:app
