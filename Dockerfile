FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc AS ldap-builder

WORKDIR /build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libldap-dev \
        libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /build/
RUN pip install --no-cache-dir --require-hashes \
    --prefix=/install -r requirements.txt


FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh
LABEL org.opencontainers.image.description="Web SSH Terminal - A modern web-based SSH client with SFTP file manager"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.revision=$VCS_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    GUNICORN_THREADS=64 \
    MAX_SOCKET_CONNECTIONS=48 \
    MAX_SOCKET_CONNECTIONS_PER_USER=8 \
    DATA_DIR=/app/data

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY requirements.txt /app/
COPY --from=ldap-builder /install /usr/local
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libldap2 \
        libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python*/ensurepip

COPY . /app

RUN chown -R appuser:appuser /app && \
    mkdir -p /app/data/logs /app/data/keys /run/webssh-auth && \
    chown -R appuser:appuser /app/data && \
    chown appuser:appuser /run/webssh-auth && \
    chmod 700 /app/data && \
    chmod 700 /app/data/logs && \
    chmod 700 /app/data/keys && \
    chmod 700 /run/webssh-auth

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Persist the data dir (SQLite DB, encrypted keys, auto-generated SECRET_KEY).
# Auto-creates an anonymous volume on `docker run` so state survives restarts;
# override with a named/bind volume (see docker-compose.yml) for real durability.
VOLUME /app/data

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '5000') + '/ready', timeout=2).read(1)"

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --workers 1 --threads \"${GUNICORN_THREADS}\" --bind 0.0.0.0:5000 start:app"]
