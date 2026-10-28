FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS ldap-builder

WORKDIR /build

# CI changes this value per run/attempt so package updates cannot use stale layers.
ARG OS_PACKAGE_REFRESH=local
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libldap-dev \
        libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /build/
RUN pip install --no-cache-dir --require-hashes \
    --prefix=/install -r requirements.txt


FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh
LABEL org.opencontainers.image.description="Web SSH Terminal - A modern web-based SSH client with SFTP file manager"
LABEL org.opencontainers.image.licenses=Apache-2.0
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
ARG OS_PACKAGE_REFRESH=local
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libldap2 \
        libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python*/ensurepip

# Copy only runtime inputs, even when building from a developer's checkout.
# .dockerignore also filters secrets and authoring files inside these trees.
COPY app/ /app/app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY deployment/ldap_secret_cli.py /app/deployment/ldap_secret_cli.py
COPY config.py start.py LICENSE THIRD-PARTY-NOTICES NOTICE /app/

RUN chown -R appuser:appuser /app && \
    mkdir -p /app/data/logs /app/data/keys /app/recovery /run/webssh-auth && \
    chown -R appuser:appuser /app/data && \
    chown appuser:appuser /app/recovery && \
    chown appuser:appuser /run/webssh-auth && \
    chmod 700 /app/data && \
    chmod 700 /app/data/logs && \
    chmod 700 /app/data/keys && \
    chmod 700 /app/recovery && \
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
