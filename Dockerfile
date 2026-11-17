FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS ldap-builder

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


FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
    && apt-get purge --yes mount \
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
COPY entrypoint.sh /app/entrypoint.sh

# Application code stays root-owned and read-only for the service, so a
# compromised process cannot change code that later starts or health checks
# run. Only the data and recovery directories belong to the service account.
# Docker seeds an empty named volume from the image on every new container and
# resets its root to the image directory's owner. The placeholder leaves the
# recovery volume non-empty after the first copy, so a custom-UID volume keeps
# its provisioned ownership when the container is recreated. Docker never
# copies into a volume that already has content.
RUN chown -R root:root /app && \
    chmod -R go-w /app && \
    chmod 755 /app/entrypoint.sh && \
    mkdir -p /app/data/logs /app/data/keys /app/recovery /run/webssh-auth && \
    chown -R appuser:appuser /app/data && \
    chown appuser:appuser /app/recovery && \
    chown appuser:appuser /run/webssh-auth && \
    chmod 700 /app/data && \
    chmod 700 /app/data/logs && \
    chmod 700 /app/data/keys && \
    chmod 700 /app/recovery && \
    chmod 700 /run/webssh-auth && \
    install -o appuser -g appuser -m 600 /dev/null /app/recovery/.webssh-volume

# Persist the data dir (SQLite DB, encrypted keys, auto-generated SECRET_KEY).
# Auto-creates an anonymous volume on `docker run` so state survives restarts;
# override with a named/bind volume (see docker-compose.yml) for real durability.
VOLUME /app/data

# Last so a new revision never invalidates the cached layers above.
ENV WEBSSH_REVISION=$VCS_REF

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '5000') + '/ready', timeout=2).read(1)"

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --workers 1 --threads \"${GUNICORN_THREADS}\" --bind 0.0.0.0:5000 start:app"]
