FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS ldap-builder

WORKDIR /build

# CI changes this value per run/attempt so package updates cannot use stale layers.
ARG OS_PACKAGE_REFRESH=local
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        build-base \
        openldap-dev \
        cyrus-sasl-dev

COPY requirements.txt /build/
RUN pip install --no-cache-dir --require-hashes \
    --prefix=/install -r requirements.txt


FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

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

# Same identity as the Debian image (1000:1000), which existing volumes,
# compose defaults and the Unraid template rely on.
# Debian's adduser also adds the account to "users" (100); keep that.
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser -g "" appuser \
    && addgroup appuser users

COPY requirements.txt /app/
COPY --from=ldap-builder /install /usr/local
ARG OS_PACKAGE_REFRESH=local
# bash runs entrypoint.sh unchanged; cmp comes from busybox.
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        bash \
        ca-certificates \
        libldap \
        libsasl \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python*/ensurepip

COPY app/ /app/app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY deployment/ldap_secret_cli.py /app/deployment/ldap_secret_cli.py
COPY config.py start.py LICENSE THIRD-PARTY-NOTICES NOTICE /app/
COPY entrypoint.sh /app/entrypoint.sh

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

VOLUME /app/data

ENV WEBSSH_REVISION=$VCS_REF

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD for port in "${PORT:-5000}" 5000; do python -c "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + sys.argv[1] + '/ready', timeout=2).read(1)" "$port" && exit 0; done; exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --workers 1 --threads \"${GUNICORN_THREADS}\" --bind 0.0.0.0:5000 start:app"]
