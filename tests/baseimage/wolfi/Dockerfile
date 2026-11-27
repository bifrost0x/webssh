FROM cgr.dev/chainguard/wolfi-base:latest@sha256:c902a861151182e4ce2de29b8632ba3f7d75b68c35880580f16e353819e524d3 AS ldap-builder

WORKDIR /build

# CI changes this value per run/attempt so package updates cannot use stale layers.
ARG OS_PACKAGE_REFRESH=local
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        build-base \
        python-3.15 \
        python-3.15-dev \
        openldap-2.6-dev \
    # openldap-2.6-dev can lag behind libldap-2.6 in the rolling repository and
    # then ships a dangling libldap.so, which makes the linker fall back to the
    # non-PIC static archive. Point the dev links at the installed soname.
    && for lib in ldap lber; do \
        test -e "/usr/lib/lib$lib.so" || ln -sf "lib$lib.so.2" "/usr/lib/lib$lib.so"; \
    done

# Wolfi's interpreter lives under /usr, so a virtual environment keeps the
# application packages apart from the OS packages and copies as one tree.
COPY requirements.txt /build/
RUN python3.15 -m venv /opt/webssh \
    && /opt/webssh/bin/python -m pip install --no-cache-dir --require-hashes \
        -r requirements.txt \
    && /opt/webssh/bin/python -m pip check \
    && /opt/webssh/bin/python -m pip uninstall --yes pip


FROM cgr.dev/chainguard/wolfi-base:latest@sha256:c902a861151182e4ce2de29b8632ba3f7d75b68c35880580f16e353819e524d3

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh
LABEL org.opencontainers.image.description="Web SSH Terminal - A modern web-based SSH client with SFTP file manager"
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.revision=$VCS_REF

ENV PATH=/opt/webssh/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    GUNICORN_THREADS=64 \
    MAX_SOCKET_CONNECTIONS=48 \
    MAX_SOCKET_CONNECTIONS_PER_USER=8 \
    DATA_DIR=/app/data

WORKDIR /app

# Same identity as the Debian image: 1000:1000, plus "users" (100).
RUN addgroup -g 100 users 2>/dev/null || true; \
    addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser -g "" appuser \
    && addgroup appuser users

ARG OS_PACKAGE_REFRESH=local
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        bash \
        ca-certificates-bundle \
        openldap-2.6 \
        python-3.15 \
    && rm -rf /usr/lib/python3.15/ensurepip /usr/share/python-wheels

COPY requirements.txt /app/
COPY --from=ldap-builder /opt/webssh /opt/webssh
RUN python -c "import bonsai, cryptography, gunicorn, paramiko"

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
