FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS ldap-builder

WORKDIR /build

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


# Collects exactly the runtime closure into /rootfs: the interpreter from the
# official image, the shared libraries it and the extensions load, bash for
# entrypoint.sh and a static busybox for the few utilities the scripts call.
# Each copied Debian package also gets its dpkg status entry so scanners still
# see it.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS collector

ARG OS_PACKAGE_REFRESH=local
RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --yes --no-install-recommends \
        bash \
        busybox-static \
        libldap2 \
        libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ldap-builder /install /usr/local
COPY --from=gcr.io/distroless/cc-debian13@sha256:e8343d4a7da8bb210df0c3ea29de38bbadbba6c773bed0cd8bde506fca3a5c44 /etc/passwd /etc/group /tmp/distroless/
RUN set -eu; \
    python -m pip check; \
    python -m pip uninstall --yes pip; \
    rm -rf /usr/local/lib/python*/ensurepip /usr/local/lib/python*/idlelib \
        /usr/local/lib/python*/tkinter /usr/local/lib/python*/turtledemo \
        /usr/local/lib/python*/lib-dynload/_curses*.so \
        /usr/local/lib/python*/lib-dynload/_curses_panel*.so \
        /usr/local/lib/python*/lib-dynload/readline*.so \
        /usr/local/lib/python*/lib-dynload/_dbm*.so \
        /usr/local/lib/python*/lib-dynload/_gdbm*.so; \
    mkdir -p /rootfs/var/lib/dpkg/status.d /rootfs/usr/bin /rootfs/etc; \
    cp -a --parents /usr/local /rootfs/; \
    for pkg in bash busybox-static libtinfo6 libbz2-1.0 libffi8 liblzma5 libmpdec4 \
            libsqlite3-0 libuuid1 zlib1g libldap2 libsasl2-2 libsasl2-modules-db \
            libdb5.3t64; do \
        dpkg-query -L "$pkg" | while read -r path; do \
            if [ -f "$path" ] || [ -L "$path" ]; then cp -a --parents "$path" /rootfs/; fi; \
        done; \
        dpkg-query -s "$pkg" > "/rootfs/var/lib/dpkg/status.d/$pkg"; \
    done; \
    rm -rf /rootfs/usr/share/doc /rootfs/usr/share/man /rootfs/usr/share/info; \
    ln -s /usr/bin/busybox /rootfs/bin/sh 2>/dev/null || ln -s busybox /rootfs/usr/bin/sh; \
    for applet in cat chmod chown cmp id install mkdir mktemp rm tr; do \
        ln -s busybox "/rootfs/usr/bin/$applet"; \
    done; \
    cp /tmp/distroless/passwd /tmp/distroless/group /rootfs/etc/; \
    echo 'appuser:x:1000:1000::/home/appuser:/bin/sh' >> /rootfs/etc/passwd; \
    echo 'appuser:x:1000:' >> /rootfs/etc/group; \
    if grep -q '^users:' /rootfs/etc/group; then sed -i 's/^users:x:100:$/users:x:100:appuser/' /rootfs/etc/group; \
    else echo 'users:x:100:appuser' >> /rootfs/etc/group; fi; \
    mkdir -p /rootfs/home/appuser; \
    chown 1000:1000 /rootfs/home/appuser


FROM gcr.io/distroless/cc-debian13@sha256:e8343d4a7da8bb210df0c3ea29de38bbadbba6c773bed0cd8bde506fca3a5c44

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

COPY --from=collector /rootfs/ /

WORKDIR /app

COPY requirements.txt /app/
COPY app/ /app/app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY deployment/ldap_secret_cli.py /app/deployment/ldap_secret_cli.py
COPY config.py start.py LICENSE THIRD-PARTY-NOTICES NOTICE /app/
COPY entrypoint.sh /app/entrypoint.sh

RUN ["/usr/bin/busybox", "sh", "-c", "chown -R root:root /app && chmod -R go-w /app && chmod 755 /app/entrypoint.sh && mkdir -p /app/data/logs /app/data/keys /app/recovery /run/webssh-auth && chown -R appuser:appuser /app/data && chown appuser:appuser /app/recovery /run/webssh-auth && chmod 700 /app/data /app/data/logs /app/data/keys /app/recovery /run/webssh-auth && install -o appuser -g appuser -m 600 /dev/null /app/recovery/.webssh-volume"]

VOLUME /app/data

ENV WEBSSH_REVISION=$VCS_REF

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD for port in "${PORT:-5000}" 5000; do python -c "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + sys.argv[1] + '/ready', timeout=2).read(1)" "$port" && exit 0; done; exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --workers 1 --threads \"${GUNICORN_THREADS}\" --bind 0.0.0.0:5000 start:app"]
