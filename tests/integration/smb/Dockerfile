FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
    && apt-get upgrade --yes \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        samba \
        smbclient \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/webssh-smb-lab
RUN chmod 755 /usr/local/bin/webssh-smb-lab

EXPOSE 445

HEALTHCHECK --interval=2s --timeout=3s --retries=30 \
    CMD smbclient -L //127.0.0.1 -U 'smbuser%Smb-Lab-Only-42!' -m SMB3 >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/webssh-smb-lab"]
