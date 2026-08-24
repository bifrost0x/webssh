FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

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
