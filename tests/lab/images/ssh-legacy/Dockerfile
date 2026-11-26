# Older OpenSSH (Debian 12, OpenSSH 9.2) restricted to SHA-1 era algorithms:
# ssh-rsa and ssh-dss host keys, SHA-1 key exchange, CBC ciphers. Lab only,
# bound to loopback.
FROM docker.io/library/debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        openssh-server python3 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/lab-sshd-legacy
RUN chmod 0755 /usr/local/bin/lab-sshd-legacy

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/lab-sshd-legacy"]
