# Disposable OpenSSH host with a pinned Herdr release for integration tests.
ARG TARGETARCH

FROM scratch AS herdr-amd64
ADD --checksum=sha256:14d9e8bc8b4a9e0118d77c32266f76d461f09b40342eb23752960bd89f59929d --chmod=0755 \
    https://github.com/herdrdev/herdr/releases/download/v0.9.5/herdr-linux-x86_64 /herdr

FROM scratch AS herdr-arm64
ADD --checksum=sha256:17d7536f2da50859523680ef279dffcac8e4a235f4e46fe8da6c2ec44141897c --chmod=0755 \
    https://github.com/herdrdev/herdr/releases/download/v0.9.5/herdr-linux-aarch64 /herdr

FROM herdr-${TARGETARCH} AS herdr

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

# testuser has no Herdr at all. agentuser has it only where the official
# installer puts it, outside the PATH of a non-login exec channel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash testuser \
    && useradd --create-home --shell /bin/bash agentuser \
    && echo 'testuser:Paramiko5-Test-Only!' | chpasswd \
    && echo 'agentuser:Paramiko5-Test-Only!' | chpasswd \
    && mkdir -p /run/sshd /home/agentuser/.local/bin \
    && ssh-keygen -A

COPY --from=herdr --chown=agentuser:agentuser /herdr /home/agentuser/.local/bin/herdr
COPY sshd_config /etc/ssh/sshd_config

RUN chown -R agentuser:agentuser /home/agentuser/.local \
    && /usr/sbin/sshd -t

EXPOSE 22

CMD ["sh", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
