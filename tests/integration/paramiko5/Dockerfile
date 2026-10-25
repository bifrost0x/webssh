FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash testuser \
    && echo 'testuser:Paramiko5-Test-Only!' | chpasswd \
    && mkdir -p /run/sshd /home/testuser/.ssh \
    && chown -R testuser:testuser /home/testuser/.ssh \
    && chmod 700 /home/testuser/.ssh \
    && ssh-keygen -A

COPY sshd_config /etc/ssh/sshd_config
COPY runtime/authorized_keys /home/testuser/.ssh/authorized_keys

RUN chown testuser:testuser /home/testuser/.ssh/authorized_keys \
    && chmod 600 /home/testuser/.ssh/authorized_keys \
    && /usr/sbin/sshd -t

EXPOSE 22

CMD ["sh", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
