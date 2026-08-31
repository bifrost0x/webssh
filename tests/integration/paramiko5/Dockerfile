FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

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
