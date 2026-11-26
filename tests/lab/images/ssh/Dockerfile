# Current OpenSSH with PAM (password, keyboard-interactive with TOTP) and
# public keys. One image serves ssh-modern, ssh-bastion, ssh-inner and the
# Tailscale SSH stand-in (LAB_SSH_ROLE=tailscale). tmux serves the
# persistent terminal sessions.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache openssh-server openssh-server-pam openssh-sftp-server \
        google-authenticator linux-pam shadow tmux
COPY sshd_config sshd_config_tailscale /etc/ssh/
COPY pam-sshd /etc/pam.d/sshd
COPY entrypoint.sh /usr/local/bin/lab-sshd
RUN chmod 0755 /usr/local/bin/lab-sshd && rm -f /etc/ssh/ssh_host_*

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/lab-sshd"]
