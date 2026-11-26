# Client tools, secret generator and small stubs for the test lab.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache \
        bind-tools \
        curl \
        iproute2 \
        jq \
        netcat-openbsd \
        openldap-clients \
        openssh-client-default \
        openssh-keygen \
        openssl \
        py3-bcrypt \
        py3-paramiko \
        python3 \
        samba-client \
    && adduser -D -H -u 10001 lab

COPY init/generate.py /opt/lab/generate.py
COPY github-stub/github_stub.py /opt/lab/github_stub.py
COPY images/tools/ts-node.sh /opt/lab/ts-node.sh
COPY images/tools/toxics.sh /opt/lab/toxics.sh
COPY windows/install.bat.in windows/enable-ssh.ps1.in /opt/lab/windows/
RUN chmod 0755 /opt/lab/*.sh

CMD ["sh"]
