FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache samba-server samba-common-tools samba-client
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/lab-samba
RUN chmod 0755 /usr/local/bin/lab-samba && testparm -s /etc/samba/smb.conf >/dev/null

EXPOSE 445
ENTRYPOINT ["/usr/local/bin/lab-samba"]
