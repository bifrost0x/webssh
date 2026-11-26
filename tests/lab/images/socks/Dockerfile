# Dante SOCKS5 in front of the SSH targets. LAB_SOCKS_MODE=open|auth.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache dante-server shadow
COPY sockd-open.conf sockd-auth.conf /etc/
COPY entrypoint.sh /usr/local/bin/lab-socks
RUN chmod 0755 /usr/local/bin/lab-socks

EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/lab-socks"]
