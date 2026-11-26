# OpenLDAP with StartTLS from the per-run lab CA. LAB_LDAP_NAME=ldap1|ldap2.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache openldap openldap-back-mdb openldap-clients
COPY slapd.conf.in /etc/openldap/lab-slapd.conf.in
COPY entrypoint.sh /usr/local/bin/lab-slapd
RUN chmod 0755 /usr/local/bin/lab-slapd

EXPOSE 389 636
ENTRYPOINT ["/usr/local/bin/lab-slapd"]
