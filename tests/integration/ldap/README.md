# Disposable LDAP integration lab

This lab exists only for local integration testing. It uses published test
passwords, an ephemeral CA, and a pinned OpenLDAP test image. Never deploy it as
real identity infrastructure.

```bash
docker compose -f tests/integration/ldap/docker-compose.yml up --build
```

Open `http://localhost:5050`, create the first local administrator, create a
non-admin local user named `alice`, and choose **Link LDAP** for that account.

- Directory username: `alice`
- Directory password for login: `alice-password`
- Bind account and CA are installed automatically into the test secret volume.

Stop and delete only the disposable lab volumes with:

```bash
docker compose -f tests/integration/ldap/docker-compose.yml down -v
```
