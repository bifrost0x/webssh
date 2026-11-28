# Install on Unraid

WebSSH ships an Unraid template next to its source code:
[`unraid/webssh.xml`](https://github.com/bifrost0x/webssh/blob/main/unraid/webssh.xml).
It runs the official image `ghcr.io/bifrost0x/webssh:latest` with the same
homelab settings as the supplied `docker-compose.yml`. A test keeps both in
sync, so a new port, path or setting always reaches the template in the same
change.

## Before you install

WebSSH is an SSH gateway. Anyone who can sign in can reach every SSH target
that WebSSH's network allows. The template uses the homelab profile for a
trusted LAN: plain HTTP, any origin you use on the LAN, and browser
registration for the first account.

- Do not forward the WebUI port to the Internet. For remote access use a VPN,
  or follow [Production Deployment](Production-Deployment) for HTTPS through a
  reverse proxy with the production profile.
- The first account created in the browser becomes the administrator. Open the
  WebUI by the server's IP address and create it right after installation; a
  name such as `tower.local` works for this step only when it is listed in
  `ALLOWED_HOSTS`. To close that window entirely,
  add the variable `BOOTSTRAP_REGISTRATION_ENABLED` with the value `false`
  before you apply the template, then create the administrator from the Unraid
  terminal:

  ```bash
  docker exec -it WebSSH /app/webssh create-admin --username admin
  ```

## Install the template

From **Apps**, search for **WebSSH** and select **Install**.

Until the Community Apps listing is available, copy the template into
Unraid's user templates from the Unraid terminal:

```bash
curl -fsSL -o /boot/config/plugins/dockerMan/templates-user/my-WebSSH.xml \
  https://raw.githubusercontent.com/bifrost0x/webssh/main/unraid/webssh.xml
```

Then open **Docker > Add Container** and select the **WebSSH** template.

Review the settings and select **Apply**:

| Setting | Default | Notes |
|---|---|---|
| WebUI port | `5000` | Host port of the web interface. |
| Data | `/mnt/user/appdata/webssh/data` | Database, generated application secret, encrypted keys and user files. |
| Recovery | `/mnt/user/appdata/webssh/recovery` | Durable backup and restore staging. Keep it outside the data folder. |
| Allowed origins | `*` | Any address you use on the LAN. Set exact origins such as `http://tower:5000` and `Allow origin wildcard` to `false` to restrict it. |
| Trusted proxies | `0` | Number of reverse proxies in front of WebSSH. |
| Secure cookies | `false` | Set `true` when WebSSH is only reached over HTTPS. |

Advanced settings mirror the remaining homelab variables. The template sets no
secret: WebSSH generates its application secret on first start and keeps it in
the data folder. All other settings are described in the
[Configuration Reference](Configuration-Reference); add them as variables in the
template when you need them.

The template icon is `assets/webssh-icon.png` from the repository.

## First start

Open the WebUI from the Docker tab. A fresh instance redirects to the
registration page; create the administrator account there. Then add SSH hosts
as described in [SSH Connections and Host Keys](SSH-Connections-and-Host-Keys).

## Container user and appdata permissions

The template sets **Extra Parameters** to
`--user 99:100 --cap-drop ALL --security-opt no-new-privileges:true`, so
WebSSH runs as `nobody:users`, never as root, without Linux capabilities and
without privilege gains through setuid programs. When you apply a template,
Unraid creates missing appdata folders and gives them to `nobody:users`, so the
first start can write them. WebSSH then restricts the folders to mode `0700`.

Keep these parameters. Without `--user`, the image runs as its built-in user
(UID 1000), which cannot write the folders Unraid created.

If the log shows `must be owned and writable by the container user 99:100`,
the folders belong to another user, for example because they were created from
the terminal as root or restored from another system. Stop the container, then
run:

```bash
chown -R 99:100 /mnt/user/appdata/webssh
```

### Moving an existing Docker Compose installation

Compose installations store data as the image's built-in user (UID 1000).
Copy the data and recovery volumes into the appdata folders while the old
container is stopped, then run the `chown` command above. Keep the same data
folder, because it contains the application secret that decrypts stored keys.

## Keep appdata private

The data folder contains the application secret next to the encrypted SSH keys
and passwords. Anyone who can read both can decrypt them.

`99:100` is the identity most Unraid containers and guest access to shares use.
Mode `0700` keeps other users out, but not other processes running as `99:100`:
a container with that identity that maps `/mnt/user` or `/mnt/user/appdata` can
read WebSSH's data.

- Do not map `/mnt/user` or the `appdata` share into other containers that run
  as `99:100`, or run WebSSH as a dedicated user instead (see below).
- Do not export the `appdata` share over SMB or NFS.
- Leave the WebSSH appdata folder out of permission-reset tools such as
  **New Permissions**.
- Back up the data and recovery folders encrypted and off the server.
- Use the built-in backup described in
  [Backup, Restore, and Secret Rotation](Backup-Restore-and-Secret-Rotation)
  before major updates.

### Run as a dedicated user

A numeric ID that no other container or Unraid account uses isolates WebSSH's
data from them. Unraid accounts usually start at 1000, so pick a higher unused
number, for example `10000`. Stop the container, give the folders to that ID
and change only the `--user` value in **Extra Parameters**:

```bash
chown -R 10000:10000 /mnt/user/appdata/webssh
```

```text
--user 10000:10000 --cap-drop ALL --security-opt no-new-privileges:true
```

Do not use `0:0`. If you later change the folder paths, create and `chown` the
new folders before the first start, because Unraid gives new folders to
`nobody:users`.

## Updates

Unraid's update pulls the newest `latest` image and recreates the container
with the same appdata folders. Create a verified backup first. For controlled
updates, set **Repository** to a published version tag from the
[releases](https://github.com/bifrost0x/webssh/releases) instead of `latest`
and change it deliberately. Read the release notes before upgrading across
versions; see
[Upgrading, Rollback, and FAQ](Upgrading-Rollback-and-FAQ).

The update to 3.4 replaces the Python server with a Go server and migrates the
appdata once at the first start; the old data stays unchanged for a way back.
Read [Upgrading to 3.4](Upgrading-to-3.4) first. Paths, port and the container
user stay the same.

## Commands and console

The image has no shell, so the container's **Console** in the Docker tab has
nothing to open. Run WebSSH's commands from the Unraid terminal instead:

```bash
docker exec WebSSH /app/webssh help
docker exec -it WebSSH /app/webssh reset-password --username admin
```

Commands that need the server stopped, such as `backup create`, run in a
one-off container with the same appdata folders while the WebSSH container is
stopped:

```bash
docker stop WebSSH
docker run --rm --user 99:100 \
  -v /mnt/user/appdata/webssh/data:/app/data \
  -v /mnt/user/appdata/webssh/recovery:/app/recovery \
  -e BACKUP_TEMP_DIR=/app/recovery \
  ghcr.io/bifrost0x/webssh:latest backup create --confirm-offline
docker start WebSSH
```

Use the same image tag as the container and add the variables you changed in
the template.

WebSSH's graceful shutdown takes up to `RUNTIME_SHUTDOWN_GRACE_SECONDS` (5 by default, at most 30). Unraid stops containers
with its own timeout, which may be shorter; an early stop ends open SSH sessions
and transfers.

## Remove or reinstall

Removing the container keeps the appdata folders. Reinstalling with the same
paths reuses the data, accounts and application secret. To remove everything,
create a backup if you may need the data later, then delete
`/mnt/user/appdata/webssh`.

## Troubleshooting

- **Container stops right after start:** read the container log in the Docker
  tab. Permission errors name the required owner; see above.
- **Unhealthy:** see [Health Checks and Troubleshooting](Health-Checks-and-Troubleshooting).
- **Cannot reach an SSH host:** the container uses Unraid's bridge network.
  Hosts must be reachable from Docker containers on the server.

Ask Unraid questions in the [support thread](https://forums.unraid.net/topic/201292-support-bifrost0x-webssh/) and report bugs as
[GitHub issues](https://github.com/bifrost0x/webssh/issues).
