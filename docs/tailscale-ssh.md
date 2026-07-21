# Tailscale SSH deployment and security

WebSSH can authenticate to a target with the Tailscale identity of the machine
or container running WebSSH. The browser user does not provide a password or a
private SSH key. The target must have Tailscale SSH enabled with
`tailscale set --ssh`, and the tailnet policy must authorize the WebSSH node.

## Shared identity security model

Tailscale sees the WebSSH node, not the individual WebSSH account that clicked
Connect. Therefore every WebSSH user authorized for this feature shares the
same tailnet identity and all permissions assigned to that node or tag.

Use this mode only in a trusted homelab or similarly controlled environment:

1. Give WebSSH a dedicated tag such as `tag:webssh`.
2. Limit that tag to TCP port 22 on only the required target tag or hosts.
3. Limit Tailscale SSH rules to the required remote OS usernames.
4. Keep WebSSH registration disabled or tightly controlled.
5. Configure WebSSH's optional target and remote-username allowlists as a
   second boundary. Tailnet ACL and SSH policy remain authoritative.

Every authorized or denied Tailscale SSH attempt is written to the security
audit log with the WebSSH username, target, remote username, client IP, and the
`shared-node` identity marker.

## WebSSH configuration

Tailscale SSH is off by default. Enable it explicitly:

```env
TAILSCALE_SSH_ENABLED=true
TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=operator
TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server,100.64.0.10
TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root,ubuntu
```

Administrators are allowed when the feature is enabled. The
`TAILSCALE_SSH_ALLOWED_WEBSSH_USERS` list grants access to additional WebSSH
usernames. Empty target or remote-user allowlists add no extra restriction;
they do not bypass Tailscale policy. Target matching is exact and
case-insensitive, while remote OS usernames are exact and case-sensitive.

## Example tailnet policy

Adapt tags, targets, and users to the deployment. This intentionally grants the
WebSSH tag only SSH access to tagged servers:

```json
{
  "tagOwners": {
    "tag:webssh": ["autogroup:admin"],
    "tag:servers": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:webssh"],
      "dst": ["tag:servers"],
      "ip": ["tcp:22"]
    }
  ],
  "ssh": [
    {
      "action": "accept",
      "src": ["tag:webssh"],
      "dst": ["tag:servers"],
      "users": ["root"]
    }
  ]
}
```

## Docker sidecar with persistent state

The sidecar is a separate Tailscale container that shares its network namespace
with WebSSH. Its `/var/lib/tailscale` volume preserves node registration across
container updates and restarts. Publish the WebSSH port on the Tailscale service
because `network_mode: service:tailscale` gives both containers one network
namespace.

### Safe first-time setup

Do not enable Tailscale SSH on a fresh, publicly reachable WebSSH database. The
first WebSSH account ever registered becomes an administrator, and administrators
can use Tailscale SSH whenever the feature is enabled.

Bootstrap the deployment in this order:

1. Save and start the sidecar configuration below as-is on a trusted network.
   It deliberately starts with `TAILSCALE_SSH_ENABLED=false` and leaves
   registration at its default so a fresh installation can create its first
   account.
2. Create the first WebSSH account. This account becomes the administrator.
3. In the Admin Panel, disable self-registration. The setting is stored in the
   persistent `webssh_data` volume.
4. Configure narrow target and remote-user allowlists, then change
   `TAILSCALE_SSH_ENABLED` to `true`.
5. Apply the updated configuration with `docker compose up -d`.

Do not set `REGISTRATION_ENABLED=False` before the first account exists. If you
want an environment-level fallback in addition to the saved Admin Panel
setting, add it only after the administrator bootstrap is complete.

### Homelab Compose example

This example follows the repository's existing homelab defaults: it permits
browser origins with `CORS_ORIGINS=*` and allows non-TLS HTTP cookies. Use it
only on a trusted network. The production HTTPS replacements are documented
immediately after the example.

```yaml
services:
  tailscale:
    image: tailscale/tailscale:stable
    hostname: webssh
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      - TS_AUTHKEY=${TS_AUTHKEY}
      - TS_AUTH_ONCE=true
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=false
      - TS_EXTRA_ARGS=--advertise-tags=tag:webssh
    volumes:
      - tailscale_state:/var/lib/tailscale
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
      - NET_RAW

  webssh:
    image: ghcr.io/bifrost0x/webssh:latest
    restart: unless-stopped
    network_mode: service:tailscale
    depends_on:
      - tailscale
    environment:
      - HOST=0.0.0.0
      - PORT=5000
      # Trusted homelab defaults, matching the repository Compose file.
      - CORS_ORIGINS=*
      - ALLOW_CORS_WILDCARD=true
      - SESSION_COOKIE_SECURE=false
      # Keep disabled until the first administrator exists and registration
      # has been disabled in the Admin Panel.
      - TAILSCALE_SSH_ENABLED=false
      # Leave empty to allow only existing WebSSH administrators.
      - TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=
      - TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server
      - TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root
    volumes:
      - webssh_data:/app/data

volumes:
  tailscale_state:
  webssh_data:
```

After the administrator bootstrap and allowlist configuration, enable the
feature by changing the value to `TAILSCALE_SSH_ENABLED=true`. Optionally add
`REGISTRATION_ENABLED=False` at that point as an environment-level fallback.

For an HTTPS deployment, replace the three homelab browser settings with the
public origin and secure cookies:

```yaml
      - CORS_ORIGINS=https://ssh.example.com
      - SESSION_COOKIE_SECURE=true
```

Remove `ALLOW_CORS_WILDCARD=true` when using a specific origin. If a reverse
proxy on the Docker host terminates TLS, also bind the published port to
loopback so clients cannot bypass HTTPS:

```yaml
    ports:
      - "127.0.0.1:5000:5000"
```

For a containerized reverse proxy, remove the `ports` block instead, attach the
`tailscale` service and proxy to the same internal Docker network, and proxy to
`tailscale:5000`. In both cases, configure `TRUSTED_PROXIES` as described in the
main README. Do not list both the wildcard and the specific origin.

Supply `TS_AUTHKEY` at deployment time through an environment file or secret
manager; do not commit it to Compose. Prefer a tagged, reusable or OAuth-issued
credential with the minimum required tag permission. After the persisted node
state exists, `TS_AUTH_ONCE=true` prevents unnecessary reauthentication on each
restart.
