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
5. Configure WebSSH's mandatory target and optional remote-username allowlists as a
   second boundary. Tailnet ACL and SSH policy remain authoritative.
6. Keep **Block ordinary SSH to tailnet nodes** (Admin → Integrations)
   enabled, which is the default. The WebSSH
   allowlists apply to Tailscale SSH connections; they only bound the node
   identity while ordinary connections cannot reach tailnet hosts.

Every authorized or denied Tailscale SSH attempt is written to the security
audit log with the WebSSH username, target, remote username, client IP, and the
`shared-node` identity marker.

## WebSSH configuration

Tailscale SSH is off by default. Enable it explicitly:

```env
TAILSCALE_SSH_ENABLED=true
TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=operator
TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server,100.64.0.10:2222
TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root,ubuntu
TAILSCALE_SSH_INTERFACE=tailscale0
```

Administrators are allowed when the feature is enabled. The
`TAILSCALE_SSH_ALLOWED_WEBSSH_USERS` list grants access to additional WebSSH
usernames. The target allowlist is mandatory whenever the feature is enabled.
A bare hostname, IPv4 address, or IPv6 address means port 22. Use
`hostname:port`, `IPv4:port`, or `[IPv6]:port` for another port. Target matching
is exact and case-insensitive, while remote OS usernames are exact and
case-sensitive. A production deployment refuses to start when the enabled
feature has an empty or malformed target list or an empty interface. The
homelab profile emits security warnings, ignores individual malformed entries
so valid siblings still work, and fails every connection closed if no valid
target or interface remains. Values stay dormant while the feature is disabled.
After DNS resolution, WebSSH accepts only an
address whose kernel route uses `TAILSCALE_SSH_INTERFACE` (default
`tailscale0`), pins that address, and binds the connecting socket to the same
interface. A route change cannot silently move the connection to another
interface.

Tailscale authentication cannot be combined with ProxyJump. The route and
interface proof applies only to a direct connection from the WebSSH host.

## Ordinary connections over the tailnet

A Tailscale SSH server authorizes the connecting node, not the password or key
the client offers. Without a further control, any signed-in WebSSH user could
open a password connection with an arbitrary password to a tailnet host and get
a shell under the shared node identity, bypassing the WebSSH user, target and
remote-user allowlists.

The admin setting **Block ordinary SSH to tailnet nodes** (Admin →
Integrations, enabled by default) closes that path. Changes take effect for the
next connection without a restart; the change is recorded in the security audit
log as `APPLICATION_FEATURE_CHANGED` with
`feature=tailscale_ssh_restrict_tailnet_routes`. While
`TAILSCALE_SSH_ENABLED=true` and `TAILSCALE_SSH_INTERFACE` is set, WebSSH
refuses, before opening a socket, every Tailscale node address for everything
except Tailscale SSH. A node address is one in `100.64.0.0/10` or
`fd7a:115c:a1e0::/48` (including the IPv4-mapped IPv6 form) whose kernel route
uses that interface. This applies to password and key terminal connections,
Gateway selectors, Jump Hosts and locally validated targets behind them,
SOCKS5 proxy endpoints and
locally validated SOCKS5 destinations, file transfers, automation runs, host
discovery and the reachability check. Saved Tailscale SSH hosts that the account
may still use stay checkable in the reachability check. The browser reports that
the host requires Tailscale SSH and links administrators to the setting;
automation records `tailscale_route_restricted`. The setting row shows whether
Tailscale SSH is enabled on the server, since it has no effect otherwise.

Hosts reached through subnet routes or an exit node are not affected; their own
SSH server checks the offered credentials. A `100.64.0.0/10` address that does
not route through the interface, such as carrier-grade NAT on the local network,
stays reachable. A node address whose kernel route cannot be determined, for
example because the route query fails or times out, is refused. An IPv4-mapped
IPv6 address is checked against the IPv4 route it actually uses. With
Tailscale SSH disabled, connection behavior is unchanged.

Proxies and jump hosts that resolve names themselves are covered too:

- A SOCKS5 proxy or jump host whose address is loopback, unspecified or one of
  the WebSSH host's own addresses is refused. Such a relay shares the WebSSH
  network namespace, for example tailscaled's own SOCKS5 server
  (`TS_SOCKS5_SERVER`) in the sidecar, so its connections leave with the node
  identity. A relay whose kernel route cannot be determined is refused as
  well.
- A target name handed to a SOCKS5 proxy with remote DNS, or to a jump host
  because only the bastion can resolve it, is refused when it ends in
  `.ts.net` (MagicDNS) or when it resolves locally to a restricted node
  address. A name that does not resolve on the WebSSH host is still passed on.

**Disabling Tailscale SSH does not remove the node from the tailnet.** The
restriction is only active while `TAILSCALE_SSH_ENABLED=true`. If the feature is
switched off while the sidecar stays logged in to the tailnet and the tailnet
policy still contains an `ssh` rule with `"action": "accept"` for the WebSSH
node or its tag, any WebSSH user can open a password connection with an
arbitrary password to those Tailscale SSH nodes and get a shell under the node
identity. Remove the node or its tag from such rules, or log the sidecar out of
the tailnet, before disabling the feature; otherwise keep the feature enabled
with the block on. While the feature is enabled and the block is off, WebSSH
logs a warning at startup and after a restore.

Disable the setting only when users must reach ordinary OpenSSH servers over
the tailnet with their own credentials and the tailnet SSH policy grants the
WebSSH node no access to hosts they can reach. Changing it requires admin
reauthentication. Installations that
already use Tailscale SSH and reach tailnet node addresses with passwords, keys,
Jump Hosts or SOCKS5 proxies should review those hosts before upgrading.

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

Do not enable Tailscale SSH on a fresh, publicly reachable WebSSH database.
Create the administrator explicitly on the Docker host before enabling the
shared Tailscale identity.

Bootstrap the deployment in this order:

1. Save and start the sidecar configuration below as-is on a trusted network.
   It deliberately starts with `TAILSCALE_SSH_ENABLED=false`.
2. Create the first administrator explicitly:
   ```bash
   docker compose exec webssh /app/entrypoint.sh flask --app start:app create-admin --username admin
   ```
3. Keep self-registration disabled in production; the production profile requires
   this. Enable optional public registration only in a homelab deployment.
   Because the administrator was created first, every later account created
   through public registration is non-administrative. On an otherwise empty
   installation, the first registered account would become administrator.
4. Configure narrow target and remote-user allowlists, then change
   `TAILSCALE_SSH_ENABLED` to `true`.
5. Apply the updated configuration with `docker compose up -d`.

Production self-registration is always disabled. In the homelab profile, a
registration setting saved in the Admin Panel takes precedence over the
environment default.

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
      # Keep online-restore rollback state durable and separate from DATA_DIR.
      - BACKUP_TEMP_DIR=/app/recovery
      - BACKUP_RECOVERY_DURABLE=true
      # Keep disabled until an administrator has been created with the CLI.
      - TAILSCALE_SSH_ENABLED=false
      # Leave empty to allow only existing WebSSH administrators.
      - TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=
      - TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server
      - TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root
      - TAILSCALE_SSH_INTERFACE=tailscale0
    volumes:
      - webssh_data:/app/data
      - webssh_recovery:/app/recovery

volumes:
  tailscale_state:
  webssh_data:
  webssh_recovery:
    driver: local
```

After the administrator bootstrap and allowlist configuration, enable the
feature by changing the value to `TAILSCALE_SSH_ENABLED=true`.

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
