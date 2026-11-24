# Tailscale SSH

Tailscale SSH is optional and disabled by default. Every authorized WebSSH user
uses the WebSSH node's same Tailscale identity. This is a stronger trust
boundary than ordinary per-user SSH credentials.

## Enable only when all controls exist

Use Tailscale SSH only when you have:

- a dedicated Tailscale tag for the WebSSH node;
- narrow tailnet ACL and SSH rules;
- trusted WebSSH administrators or an explicit non-admin allowlist;
- a mandatory exact target-and-port allowlist;
- exact remote operating-system username allowlists;
- a tested local WebSSH administrator and recovery path;
- persistent Tailscale node state.

Hiding the UI is not authorization. The backend enforces the WebSSH user,
target, and remote-user allowlists for Tailscale SSH connections; the tailnet
ACL and SSH policy remain authoritative for the node itself. Tailscale SSH
servers authorize the WebSSH node, not the password or key a client offers, so
these allowlists only hold while ordinary connections cannot reach tailnet
hosts. WebSSH therefore reserves tailnet routes for Tailscale SSH by default;
see [Ordinary SSH over the tailnet](#ordinary-ssh-over-the-tailnet).

## WebSSH settings

```bash
TAILSCALE_SSH_ENABLED=true
TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=operator
TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server,100.64.0.10:2222
TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root,ubuntu
TAILSCALE_SSH_INTERFACE=tailscale0
```

Administrators are authorized by role when the feature is enabled. The user
allowlist adds specifically trusted non-admin WebSSH accounts. The target list
is required when the feature is enabled. A bare hostname, IPv4 address, or IPv6
address means port 22; use `hostname:port`, `IPv4:port`, or `[IPv6]:port` for
another port. Production refuses to start with an empty or malformed enabled
target list or an empty interface. Homelab emits security warnings, ignores
individual malformed entries so valid siblings still work, and fails every
connection closed if no valid target or interface remains. Dormant values are
tolerated while the feature is disabled. WebSSH resolves once, accepts only an
address whose kernel route uses `TAILSCALE_SSH_INTERFACE` (default
`tailscale0`), pins that address, and binds the connecting socket to the same
interface. A route change cannot silently move the connection to another
interface. An empty remote-user list still delegates that dimension to
tailnet SSH policy.

Tailscale authentication cannot be combined with ProxyJump. The route and
interface proof applies only to a direct connection from the WebSSH host.

## Ordinary SSH over the tailnet

The admin setting **Block ordinary SSH to tailnet nodes** (Admin →
Integrations) is enabled by default and takes effect only while
`TAILSCALE_SSH_ENABLED=true` and `TAILSCALE_SSH_INTERFACE` is set. A change
applies to the next connection without a restart, requires admin
reauthentication, and is recorded in the security audit log as
`APPLICATION_FEATURE_CHANGED` with
`feature=tailscale_ssh_restrict_tailnet_routes`. It
covers Tailscale node addresses only: an address in `100.64.0.0/10` or
`fd7a:115c:a1e0::/48` (including the IPv4-mapped IPv6 form) whose kernel route
uses that interface. WebSSH refuses such an address for everything except
Tailscale SSH, before it opens a socket:

- password and key terminal connections, including Gateway selectors;
- Jump Hosts and targets behind them that WebSSH validates locally;
- SOCKS5 proxy endpoints and locally validated SOCKS5 destinations;
- file-transfer connections and automation runs;
- host discovery and the reachability check. Saved Tailscale SSH hosts that
  the account may still use stay checkable.

The browser shows that the host requires Tailscale SSH (administrators also get
a link to the setting), and automation records
the reason `tailscale_route_restricted`. Without this restriction, any signed-in
user could open a password connection with an arbitrary password to a tailnet
host running Tailscale SSH and obtain a shell under the shared node identity,
outside every WebSSH allowlist.

Hosts reached through subnet routes or an exit node are not affected: they run
their own SSH server, which checks the offered password or key. A `100.64.0.0/10`
address that does not route through the interface, such as carrier-grade NAT on
the local network, also stays reachable. If the kernel route of a node address
cannot be determined, for example because the route query fails or times out,
the address is refused. An IPv4-mapped IPv6 address is checked against the
IPv4 route, because the connection leaves over IPv4. When Tailscale SSH is
disabled, connections behave exactly as before.

Proxies and jump hosts that resolve names themselves are covered too:

- A SOCKS5 proxy or jump host whose address is loopback, unspecified or one of
  the WebSSH host's own addresses is refused. Such a relay shares the WebSSH
  network namespace, for example tailscaled's own SOCKS5 server
  (`TS_SOCKS5_SERVER`) in the sidecar, so its connections leave with the node
  identity.
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
the tailnet with their own credentials, and only when the tailnet SSH policy
does not grant the WebSSH node access to any host those users can reach. With
the restriction lifted, the WebSSH allowlists no longer bound what the node
identity can be used for.

When upgrading an installation that already has Tailscale SSH enabled, check
whether users reach tailnet node addresses with passwords, keys, Jump Hosts or
SOCKS5 proxies. Those connections now fail until the hosts are added to the Tailscale
SSH allowlists or the operator opts out.

## Tailnet policy concept

Use a dedicated source tag such as `tag:webssh` and target tag such as
`tag:servers`. Grant only TCP/22 and only the remote users that WebSSH should
reach.

Illustrative policy:

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

Adapt this to the current Tailscale policy schema and organizational controls.
The example is intentionally narrow.

## Persistent sidecar model

A Tailscale sidecar can share its network namespace with WebSSH. Persist
`/var/lib/tailscale` so the node identity survives updates.

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
      - CORS_ORIGINS=*
      - ALLOW_CORS_WILDCARD=true
      - SESSION_COOKIE_SECURE=false
      - BACKUP_TEMP_DIR=/app/recovery
      - BACKUP_RECOVERY_DURABLE=true
      - TAILSCALE_SSH_ENABLED=false
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

The example starts with Tailscale SSH disabled.

## Safe bootstrap order

1. Start the sidecar deployment on a trusted network with
   `TAILSCALE_SSH_ENABLED=false`.
2. Create the first WebSSH administrator explicitly with the CLI.
3. Keep ordinary registration closed unless deliberately needed.
4. Configure tailnet policy and exact WebSSH allowlists.
5. Enable Tailscale SSH.
6. Recreate the service and test one narrow target/user combination.

## HTTPS browser access

These changes configure HTTPS browser access; they do not switch the application
from the homelab profile to production. For production, also follow
[Production Deployment](Production-Deployment.md), including
`DEPLOYMENT_PROFILE=production`, disabled registration and bootstrap, and trusted
proxy configuration matched to your actual proxy topology.

Replace homelab CORS and cookie settings with:

```yaml
environment:
  - CORS_ORIGINS=https://ssh.example.com
  - SESSION_COOKIE_SECURE=true
```

Remove wildcard CORS. If a reverse proxy on the host terminates TLS, bind the
published port to loopback:

```yaml
ports:
  - "127.0.0.1:5000:5000"
```

For a containerized proxy, remove the public port and use a private shared
network.

## Auth key handling

Do not commit `TS_AUTHKEY`. Supply it through an environment file or secret
manager. Prefer a tagged reusable or OAuth-issued credential with only the
permission needed to own `tag:webssh`. `TS_AUTH_ONCE=true` avoids unnecessary
reauthentication after persistent node state exists.

## User experience

Authorized profiles can select Tailscale SSH instead of a password or stored
key. A saved profile can launch directly when no interactive credential is
needed. Manual reconnect can also proceed directly while authorization remains
valid.

## Troubleshooting

### Tailscale option is absent

Check the feature flag and whether the WebSSH account is an administrator or is
listed in `TAILSCALE_SSH_ALLOWED_WEBSSH_USERS`.

### Target is rejected

Check the exact WebSSH target allowlist, DNS/Tailscale name, tailnet grants, SSH
rules, and remote-user allowlist.

### Password or key connection to a tailnet host is refused

The address is a Tailscale node address that routes through
`TAILSCALE_SSH_INTERFACE` while Tailscale SSH is enabled. Connect with Tailscale SSH and add the host to the allowlists, or see
[Ordinary SSH over the tailnet](#ordinary-ssh-over-the-tailnet) before opting
out.

### Node identity changes after restart

Confirm `/var/lib/tailscale` is persistent and `TS_STATE_DIR` points to it.

### All WebSSH users appear as the same source

That is the design boundary: Tailscale sees the shared WebSSH node identity.
Use WebSSH audit logs and strict user/target/remote-user controls, or do not
enable the feature for users who should have separate tailnet identities.

## Related pages

- [Security Model and Hardening](Security-Model-and-Hardening)
- [Profiles, Jump Hosts and Commands](Profiles-Jump-Hosts-and-Commands)
- [Production Deployment](Production-Deployment)
