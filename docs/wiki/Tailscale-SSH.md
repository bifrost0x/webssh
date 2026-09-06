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

Hiding the UI is not authorization. The backend enforces WebSSH user, target,
remote-user, and tailnet policy.

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
      - TAILSCALE_SSH_ENABLED=false
      - TAILSCALE_SSH_ALLOWED_WEBSSH_USERS=
      - TAILSCALE_SSH_ALLOWED_TARGETS=tiny-server
      - TAILSCALE_SSH_ALLOWED_REMOTE_USERS=root
      - TAILSCALE_SSH_INTERFACE=tailscale0
    volumes:
      - webssh_data:/app/data

volumes:
  tailscale_state:
  webssh_data:
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

## Production browser access

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
