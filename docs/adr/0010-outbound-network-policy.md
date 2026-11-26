# ADR 0010: One outbound network policy and one SSH dialer

## Status

Accepted

## Date

2026-11-26

## Context

WebSSH connects from the server to targets that users name: SSH hosts,
jump hosts, SOCKS proxies, SMB servers, and addresses probed by host
discovery and the reachability check. In the Python release:

- with `BLOCK_INTERNAL_SSH=false`, the default, address checks are off
  entirely: remote hosts, the local network and the WebSSH host itself are
  reachable, which is how WebSSH is meant to be used;
- SMB has its own, stricter check that rejects tailnet addresses
  (`100.64.0.0/10`);
- every signed-in user may run discovery and a TCP port check, and the
  results reveal the policy;
- the tailnet block does not apply when the Tailscale SSH feature is off,
  even if the WebSSH host is a tailnet node;
- Quick SFTP has its own SSH connection path without jump hosts, SOCKS5 or
  the host key prompt.

## Decision

**One policy.** `internal/netpolicy` admits every outbound target. It has
roles (`ssh`, `smb`, `socks`, `probe`) and one set of address classes
(public, private, tailnet, loopback, link-local, unspecified, multicast)
that is the same for every role. SMB therefore reaches tailnet addresses
like SSH does.

**Default: no target restriction.** WebSSH is usable without limits for
remote hosts, the local network and its own host. For every installation,
new or upgraded, loopback, private, tailnet, link-local and all other
address classes are reachable by default, as with
`BLOCK_INTERNAL_SSH=false` today. Nothing has to be recorded during the
migration.

**Optional restriction.** Administrators can turn on the restriction with
`BLOCK_INTERNAL_SSH=true`, which keeps its documented meaning. In Go it is
one rule set applied to the roles `ssh`, `smb` and `socks` alike; which
address classes it blocks is a table in `internal/netpolicy` and in the
documentation. The documentation states plainly what the setting opens
when off (including loopback and cloud metadata addresses) and what it
blocks when on.

**Resolve once.** A name is resolved once, every resolved address is
checked, and the connection goes to an admitted address without resolving
again. Each hop (jump host, SOCKS proxy, target) is admitted separately.

**Tailnet.** If the WebSSH host is a tailnet node, the tailnet rule for
Tailscale SSH targets applies whether or not the Tailscale SSH feature is
enabled. The route lookup is `internal/netpolicy/route_linux.go`.

**Discovery and reachability.** Host discovery and the reachability check
are one permission that is granted per role or user. New installations
grant it to administrators only; on existing installations the migration
grants it to the roles that can use it today. The reachability check reports
a host as reachable only when it answers with an SSH identification string,
and it is subject to the same permission, the network policy and rate
limits.

**One SSH dialer.** `internal/ssh/client` is the only code that opens SSH
connections: terminal, Quick SFTP, automation, the reachability probe and
the SSH gateway. Quick SFTP becomes an SSH connection without a PTY, with
jump hosts, SOCKS5, `SSH_CONNECT_TIMEOUT` and the same host key handling as
the terminal: an unknown key is offered for confirmation, a changed key is
refused. The gateway is a variant of interactive authentication with the
same UI flow; if phase G0 check K8 shows that this does not fit, it stays a
separate path inside `internal/ssh/gateway`, still built on the dialer.

## Alternatives considered

- **Keep the Python behaviour.** Keeps two inconsistent policies for SSH
  and SMB and the tailnet gap.
- **Stricter defaults (link-local or loopback only by opt-in).** Rejected by
  the maintainer: WebSSH must work for the local network and its own host
  without extra settings.
- **Discovery for administrators only, without a permission.** Removes a
  feature multi-user installations use.

## Consequences

- The migration notes list the tailnet rule, SMB reaching tailnet
  addresses, the Quick SFTP host key prompt and the new discovery
  permission. The target default does not change.
- `internal/netpolicy` gets table tests per address class and role, and
  tests that a resolved address is the one dialled.
- Discovery and reachability results for users without the permission are
  not produced at all, so they reveal nothing about the policy.
