# SSH gateway and Tailscale SSH in the Go release (draft)

Draft for the documentation package of M2 (DOC1). It describes what the Go
server does differently from the Python release for the SSH gateway
(Warpgate) and the shared-identity mode of Tailscale SSH, what an upgraded
installation keeps, and what has not been verified. The user guides
[warpgate.md](../warpgate.md) and [tailscale-ssh.md](../tailscale-ssh.md)
stay valid apart from the points below.

## SSH gateway

WebSSH is the client of the gateway. A username with a colon
(`user:target`) selects the gateway while the administrator switch
*SSH gateway* is on. Selectors follow the rules of the Python release
(no `ticket-`, no `#`, no control or format characters, at most 128 UTF-8
bytes, no surrounding whitespace) and saved hosts may keep a selector as
their username. tmux names of gateway sessions use the same digest.

Changes against the Python release:

| Change | Kind |
|---|---|
| Prompts carry the server's echo flag. The page still masks every answer. | additive |
| Output of the temporary gateway terminal keeps characters that span two 4 KiB frames; Python replaced them with U+FFFD. | fix |
| A gateway that wants a password and then a one-time code, without a saved password, now asks for both in the browser; Python refused the code after the typed password. | fix |
| The SSH client always tries the `none` method first (visible only in the gateway's log). | keep |
| Switching the gateway off ends pending gateway logins within a second. | keep |

Unchanged on purpose, checked against a real Warpgate 0.30.6 and the
Python strategy on the same gateway: without a saved password, a Warpgate
user with password and one-time code is asked the code first and then
refused, as in the Python release; with a saved password the login works.

A jump host may stand in front of the gateway and uses the same
authentication strategy; its prompts are titled "Jump host: <name>".
Quick SFTP through the gateway follows with the file packages.

## Tailscale SSH

The allowlists, the route check and the texts of the refusals are those of
the Python release; 4000 decisions of the Python policy are part of the
Go tests.

Changes against the Python release:

| Change | Kind |
|---|---|
| The connection is bound to `TAILSCALE_SSH_INTERFACE` with `SO_BINDTODEVICE` (Linux 5.7 and later, no capability needed). The Python release set `IP_UNICAST_IF`, which Linux ignores for TCP: in the test namespace its socket reached a host on another interface, the Go socket does not. | fix |
| Outside Linux Tailscale SSH is refused, as before; the tailnet rule applies there only when the interface exists. | keep |
| Every use of the shared identity is written to the audit log (`TAILSCALE_SSH_AUTHORIZED`, `TAILSCALE_SSH_DENIED`); the client address is not part of the entry yet. | change |

## Ordinary SSH to tailnet nodes (D-28)

New installations refuse ordinary SSH (password or key) to tailnet node
addresses whenever this host is a tailnet node, whether or not
`TAILSCALE_SSH_ENABLED` is set. The Python release refused them only while
Tailscale SSH was enabled.

An installation upgraded from the Python release keeps the old behaviour:
the migration writes the setting `netpolicy.tailnet_follows_switch` and
lists it in the migration report. While it is set, Tailscale SSH is off
and the tailnet interface exists, the server writes a warning to the log
and the audit log at every start:

> Tailscale SSH is disabled but the Tailscale interface exists; ordinary
> SSH to tailnet nodes is not blocked

Administrators should remove the setting once no saved host depends on
reaching tailnet nodes with ordinary SSH. The switch for it belongs to the
integration settings (OP3); until then the setting stays as migrated.

## Docker sidecar

The sidecar setup of [tailscale-ssh.md](../tailscale-ssh.md#docker-sidecar-with-persistent-state)
applies unchanged: WebSSH shares the network namespace of the tailscaled
container, so `tailscale0` and table 52 are visible to it, and the state
volume keeps the node identity.

## Residual risk: no real tailnet

There is no Tailscale account in the test setup, so the Go release has
been tested only against a stand-in: a network namespace with a
`tailscale0` interface, the node route in table 52 behind rule 5270 and an
OpenSSH server that accepts `none` for one user. Not verified:

- tailscaled itself: the WireGuard device, its rules and throw routes,
  peer routes, MagicDNS (`100.100.100.100`), exit nodes, subnet routes and
  4via6 routes as tailscaled installs them;
- the authorization of tailssh: node identity, ACLs, `ssh` rules and the
  `check` mode with approval in the browser (it may arrive as a banner or
  as a keyboard-interactive round, which the Go client would show or
  refuse);
- MagicDNS names when they resolve; only the rule that refuses them for
  relays is tested;
- IPv6 over a tailnet: binding a `tcp6` socket is tested, a connection is
  not (the stand-in has no IPv6 route);
- a route change while a connection is open: only that a bound socket
  cannot move to another interface is shown.

A live test on a real tailnet should cover a login with the shared
identity, a refused account and remote user, a host reached over the
tailnet with ordinary SSH (refused on a new installation, allowed with
the migrated setting and the warning shown) and a `check` rule.

## Running the tests

- Unit and differential tests: `go test ./internal/ssh/gateway ./internal/ssh/tailscale ./internal/netpolicy`.
  The Python vectors are rebuilt with the scripts in the packages'
  `testdata`.
- Warpgate: `internal/ssh/gateway/testdata/warpgate-up.sh` starts a
  throwaway Warpgate on the lab network, then
  `WEBSSH_WARPGATE_DIR=… go test -tags warpgate -run Warpgate ./internal/ssh/gateway ./cmd/webssh`;
  `warpgate-down.sh` removes it.
- Lab PAM and jump hosts: `go test -tags lab -run Lab ./internal/ssh/gateway`.
- Network namespaces: `internal/netpolicy/testdata/netns-test.sh lab` and
  `… crafted`; the lab mode also runs the Python route lookup and the
  Python socket options in the same namespace.
