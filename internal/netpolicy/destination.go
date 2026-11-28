package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

// A relay (jump host or SOCKS5 proxy) opens the onward connection itself.
// The policy decides what it is asked to reach: an address resolved and
// admitted here, or, where the configuration permits it, the name for the
// relay to resolve. Both functions follow app/ssh_manager.py and
// app/network_policy.py (socks_destination).

// JumpDestination returns what a jump host is asked to connect to for
// host:port: the admitted address, or the canonical name when it cannot be
// admitted here but remote resolution is allowed (BLOCK_INTERNAL_SSH off,
// or the name is on PROXY_JUMP_REMOTE_DNS_ALLOWLIST). A tailnet refusal is
// final: the bastion's resolver must not reopen a refused route. relay
// marks a further jump host: its address passes the relay rule, and while
// the tailnet rule applies it must be resolvable here. The zone of a
// link-local address is never sent: it means nothing on the remote host.
func (p *Policy) JumpDestination(ctx context.Context, host string, port int, relay bool) (string, error) {
	canonical, err := CanonicalHost(host)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", errPort
	}
	adm, err := p.Admit(ctx, RoleSSH, canonical, port)
	switch {
	case err == nil && relay && p.cfg.Tailnet.relayRestricted(ctx, adm.Addr.Addr()):
		return "", tailnetRefusal(msgTailnetRelay)
	case err == nil:
		return adm.Addr.Addr().WithZone("").String(), nil
	case errors.Is(err, ErrTailnetRestricted) || !refusedHere(err):
		return "", err
	case relay && p.cfg.Tailnet.active():
		return "", tailnetRefusal(msgTailnetRelay)
	}
	if _, numeric := inetAton(canonical); numeric {
		return "", err // the relay would reach the same refused address
	}
	if p.cfg.BlockInternal && !remoteDNSAllowed(canonical, p.cfg.JumpRemoteDNS) {
		return "", errBlocked
	}
	if p.cfg.Tailnet.remoteNameRestricted(ctx, canonical, p.lookup) {
		return "", tailnetRefusal(msgTailnetName)
	}
	return canonical, nil
}

// SOCKSDestination returns what a SOCKS5 proxy is asked to connect to. With
// remoteDNS (the proxy's setting) a name goes to the proxy unresolved when
// BLOCK_INTERNAL_SSH is off or the name is on SOCKS_REMOTE_DNS_ALLOWLIST;
// otherwise it is resolved and admitted here and the address is sent.
func (p *Policy) SOCKSDestination(ctx context.Context, host string, port int, remoteDNS bool) (string, error) {
	canonical, err := CanonicalHost(host)
	if err != nil {
		return "", err
	}
	if strings.Contains(canonical, "%") {
		return "", errScoped
	}
	if port < 1 || port > 65535 {
		return "", errPort
	}
	_, literal := policyAddr(canonical)
	if !literal && remoteDNS && (!p.cfg.BlockInternal || remoteDNSAllowed(canonical, p.cfg.SOCKSRemoteDNS)) {
		if p.cfg.Tailnet.remoteNameRestricted(ctx, canonical, p.lookup) {
			return "", tailnetRefusal(msgTailnetName)
		}
		if p.cfg.BlockInternal {
			p.cfg.Logger.InfoContext(ctx, "SOCKS target admitted by remote DNS allowlist", "host", canonical, "port", port)
		}
		return canonical, nil
	}
	adm, err := p.Admit(ctx, RoleSOCKS, canonical, port)
	switch {
	case err == nil:
		return adm.Addr.Addr().String(), nil
	case errors.Is(err, ErrTailnetRestricted):
		return "", err
	case remoteDNS && p.cfg.BlockInternal && refusedHere(err):
		return "", errBlocked
	}
	return "", err
}

// refusedHere reports a refusal that remote resolution may still overcome:
// the name did not resolve or no address was admitted. Python treats both
// as the same ValueError.
func refusedHere(err error) bool {
	code := fault.CodeOf(err)
	return code == fault.TargetBlocked || code == fault.Unreachable
}

func (p *Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return p.cfg.Resolver.LookupNetIP(ctx, "ip", host)
}

// remoteDNSAllowed matches a canonical name exactly against an allowlist of
// canonical names. IP literals and numeric IPv4 forms never match.
func remoteDNSAllowed(canonical string, allowlist []string) bool {
	if _, isIP := policyAddr(canonical); isIP {
		return false
	}
	return slices.Contains(allowlist, canonical)
}
