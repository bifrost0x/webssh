package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
)

// ErrTailnetRestricted is the cause of every refusal by the tailnet rule.
// Its code is tailscale_route_restricted, as in the Python release; the
// frontend shows its own hint for it.
var ErrTailnetRestricted = errors.New("netpolicy: tailnet route restricted")

// Refusals. The messages are those of the Python release.
var (
	errBlocked    = fault.New(fault.TargetBlocked, "Connections to this address are not allowed.")
	errUnresolved = fault.New(fault.Unreachable, "Host could not be resolved.")
	errPort       = fault.New(fault.InvalidValue, "Port must be between 1 and 65535.")
	errScoped     = fault.New(fault.InvalidValue, "Scoped addresses cannot be used through a SOCKS5 proxy.")
	errNetwork    = fault.New(fault.InvalidRequest, "Only TCP connections are supported.")
)

func tailnetRefusal(message string) error {
	return fault.Wrap(fault.TailnetRouteRestricted, ErrTailnetRestricted, message)
}

const (
	msgTailnetTarget = "This target is on the tailnet and requires Tailscale SSH."
	msgTailnetRelay  = "A proxy or jump host on the WebSSH host itself, or one whose route cannot be determined, would use the Tailscale node identity."
	msgTailnetName   = "This name resolves to the tailnet and requires Tailscale SSH."
)

// Resolver resolves host names; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config is the network policy. The zero value is the default of every
// installation: no target restriction (ADR 0010) and the tailnet rule
// with the interface named by Tailnet.Interface.
type Config struct {
	// BlockInternal is BLOCK_INTERNAL_SSH: refuse every address that is
	// not public, for the roles ssh, smb and socks alike.
	BlockInternal bool
	// AllowedInternal is SSH_ALLOWED_INTERNAL_NETWORKS: private networks
	// that stay reachable while BlockInternal is set.
	AllowedInternal []netip.Prefix
	// JumpRemoteDNS and SOCKSRemoteDNS are PROXY_JUMP_REMOTE_DNS_ALLOWLIST
	// and SOCKS_REMOTE_DNS_ALLOWLIST: names a relay may resolve itself
	// while BlockInternal is set.
	JumpRemoteDNS  []string
	SOCKSRemoteDNS []string
	Tailnet        Tailnet

	// Resolver and Dial default to the standard library.
	Resolver Resolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger   *slog.Logger
}

// Policy admits outbound targets and dials only admitted addresses. It is
// safe for concurrent use.
type Policy struct {
	cfg Config
}

// New validates cfg and returns the policy.
func New(cfg Config) (*Policy, error) {
	for _, p := range cfg.AllowedInternal {
		if !p.IsValid() || p != p.Masked() || !slices.ContainsFunc(allowlistable, func(a netip.Prefix) bool {
			return a.Addr().BitLen() == p.Addr().BitLen() && a.Bits() <= p.Bits() && a.Contains(p.Addr())
		}) {
			return nil, fmt.Errorf("netpolicy: allowed internal network %s is not inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7", p)
		}
	}
	for _, list := range [][]string{cfg.JumpRemoteDNS, cfg.SOCKSRemoteDNS} {
		for _, name := range list {
			canonical, err := CanonicalHost(name)
			if _, isIP := parsePythonAddr(canonical); err != nil || isIP || canonical != name {
				return nil, fmt.Errorf("netpolicy: remote DNS allowlist entry %q is not a canonical host name", name)
			}
		}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{}).DialContext
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Policy{cfg: cfg}, nil
}

// Admitted is a target the policy allows: the canonical host and the one
// address to connect to.
type Admitted struct {
	Host string
	Addr netip.AddrPort
	// ViaAllowance is set when only SSH_ALLOWED_INTERNAL_NETWORKS admitted
	// the address.
	ViaAllowance bool
}

// Admit resolves host once and returns the first address the policy
// allows. Every refusal is a *fault.Error with TargetBlocked,
// TailnetRouteRestricted (wrapping ErrTailnetRestricted) for the tailnet
// rule, Unreachable for a name that
// does not resolve, or InvalidValue for a malformed host or port.
func (p *Policy) Admit(ctx context.Context, role Role, host string, port int) (Admitted, error) {
	canonical, err := CanonicalHost(host)
	if err != nil {
		return Admitted{}, err
	}
	if port < 1 || port > 65535 {
		return Admitted{}, errPort
	}
	adm, err := p.admit(ctx, canonical, port)
	if err != nil {
		return Admitted{}, err
	}
	if adm.ViaAllowance {
		p.cfg.Logger.InfoContext(ctx, "target admitted by internal network allowance",
			"role", string(role), "host", adm.Host, "ip", adm.Addr.Addr().String(), "port", port)
	}
	return adm, nil
}

func (p *Policy) decide(addr netip.Addr) (allowed, viaAllowance bool) {
	if !p.cfg.BlockInternal || !Internal(addr) {
		return true, false
	}
	if allowlisted(addr, p.cfg.AllowedInternal) {
		return true, true
	}
	return false, false
}

func (p *Policy) admit(ctx context.Context, canonical string, port int) (Admitted, error) {
	if literal, ok := parsePythonAddr(canonical); ok {
		allowed, via := p.decide(literal)
		if !allowed {
			return Admitted{}, errBlocked
		}
		if p.cfg.Tailnet.targetRestricted(ctx, literal) {
			return Admitted{}, tailnetRefusal(msgTailnetTarget)
		}
		return Admitted{Host: canonical, Addr: netip.AddrPortFrom(literal, uint16(port)), ViaAllowance: via}, nil // #nosec G115 -- port checked by the caller
	}
	candidates, err := p.cfg.Resolver.LookupNetIP(ctx, "ip", canonical)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Admitted{}, ctxErr
		}
		return Admitted{}, fault.Wrap(errUnresolved.Code, err, errUnresolved.Message)
	}
	var seen []netip.Addr
	tailnet := false
	for _, addr := range candidates {
		if !addr.IsValid() || slices.Contains(seen, addr) {
			continue
		}
		seen = append(seen, addr)
		allowed, via := p.decide(addr)
		if !allowed {
			continue
		}
		if p.cfg.Tailnet.targetRestricted(ctx, addr) {
			tailnet = true
			continue
		}
		return Admitted{Host: canonical, Addr: netip.AddrPortFrom(addr, uint16(port)), ViaAllowance: via}, nil // #nosec G115 -- port checked by the caller
	}
	if tailnet {
		return Admitted{}, tailnetRefusal(msgTailnetTarget)
	}
	return Admitted{}, errBlocked
}

// DialContext connects to the target named by addr ("host:port") after
// admitting it, to the admitted address only. A SOCKS5 proxy (RoleSOCKS)
// is a relay and passes the relay rule as well.
func (p *Policy) DialContext(ctx context.Context, role Role, network, addr string) (net.Conn, error) {
	return p.dial(ctx, role, network, addr, role == RoleSOCKS)
}

// DialRelay connects to a jump host or SOCKS5 proxy: like DialContext,
// and the tailnet relay rule applies to the admitted address.
func (p *Policy) DialRelay(ctx context.Context, role Role, network, addr string) (net.Conn, error) {
	return p.dial(ctx, role, network, addr, true)
}

func (p *Policy) dial(ctx context.Context, role Role, network, addr string, relay bool) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errNetwork
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fault.Wrap(fault.InvalidValue, err, "Invalid host format.")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, errPort
	}
	adm, err := p.Admit(ctx, role, host, port)
	if err != nil {
		return nil, err
	}
	if relay && p.cfg.Tailnet.relayRestricted(ctx, adm.Addr.Addr()) {
		return nil, tailnetRefusal(msgTailnetRelay)
	}
	return p.cfg.Dial(ctx, "tcp", adm.Addr.String())
}
