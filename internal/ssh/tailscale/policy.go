// Package tailscale decides who may use the WebSSH node's shared Tailscale
// identity, for which target and remote user, and builds the dialer variant
// of such a connection: the address pinned after the kernel route check,
// the socket bound to the tailnet interface and the SSH "none" method.
package tailscale

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// Refusals with the texts of the Python release; the page and the audit
// log show them.
var (
	ErrNotEnabled        = fault.New(fault.Forbidden, "Tailscale SSH is not enabled for this account")
	ErrTargetNotAllowed  = fault.New(fault.Forbidden, "Tailscale SSH target is not allowed")
	ErrRemoteUserDenied  = fault.New(fault.Forbidden, "Tailscale SSH remote username is not allowed")
	ErrAuthorizationGone = fault.New(fault.Forbidden, "Tailscale SSH authorization is invalid")
	ErrJumpHost          = fault.New(fault.InvalidValue, "Tailscale SSH cannot be used with a jump host")
	ErrSOCKS             = fault.New(fault.InvalidValue, "Tailscale SSH cannot be used with a SOCKS5 proxy")
	ErrGatewaySelector   = fault.New(fault.InvalidValue, "Gateway selectors cannot use Tailscale SSH")
)

// Target is one canonical TAILSCALE_SSH_ALLOWED_TARGETS entry.
type Target struct {
	Host string
	Port int
}

// Config is the environment of the shared-identity mode. internal/config
// parses and validates it; AllowedTargets are canonical.
type Config struct {
	Enabled            bool
	Interface          string
	AllowedWebSSHUsers []string
	AllowedTargets     []Target
	AllowedRemoteUsers []string
}

// User is the WebSSH account asking for the shared identity.
type User struct {
	ID       int64
	Username string
	IsAdmin  bool
}

// Resolver resolves a host name to its addresses in the order the
// resolver returns them; *net.Resolver's LookupNetIP with "ip" fits.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Policy is the immutable form of Config with the kernel route lookup.
type Policy struct {
	cfg     Config
	iface   string
	resolve Resolver
	lookup  netpolicy.RouteLookup
}

// New builds the policy. resolve and lookup default to the system resolver
// and the kernel FIB lookup.
func New(cfg Config, resolve Resolver, lookup netpolicy.RouteLookup) *Policy {
	if lookup == nil {
		lookup = netpolicy.LookupRoute
	}
	return &Policy{cfg: cfg, iface: strings.TrimSpace(cfg.Interface), resolve: resolve, lookup: lookup}
}

// Enabled is TAILSCALE_SSH_ENABLED.
func (p *Policy) Enabled() bool { return p != nil && p.cfg.Enabled }

// Interface is the trusted tailnet interface.
func (p *Policy) Interface() string { return p.iface }

// UserMayUse is user_can_use_tailscale_ssh: administrators and the
// accounts named in TAILSCALE_SSH_ALLOWED_WEBSSH_USERS (exact match) while
// the feature is on.
func (p *Policy) UserMayUse(u User) bool {
	if !p.Enabled() {
		return false
	}
	return u.IsAdmin || slices.Contains(p.cfg.AllowedWebSSHUsers, u.Username)
}

// Check is validate_tailscale_ssh_access: account, target and remote user,
// without resolving anything. The remote user is compared after stripping
// whitespace, as in Python; the username rules of saved hosts and of the
// connect request apply before.
func (p *Policy) Check(u User, host string, port int, remoteUser string) error {
	if !p.UserMayUse(u) {
		return ErrNotEnabled
	}
	if p.iface == "" || port < 1 || port > 65535 {
		return ErrTargetNotAllowed
	}
	canonical, err := netpolicy.CanonicalHost(host)
	if err != nil {
		return ErrTargetNotAllowed
	}
	if !slices.Contains(p.cfg.AllowedTargets, Target{Host: canonical, Port: port}) {
		return ErrTargetNotAllowed
	}
	remote := pyStrip(remoteUser)
	if len(p.cfg.AllowedRemoteUsers) > 0 && !slices.Contains(p.cfg.AllowedRemoteUsers, remote) {
		return ErrRemoteUserDenied
	}
	return nil
}

// Authorization is attempt-scoped authority for one exact connection. Its
// fields are unexported so that only Authorize can mint one.
type Authorization struct {
	userID     int64
	host       string
	port       int
	remoteUser string
	addr       netip.AddrPort
	iface      string
}

// Addr is the pinned address the connection must use.
func (a Authorization) Addr() netip.AddrPort { return a.addr }

// Interface is the interface the connection must be bound to.
func (a Authorization) Interface() string { return a.iface }

// Host is the canonical target host; host keys are stored under it.
func (a Authorization) Host() string { return a.host }

// RemoteUser is the SSH username sent to the target.
func (a Authorization) RemoteUser() string { return a.remoteUser }

// Matches is TailscaleSSHAuthorization.matches: the request about to
// connect is the authorized one.
func (a Authorization) Matches(userID int64, host string, port int, remoteUser string) bool {
	canonical, err := netpolicy.CanonicalHost(host)
	return err == nil && a.addr.IsValid() &&
		userID == a.userID && canonical == a.host && port == a.port &&
		pyStrip(remoteUser) == a.remoteUser
}

// Authorize is authorize_tailscale_ssh_access: Check, then the first
// address of the target whose kernel route leaves through the tailnet
// interface is pinned. A literal address is checked the same way. An
// IPv4-mapped or scoped address and an address without such a route are
// skipped; with none left the target is refused.
func (p *Policy) Authorize(ctx context.Context, u User, host string, port int, remoteUser string) (Authorization, error) {
	if err := p.Check(u, host, port, remoteUser); err != nil {
		return Authorization{}, err
	}
	canonical, _ := netpolicy.CanonicalHost(host)
	var candidates []netip.Addr
	if addr, err := netip.ParseAddr(canonical); err == nil {
		candidates = []netip.Addr{addr}
	} else {
		if p.resolve == nil {
			return Authorization{}, ErrTargetNotAllowed
		}
		if candidates, err = p.resolve(ctx, canonical); err != nil {
			return Authorization{}, ErrTargetNotAllowed
		}
	}
	seen := map[netip.Addr]bool{}
	for _, addr := range candidates {
		if seen[addr] || addr.Zone() != "" || addr.Is4In6() || !addr.IsValid() {
			continue
		}
		seen[addr] = true
		route, err := p.lookup(ctx, addr)
		if err != nil || route.Interface != p.iface {
			continue
		}
		return Authorization{
			userID: u.ID, host: canonical, port: port,
			remoteUser: pyStrip(remoteUser),
			addr:       netip.AddrPortFrom(addr, uint16(port)), // #nosec G115 -- port range checked in Check
			iface:      p.iface,
		}, nil
	}
	return Authorization{}, ErrTargetNotAllowed
}

// pyStrip mirrors Python's str.strip() without arguments.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case 0x1c, 0x1d, 0x1e, 0x1f, 0x85:
			return true
		}
		return r == ' ' || r >= '\t' && r <= '\r' || r == 0xa0 || r == 0x1680 ||
			r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
	})
}
