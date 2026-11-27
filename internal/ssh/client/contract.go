// Package client is the only SSH dialer of WebSSH: direct, through a
// jump-host chain or through SOCKS5, with host-key checks and all supported
// authentication methods.
//
// This file is the contract with the packages around the dialer. The
// interfaces are declared here, by the consumer: internal/vault provides
// KeySource, internal/ssh/hostkey provides HostKeys, internal/terminal
// provides Interaction and internal/netpolicy provides NetDialer and
// Network.
// Implementations use only standard library, foundation and x/crypto/ssh
// types, so none of them imports this package.
package client

import (
	"context"
	"io"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// Role names the hop a prompt or failure belongs to. The values are the
// prompt contexts of the realtime protocol.
type Role string

// Roles of a hop.
const (
	RoleTarget Role = "target"
	RoleJump   Role = "jump_host"
	RoleSOCKS  Role = "socks_proxy"
)

// Target is one connection request: the target hop, the jump-host chain
// (outermost first) and an optional SOCKS5 proxy in front of the first hop.
// Jumps and Proxy are exclusive.
type Target struct {
	// Owner is the user on whose behalf the connection is made; host keys
	// and SSH keys are looked up for this user.
	Owner int64
	Hop   Hop
	Jumps []Hop
	Proxy *SOCKS
	// Display is how the session is presented; the dialer ignores it.
	Display Display
	// Variant is the SSH gateway or Tailscale SSH form of the connection
	// (variant.go); nil for an ordinary one.
	Variant *Variant
}

// Hop is one SSH server on the way to the target.
type Hop struct {
	// Host is the name the user configured; host keys are stored under it.
	Host string
	Port int
	User string
	Auth Auth
	// Legacy enables ssh-rsa and SHA-1 key exchange for this hop only
	// (opt-in per host, or the setting written for existing installations
	// under D-01).
	Legacy bool
}

// Auth is how a hop authenticates. Password answers the password method
// and the first hidden keyboard-interactive prompt; KeyID selects a stored
// key through KeySource. Both may be set.
type Auth struct {
	Password string
	KeyID    string
}

// SOCKS is a SOCKS5 proxy. Username and Password, both set or both
// empty, are the login of RFC 1929.
type SOCKS struct {
	Host     string
	Port     int
	Username string
	Password string
	// RemoteDNS is the proxy's remote_dns setting: the proxy may resolve
	// the target name itself where the network policy permits it.
	RemoteDNS bool
}

// Display carries what the terminal shows for a session. It travels with
// the target so that the resolver of saved profiles (internal/hosts)
// and the terminal share one type without importing each other.
type Display struct {
	ProfileID    string
	Name         string
	JumpHostID   string
	SOCKSProxyID string
	// Startup features of the saved host. The terminal takes the
	// post-connect behaviour and tmux from the request, as the Python
	// release did; Herdr and UseHerdr are the host's Herdr options
	// (overview, session mode), which only the server grants.
	UseTmux        bool
	Herdr          bool
	UseHerdr       bool
	StartupCommand bool
	// Tailscale marks a host that signs in with the WebSSH node's
	// Tailscale identity (auth type "tailscale"): Hop.User is the remote
	// user and the hop has no password or key.
	Tailscale bool
}

// KeySource returns the signer of a stored SSH key of a user. Provided by
// internal/vault; the key never leaves the vault in another form.
type KeySource interface {
	Signer(ctx context.Context, owner int64, keyID string) (ssh.Signer, error)
}

// HostKeys is the store of trusted host keys (internal/ssh/hostkey).
type HostKeys interface {
	// Known reports whether key is trusted for host:port and owner. It
	// returns false and nil for a host without trust (the user is asked),
	// and an error with fault.HostKeyChanged or fault.HostKeyRevoked when
	// trust exists but not for this key (the connection is refused, no
	// prompt).
	Known(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) (bool, error)
	// Record trusts key after the user accepted it. It re-checks under its
	// own lock and fails with fault.HostKeyChanged if another session
	// recorded a different key meanwhile.
	Record(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) error
	// Preferred orders the allowed host-key algorithms with the trusted
	// key types first, so the server presents a key that can be verified.
	Preferred(ctx context.Context, owner int64, host string, port int, allowed []string) ([]string, error)
}

// HostKeyPrompt asks the user to trust a host key seen for the first time.
type HostKeyPrompt struct {
	Role        Role
	Host        string
	Port        int
	KeyType     string
	Fingerprint string // SHA256:… as ssh-keygen prints it
}

// BannerPrompt asks the user to accept a pre-authentication banner. Banner
// is remote-supplied text, bounded and sanitized by the dialer.
type BannerPrompt struct {
	Role   Role
	Host   string
	Port   int
	Banner string
}

// Interaction asks the user during a connection attempt (provided by
// internal/terminal per attempt). Both methods block until the user
// answers, ctx ends or the prompt expires; false or an error aborts the
// connection. A nil Interaction means unattended: unknown host keys and
// banners are refused.
type Interaction interface {
	HostKey(ctx context.Context, q HostKeyPrompt) (bool, error)
	Banner(ctx context.Context, q BannerPrompt) (bool, error)
}

// Challenger is an Interaction that can also put the questions of a
// keyboard-interactive round to the user (one-time codes, a second
// question, the dialogs of PAM). The terminal adds it for a page that
// answers prompts, backed by prompt.interactive of an attempt of
// internal/ssh/gateway (gateway.Attempt.Challenger). Without it, an
// attended connection that needs
// such an answer ends with not_available_in_preview. The answers are sent
// once; a rejected answer ends the attempt.
type Challenger interface {
	Challenge(ctx context.Context, q Challenge) ([]string, error)
}

// Challenge is one keyboard-interactive round. Name, Instruction and the
// question texts are remote-supplied, bounded and cleaned like a banner.
type Challenge struct {
	Role        Role
	Host        string
	Port        int
	Name        string
	Instruction string
	Questions   []Question
}

// Question is one prompt of a round; Echo false means a secret.
type Question struct {
	Text string
	Echo bool
}

// NetDialer opens the TCP connection to the first hop or proxy after the
// network policy admitted it (provided by internal/netpolicy). Refusals
// carry fault.TargetBlocked, those of the tailnet rule
// fault.TailnetRouteRestricted.
type NetDialer interface {
	DialContext(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error)
}

// Network is the network policy as the dialer uses it: every TCP
// connection and every destination a relay is asked to reach passes it
// (ADR 0010). Provided by *netpolicy.Policy.
type Network interface {
	NetDialer
	// DialRelay connects to a jump host or SOCKS5 proxy; the tailnet relay
	// rule applies in addition.
	DialRelay(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error)
	// JumpDestination returns what a jump host is asked to connect to: an
	// admitted address or, where permitted, the name. relay marks a further
	// jump host, which passes the relay rule as well.
	JumpDestination(ctx context.Context, host string, port int, relay bool) (string, error)
	// SOCKSDestination returns what a SOCKS5 proxy is asked to connect to.
	SOCKSDestination(ctx context.Context, host string, port int, remoteDNS bool) (string, error)
}

// Shell is an interactive session on the target, returned by
// (*Dialer).OpenShell(ctx, t, ix, rows, cols). Close ends the shell and
// the connection to the target, jump hosts included.
type Shell interface {
	io.ReadWriteCloser
	// Resize changes the terminal size.
	Resize(rows, cols int) error
	// Wait returns when the remote shell ends.
	Wait() error
}
