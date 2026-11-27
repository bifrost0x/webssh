// Package smb is the SMB file backend (files.Backend): one authenticated,
// encrypted SMB 3.1.1 session per share, path operations that never
// follow reparse points, replacements that never lose data, the saved
// share definitions and their realtime messages.
package smb

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// DefaultPort is the only port WebSSH connects to in production.
const DefaultPort = 445

// DefaultMutationTimeout bounds one mutation, as MUTATION_TIMEOUT of
// app/file_mutations.py.
const DefaultMutationTimeout = 10 * time.Second

// Limits of the connection input (create_source of app/smb_pool.py).
const (
	MaxUsername = 256
	MaxDomain   = 255
	MaxPassword = 4096
)

// Network admits outbound targets; *netpolicy.Policy implements it.
type Network interface {
	Admit(ctx context.Context, role netpolicy.Role, host string, port int) (netpolicy.Admitted, error)
}

// Config holds the settings every source shares.
type Config struct {
	Network Network
	// AllowedTargets is SMB_ALLOWED_TARGETS: exact host names and IP
	// addresses in canonical form. A host must be listed to be dialled.
	AllowedTargets []string
	// ConnectTimeout bounds TCP connect, negotiate, authentication, tree
	// connect and the access probe (SMB_CONNECT_TIMEOUT_SECONDS).
	ConnectTimeout time.Duration
	// IOIdleTimeout bounds every request and every chunk of a transfer
	// (SMB_IO_IDLE_TIMEOUT_SECONDS).
	IOIdleTimeout time.Duration
	// MutationTimeout bounds one mutation (DefaultMutationTimeout when 0).
	MutationTimeout time.Duration
	// Port and Dial are test seams; zero values are DefaultPort and a
	// net.Dialer.
	Port uint16
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Target is one share and the account to use. Password is cleared by
// Connect.
type Target struct {
	Host, Share, Domain, Username string
	Password                      []byte
}

// ciphers are offered in this order: AES-256-GCM first (stronger and
// measured at no cost in K1), then the 128-bit and CCM variants that
// older servers choose.
var ciphers = []smb2.Cipher{smb2.AES256GCM, smb2.AES128GCM, smb2.AES256CCM, smb2.AES128CCM}

var errIncompleteConfig = errors.New("smb: incomplete configuration")

// Connect admits the target, negotiates SMB 3.1.1 with mandatory signing
// and encryption, authenticates with NTLMv2, mounts the share and probes
// the access rights at its root. Every failure is a *fault.Error with the
// codes of create_source; the input is checked before any connection is
// opened, an empty user name or password on its own included.
func Connect(ctx context.Context, cfg Config, t Target) (*Backend, error) {
	defer clear(t.Password)
	if err := ctx.Err(); err != nil {
		return nil, fail(fault.SMBConnectCancelled, PhaseLifecycle, "Canceled", err)
	}
	if cfg.Network == nil || cfg.ConnectTimeout <= 0 || cfg.IOIdleTimeout <= 0 {
		return nil, fail(fault.SMBConnectionFailed, PhaseLifecycle, "ConfigError", errIncompleteConfig)
	}
	if err := checkTarget(t); err != nil {
		return nil, err
	}
	return connect(ctx, cfg, t)
}

func connect(ctx context.Context, cfg Config, t Target) (*Backend, error) {
	host, err := netpolicy.CanonicalHost(t.Host)
	if err != nil || !slices.Contains(cfg.AllowedTargets, host) {
		return nil, fail(fault.SMBTargetNotAllowed, PhaseTargetResolution, "ValueError", err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	port := cfg.Port
	if port == 0 {
		port = DefaultPort
	}
	adm, err := cfg.Network.Admit(ctx, netpolicy.RoleSMB, host, int(port))
	if err != nil {
		if ctx.Err() != nil {
			return nil, classifyCtx(ctx, err, PhaseTargetResolution)
		}
		return nil, fail(fault.SMBTargetNotAllowed, PhaseTargetResolution, "ValueError", err)
	}
	domain := t.Domain
	dialer := &smb2.Dialer{
		Credentials:           auth.NTLMCredential{User: t.Username, Password: string(t.Password), Domain: &domain},
		TransportDialer:       admitted{addr: adm.Addr.String(), dial: cfg.Dial},
		RequireMessageSigning: true,
		SpecifiedDialects:     []smb2.Dialect{smb2.SMB311},
		Ciphers:               ciphers,
		RequireEncryption:     true,
		DisableAAPLExtension:  true,
	}
	session, err := dialer.Dial(ctx, adm.Addr.Addr().String())
	if err != nil {
		return nil, classifyCtx(ctx, err, PhaseSessionAuthentication)
	}
	b, err := mount(ctx, cfg, session, t.Share)
	if err != nil {
		_ = session.Abort()
		return nil, err
	}
	b.host, b.share, b.peer = adm.Host, t.Share, adm.Addr.Addr()
	return b, nil
}

// checkTarget applies the input rules of create_source and of the
// smb_quick_connect handler. Python refused an empty user name and an
// empty password only together with the rest of the form; Go refuses each
// on its own before anything is dialled.
func checkTarget(t Target) error {
	switch {
	case !ValidShareName(t.Share):
		return fault.New(fault.InvalidRequest, "Invalid SMB share.")
	case t.Username == "":
		return fault.New(fault.InvalidRequest, "Enter a user name.")
	case len(t.Password) == 0:
		return fault.New(fault.InvalidRequest, "Enter a password.")
	case !credentialText(t.Username, MaxUsername) || strings.ContainsAny(t.Username, `\/`):
		return fault.New(fault.InvalidRequest, "Invalid username.")
	case t.Domain != "" && (!credentialText(t.Domain, MaxDomain) || strings.ContainsAny(t.Domain, `\/@`)):
		return fault.New(fault.InvalidRequest, "Invalid domain.")
	case !credentialText(string(t.Password), MaxPassword):
		return fault.New(fault.InvalidRequest, "Invalid password.")
	}
	return nil
}

// credentialText is _credential_text: 1 to maximum characters without a
// C0 control character.
func credentialText(v string, maximum int) bool {
	n := 0
	for _, c := range v {
		if c < 32 {
			return false
		}
		n++
	}
	return n > 0 && n <= maximum
}

// admitted dials only the address the network policy admitted.
type admitted struct {
	addr string
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (a admitted) Dial(ctx context.Context, _ string) (smb2.Transport, error) {
	dial := a.dial
	if dial == nil {
		dial = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", a.addr)
	if err != nil {
		return nil, err
	}
	return smb2.NewTransport(conn), nil
}

// mount checks the negotiated security, mounts the share and probes the
// root. A guest or null session, a dialect other than 3.1.1, missing
// signing or encryption, a DFS, unencrypted or non-disk share are refused.
func mount(ctx context.Context, cfg Config, session *smb2.Session, share string) (*Backend, error) {
	info := session.SecurityInfo()
	switch {
	case info.Dialect != smb2.SMB311:
		return nil, fail(fault.SMBDialectRequired, PhaseSecurityRequirements, "DialectError", nil)
	case info.Guest || info.Null:
		return nil, fail(fault.SMBAuthenticationRequired, PhaseSessionAuthentication, "GuestSession", nil)
	case !info.SigningRequired, !info.EncryptData, info.Cipher == 0:
		return nil, fail(fault.SMBEncryptionRequired, PhaseSecurityRequirements, "SecurityError", nil)
	}
	mounted, err := session.Mount(ctx, share)
	if err != nil {
		return nil, classifyCtx(ctx, err, PhaseShareAccess)
	}
	si := mounted.Info()
	if si.DFS || !si.Encrypted || si.ShareType != shareTypeDisk {
		return nil, fail(fault.ShareUnavailable, PhaseShareAccess, "ShareTypeError", nil)
	}
	b := newBackend(session, mounted, cfg, info)
	access, err := b.probe(ctx, nil)
	if err != nil {
		return nil, classifyCtx(ctx, err, PhaseShareAccess)
	}
	b.access = access
	return b, nil
}

// shareTypeDisk is SMB2_SHARE_TYPE_DISK.
const shareTypeDisk = 0x01
