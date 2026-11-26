package config

import (
	"net/netip"
	"time"
)

// LookupFunc returns the value of an environment variable and whether it
// is set, like os.LookupEnv.
type LookupFunc func(name string) (string, bool)

// Profile is the deployment profile (DEPLOYMENT_PROFILE).
type Profile string

const (
	ProfileHomelab    Profile = "homelab"
	ProfileProduction Profile = "production"
)

// Switch is an environment value that overrides an administrator switch.
// An empty value counts as not supplied: it neither locks the switch nor
// changes the default.
type Switch struct {
	Value bool
	// Locked is true when the environment supplied a value, which then
	// wins over the stored administrator setting.
	Locked bool
}

// Config is the configuration of the Go release, read from the documented
// environment variables with the meaning they have in the Python release.
// Only the settings this preview acts on are fields; every other
// documented variable is still validated like the Python release does.
type Config struct {
	Profile Profile
	Debug   bool

	// DataDir is the canonical data directory (see ResolveDataDir).
	DataDir string
	// SecretKey is the application secret. It is resolved by
	// ResolveSecretKey and checked by Load.
	SecretKey Secret
	// SecretSource says where SecretKey came from.
	SecretSource SecretSource

	// ApplicationRoot is the URL prefix without a trailing slash, or "".
	ApplicationRoot string
	// Listen holds HOST and PORT, which the Python release honours only
	// when started from source; the container always listened on
	// 0.0.0.0:5000.
	Listen Listen

	Cookies  Cookies
	Origins  Origins
	Proxies  Proxies
	Accounts Accounts
	Features Features
	WebAuthn WebAuthn
	OIDC     OIDC
	// StepUpMaxAge is STEP_UP_MAX_AGE_SECONDS.
	StepUpMaxAge time.Duration
	RateLimits   RateLimits
	Network      Network
	Terminal     Terminal
	Stores       Stores
	Audit        Audit
	// ShutdownGrace is RUNTIME_SHUTDOWN_GRACE_SECONDS.
	ShutdownGrace time.Duration
	// CABundle is the extra trust anchor file or directory from
	// REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE, or "".
	CABundle CABundle
	// BackupTempDir is BACKUP_TEMP_DIR as the Python release resolves it:
	// where Python keeps its backup operation lock and restore status. The
	// migration probes both before it reads legacy data.
	BackupTempDir string

	// explicit holds the variables with a non-empty value
	// (EXPLICIT_ENVIRONMENT_KEYS).
	explicit map[string]bool
}

// Explicit reports whether the environment set name to a value that is not
// blank. An explicit value locks the matching administrator setting, as in
// the Python release.
func (c Config) Explicit(name string) bool { return c.explicit[name] }

// Listen is the source-start listen address.
type Listen struct {
	Host string
	Port int
}

// Cookies are the browser cookie settings.
type Cookies struct {
	SessionName  string
	RememberName string
	// Secure sets the Secure attribute on the session and remember cookies.
	Secure bool
}

// Origins holds the realtime origin settings (decision D-20).
type Origins struct {
	// AllowAny is true for CORS_ORIGINS=*; List is then empty.
	AllowAny bool
	// List is the explicit origin allowlist. The Python release keeps
	// entries as written after trimming, including empty ones.
	List []string
	// AllowWildcard is ALLOW_CORS_WILDCARD.
	AllowWildcard bool
	// SkipSameOrigin is SOCKETIO_ALLOW_ANY_ORIGIN: with AllowAny, accept
	// any origin instead of the same origin.
	SkipSameOrigin bool
}

// Proxies describes the reverse proxies in front of WebSSH (D-19).
type Proxies struct {
	// Hops is TRUSTED_PROXIES: the number of proxies whose forwarding
	// headers are applied.
	Hops int
	// HopsExplicit is true when TRUSTED_PROXIES is present.
	HopsExplicit bool
	// CIDRs is TRUSTED_PROXY_CIDRS. When it is not empty, forwarding
	// headers count only on connections from these networks.
	CIDRs []netip.Prefix
}

// Accounts holds the account bootstrap settings.
type Accounts struct {
	// AdminUsers are granted administrator rights at startup.
	AdminUsers []string
	// RegistrationEnabled is only the initial value; a stored
	// administrator setting wins.
	RegistrationEnabled          bool
	BootstrapRegistrationEnabled bool
	AdminPanelEnabled            bool
}

// Features are the feature gates that the environment caps.
type Features struct {
	HostKeyManagement bool
	TOTP              bool
	WebAuthn          bool
	RecoveryCodes     bool
	HostDiscovery     bool
	Tmux              Switch
	TmuxDefault       Switch
	TmuxSessionPrefix string
}

// WebAuthn is the relying party configuration.
type WebAuthn struct {
	RPID   string
	RPName string
	Origin string
}

// RateLimits are the rate limit strings in the Flask-Limiter notation the
// Python release uses ("5 per minute"). Python does not check them at
// startup; their consumers parse them.
type RateLimits struct {
	Enabled            bool
	Default            string
	Login              string
	Reauth             string
	SSHConnect         string
	SSHKeyWrite        string
	SSHKeyList         string
	ConnectionMutation string
}

// Network is the outbound network policy input.
type Network struct {
	BlockInternalSSH bool
	// AllowedInternalNetworks stay reachable while BlockInternalSSH is on.
	AllowedInternalNetworks []netip.Prefix
	// ProxyJumpRemoteDNS lists names a jump host may resolve, as written
	// after trimming (the Python release checks them when it connects).
	ProxyJumpRemoteDNS []string
	// SOCKSRemoteDNS lists canonical names a SOCKS proxy may resolve.
	SOCKSRemoteDNS []string
	// TailscaleSSHEnabled is TAILSCALE_SSH_ENABLED and TailscaleInterface
	// is TAILSCALE_SSH_INTERFACE (default tailscale0); the network policy
	// applies its tailnet rule with them.
	TailscaleSSHEnabled bool
	TailscaleInterface  string
}

// Terminal holds the limits of interactive sessions.
type Terminal struct {
	SessionTimeout time.Duration
	// SessionsGlobal and SessionsPerUser are QUOTA_SSH_SESSION_*.
	SessionsGlobal  int
	SessionsPerUser int
	// MaxConnections and MaxConnectionsPerUser limit realtime connections.
	MaxConnections        int
	MaxConnectionsPerUser int
	Output                OutputLimits
	Input                 InputLimits
}

// OutputLimits are the SSH_OUTPUT_* budgets for unacknowledged output.
type OutputLimits struct {
	BytesPerSocket  int
	EventsPerSocket int
	EventsPerUser   int
	EventsGlobal    int
	BytesPerUser    int
	BytesGlobal     int
	AckTimeout      time.Duration
}

// InputLimits are the SSH_INPUT_* budgets.
type InputLimits struct {
	MaxBytes              int
	SessionBurstBytes     int
	SessionBytesPerSecond int
	UserBurstBytes        int
	UserBytesPerSecond    int
}

// Stores are the size limits of saved connection data and keys.
type Stores struct {
	ProfileMaxRecords                 int
	JumpHostMaxRecords                int
	SOCKSProxyMaxRecords              int
	ConnectionStoreMaxBytes           int
	ConnectionConfigMaxBytes          int
	ConnectionStoreRecoveryMaxBytes   int
	ConnectionStoreRecoveryMaxRecords int
	SSHKeyMaxRecords                  int
	SSHKeyStoreMaxBytes               int
	MaxWebAuthnJSONSize               int
	MaxRecoveryJSONSize               int
}

// Audit holds the audit log limits.
type Audit struct {
	ExportEnabled bool
	LogMaxBytes   int64
	BackupCount   int
}
