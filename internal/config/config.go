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
	// LDAP holds the LDAP_* settings.
	LDAP LDAP
	OIDC OIDC
	// StepUpMaxAge is STEP_UP_MAX_AGE_SECONDS.
	StepUpMaxAge time.Duration
	RateLimits   RateLimits
	Network      Network
	Terminal     Terminal
	// Quotas are the runtime quota limits by kind (ssh_session,
	// quick_connection, transfer, temp_bytes, background_job), from
	// QUOTA_<KIND>_GLOBAL and QUOTA_<KIND>_PER_USER.
	Quotas map[string]QuotaLimit
	Stores Stores
	Files  Files
	Audit  Audit
	SMB    SMB
	// ShutdownGrace is RUNTIME_SHUTDOWN_GRACE_SECONDS.
	ShutdownGrace time.Duration
	// CABundle is the extra trust anchor file or directory from
	// REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE, or "".
	CABundle CABundle
	// BackupTempDir is BACKUP_TEMP_DIR as the Python release resolves it:
	// where Python keeps its backup operation lock and restore status. The
	// migration probes both before it reads legacy data.
	BackupTempDir string
	// Backup holds the limits and rate limits of backups and restores.
	Backup Backup

	// explicit holds the variables with a non-empty value
	// (EXPLICIT_ENVIRONMENT_KEYS).
	explicit map[string]bool
}

// Explicit reports whether the environment set name to a value that is not
// blank. An explicit value locks the matching administrator setting, as in
// the Python release.
func (c Config) Explicit(name string) bool { return c.explicit[name] }

// Backup is the BACKUP_* configuration of config.py.
type Backup struct {
	MaxMembers          int64
	MaxFileSize         int64
	MaxTotalSize        int64
	MaxCompressionRatio int64
	MaxManifestSize     int64
	UploadMaxSize       int64
	OperationTimeout    time.Duration
	DownloadTTL         time.Duration
	// RecoveryDurable is BACKUP_RECOVERY_DURABLE; the Go restore keeps its
	// rollback state in the Go directory and does not need it.
	RecoveryDurable bool
	// RateCreate, RateUpload, RateDownload and RateRestore are the
	// RATELIMIT_BACKUP_* strings.
	RateCreate, RateUpload, RateDownload, RateRestore string
}

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
	CommandMutation    string
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
	// Tailscale holds the allowlists of the shared-identity mode.
	Tailscale TailscaleSSH
}

// TailscaleSSH are the allowlists of Tailscale SSH (TAILSCALE_SSH_*). Names
// match exactly, with case.
type TailscaleSSH struct {
	AllowedWebSSHUsers []string
	AllowedRemoteUsers []string
	// AllowedTargets are the valid entries of TAILSCALE_SSH_ALLOWED_TARGETS
	// in canonical form. A malformed entry grants nothing (homelab) or
	// stops the start (production); an entry with a non-ASCII name, which
	// this build cannot canonicalize yet, grants nothing either.
	AllowedTargets []HostPort
}

// HostPort is one canonical host and port.
type HostPort struct {
	Host string
	Port int
}

// QuotaLimit is the global and per-user limit of one quota kind. Values
// beyond int64 saturate; a per-user limit below the global one stays
// below it.
type QuotaLimit struct {
	Global, PerUser int64
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
	// The command library (COMMAND_*).
	CommandMaxRecords     int
	CommandSetMaxRecords  int
	CommandSetMaxSteps    int
	CommandOSMaxEntries   int
	CommandStoreMaxBytes  int
	CommandConfigMaxBytes int
}

// Transfers are the size limits of HTTP transfers and host-to-host
// copies.
type Transfers struct {
	MaxUpload   int64 // MAX_UPLOAD_SIZE
	MaxDownload int64 // MAX_DOWNLOAD_SIZE
	MaxArchive  int64 // MAX_ZIP_DOWNLOAD_SIZE, also host-to-host copies
}

// Files are the limits of the file workspace and the editor.
type Files struct {
	MaxEditorBytes       int64 // MAX_EDITOR_FILE_SIZE
	EditorBytesPerMinute int64 // EDITOR_SAVE_BYTES_PER_MINUTE
	ControlBytesPerMin   int64 // FILE_CONTROL_BYTES_PER_MINUTE
	ListingPageSize      int   // REMOTE_LISTING_PAGE_SIZE
	SnapshotTTL          time.Duration
	SnapshotsTotal       int   // REMOTE_LISTING_SNAPSHOT_MAX_STATES
	SnapshotsPerUser     int   // REMOTE_LISTING_SNAPSHOT_MAX_PER_USER
	MaxTransferMembers   int   // MAX_TRANSFER_MEMBERS
	MaxPreviewBytes      int64 // MAX_PREVIEW_SIZE
	MaxPreviewTailLines  int64 // MAX_PREVIEW_TAIL_LINES
	MaxSupportedFileSize int64 // MAX_SUPPORTED_FILE_SIZE
	SFTP                 SFTP
	Transfers            Transfers
}

// SFTP are the protocol limits of the SFTP backend.
type SFTP struct {
	MaxPacketBytes   int           // SFTP_MAX_PACKET_BYTES
	MaxHandleBytes   int           // SFTP_MAX_HANDLE_BYTES
	MaxNameBytes     int           // REMOTE_FILENAME_MAX_BYTES
	MaxMetadataBytes int           // REMOTE_LISTING_MAX_METADATA_BYTES
	OperationTimeout time.Duration // SFTP_OPERATION_TIMEOUT
}

// Audit holds the audit log limits.
type Audit struct {
	ExportEnabled bool
	LogMaxBytes   int64
	BackupCount   int
}
