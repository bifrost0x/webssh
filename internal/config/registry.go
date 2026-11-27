package config

import (
	"slices"
	"strings"
)

// usage says what the Go release does with a variable.
type usage int

const (
	// used: the Go release reads the variable into Config and acts on it.
	used usage = iota
	// obsolete: the variable has no meaning in the Go release (D-16).
	obsolete
	// internal: set by the runtime, the image or the test harness, or read
	// only by Compose; never reported.
	internal
)

// variables lists every environment variable the Python release reads,
// the ones its Compose files and image define, and the ones the Go release
// adds, grouped like the configuration reference.
var variables = map[string]usage{
	// Profile, paths, core.
	"DEPLOYMENT_PROFILE": used, "DATA_DIR": used, "SECRET_KEY": used, "DEBUG": used,
	"APPLICATION_ROOT": used, "TRUSTED_PROXIES": used, "TRUSTED_PROXY_CIDRS": used,
	"CORS_ORIGINS": used, "ALLOW_CORS_WILDCARD": used, "SOCKETIO_ALLOW_ANY_ORIGIN": used,
	"SESSION_COOKIE_SECURE": used, "SESSION_COOKIE_NAME": used, "REMEMBER_COOKIE_NAME": used,
	"REGISTRATION_ENABLED": used, "BOOTSTRAP_REGISTRATION_ENABLED": used, "ADMIN_USERS": used,
	"ADMIN_PANEL_ENABLED": used, "BLOCK_INTERNAL_SSH": used, "SSH_ALLOWED_INTERNAL_NETWORKS": used,
	"PROXY_JUMP_REMOTE_DNS_ALLOWLIST": used, "SOCKS_REMOTE_DNS_ALLOWLIST": used,
	"SESSION_TIMEOUT": used, "HOST": used, "PORT": used, "TZ": used,
	"TRANSFER_TEMP_DIR": obsolete, "BACKUP_TEMP_DIR": used, "BACKUP_RECOVERY_DURABLE": obsolete,
	"HOST_DISCOVERY_ENABLED": used,

	// Feature switches.
	"HOST_KEY_MANAGEMENT_ENABLED": used, "RECOVERY_CODES_ENABLED": used, "TOTP_ENABLED": used,
	"WEBAUTHN_ENABLED": used, "WEBAUTHN_RP_ID": used, "WEBAUTHN_RP_NAME": used, "WEBAUTHN_ORIGIN": used,
	"TMUX_ENABLED": used, "TMUX_DEFAULT": used, "TMUX_SESSION_PREFIX": used,
	"AUTOMATION_ENABLED": used, "AUTOMATION_ALLOW_INSECURE_LOOPBACK": used,
	"SERVER_OPERATIONS_ENABLED": used, "SFTP_CHMOD_ENABLED": used, "AUDIT_EXPORT_ENABLED": used,
	"TAILSCALE_SSH_ENABLED": used, "TAILSCALE_SSH_ALLOWED_WEBSSH_USERS": used,
	"TAILSCALE_SSH_ALLOWED_TARGETS": used, "TAILSCALE_SSH_ALLOWED_REMOTE_USERS": used,
	"TAILSCALE_SSH_INTERFACE": used, "SMB_ENABLED": used, "SMB_ALLOWED_TARGETS": used,

	// OIDC, LDAP and outbound TLS.
	"OIDC_ENABLED": used, "OIDC_ISSUER": used, "OIDC_CLIENT_ID": used,
	"OIDC_CLIENT_SECRET_FILE": used, "OIDC_REDIRECT_URI": used, "OIDC_ALLOWED_SUBJECTS": used,
	"OIDC_ALLOWED_DOMAINS": used, "OIDC_LOGIN_RATE_LIMIT": used, "OIDC_MFA_AMR_VALUES": used,
	"OIDC_MFA_ACR_VALUES": used, "OIDC_PHISHING_RESISTANT_AMR_VALUES": used,
	"OIDC_PHISHING_RESISTANT_ACR_VALUES": used, "OIDC_STEP_UP_ACR_VALUES": used,
	"STEP_UP_MAX_AGE_SECONDS": used,
	"LDAP_ENABLED":            used, "LDAP_AUTO_PROVISION": used, "LDAP_PROVIDER_ID": used, "LDAP_URL": used,
	"LDAP_BACKUP_URL": used, "LDAP_BASE_DN": used, "LDAP_BIND_DN": used,
	"LDAP_BIND_PASSWORD_FILE": used, "LDAP_CA_FILE": used, "LDAP_USER_FILTER": used,
	"LDAP_UNIQUE_ID_ATTRIBUTE": used, "LDAP_LOGIN_RATE_LIMIT": used, "LDAP_CONNECT_TIMEOUT": used,
	"LDAP_OPERATION_TIMEOUT": used, "LDAP_SESSION_REVALIDATION_SECONDS": used,
	// The trust anchors of the outbound TLS clients (GitHub and OIDC sign-in); LDAP
	// trusts only LDAP_CA_FILE.
	"REQUESTS_CA_BUNDLE": used, "CURL_CA_BUNDLE": used,

	// Rate limits.
	"RATELIMIT_ENABLED": used, "RATELIMIT_LOGIN_LIMIT": used, "RATELIMIT_DEFAULT": used,
	"RATELIMIT_REAUTH": used, "SSH_CONNECT_RATELIMIT": used, "SSH_KEY_WRITE_RATELIMIT": used,
	"SSH_KEY_LIST_RATELIMIT": used, "CONNECTION_MUTATION_RATELIMIT": used,
	"RATELIMIT_STORAGE_URL": obsolete, "RATELIMIT_BACKUP_CREATE": used,
	"RATELIMIT_BACKUP_UPLOAD": used, "RATELIMIT_BACKUP_DOWNLOAD": used,
	"RATELIMIT_BACKUP_RESTORE": used, "COMMAND_MUTATION_RATELIMIT": used,
	"SMB_CONNECT_RATELIMIT": used, "SMB_SHARE_MUTATION_RATELIMIT": used, "SMB_SHARE_LIST_RATELIMIT": used,

	// Capacity, quotas, process.
	"QUOTA_SSH_SESSION_GLOBAL": used, "QUOTA_SSH_SESSION_PER_USER": used,
	"QUOTA_QUICK_CONNECTION_GLOBAL": used, "QUOTA_QUICK_CONNECTION_PER_USER": used,
	"QUOTA_TRANSFER_GLOBAL": used, "QUOTA_TRANSFER_PER_USER": used,
	"QUOTA_TEMP_BYTES_GLOBAL": used, "QUOTA_TEMP_BYTES_PER_USER": used,
	"QUOTA_BACKGROUND_JOB_GLOBAL": used, "QUOTA_BACKGROUND_JOB_PER_USER": used,
	"BACKGROUND_WORKERS": obsolete, "GUNICORN_THREADS": obsolete,
	"RUNTIME_SHUTDOWN_GRACE_SECONDS": used,
	"MAX_SOCKET_CONNECTIONS":         used, "MAX_SOCKET_CONNECTIONS_PER_USER": used,
	"SSH_OUTPUT_MAX_UNACKED_BYTES_PER_SOCKET": used, "SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET": used,
	"SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER": used, "SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL": used,
	"SSH_OUTPUT_MAX_UNACKED_BYTES_PER_USER": used, "SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL": used,
	"SSH_OUTPUT_ACK_TIMEOUT_SECONDS": used,
	"SSH_INPUT_MAX_BYTES":            used, "SSH_INPUT_SESSION_BURST_BYTES": used,
	"SSH_INPUT_SESSION_BYTES_PER_SECOND": used, "SSH_INPUT_USER_BURST_BYTES": used,
	"SSH_INPUT_USER_BYTES_PER_SECOND": used,

	// Files, transfers, editor.
	"SFTP_OPERATION_TIMEOUT": used, "MAX_UPLOAD_SIZE": used, "MAX_EDITOR_FILE_SIZE": used,
	"EDITOR_SAVE_BYTES_PER_MINUTE": used, "FILE_CONTROL_MAX_PATH_BYTES": used,
	"REMOTE_FILENAME_MAX_BYTES": used, "REMOTE_LISTING_MAX_METADATA_BYTES": used,
	"REMOTE_LISTING_PAGE_SIZE": used, "REMOTE_LISTING_SNAPSHOT_TTL_SECONDS": used,
	"REMOTE_LISTING_SNAPSHOT_MAX_STATES": used, "REMOTE_LISTING_SNAPSHOT_MAX_PER_USER": used,
	"SFTP_MAX_PACKET_BYTES": used, "SFTP_MAX_HANDLE_BYTES": used,
	"FILE_CONTROL_BYTES_PER_MINUTE": used, "MAX_DOWNLOAD_SIZE": used,
	"MAX_ZIP_DOWNLOAD_SIZE": used, "MAX_TRANSFER_MEMBERS": used, "MAX_PREVIEW_SIZE": used,
	"MAX_PREVIEW_TAIL_LINES": used, "MAX_SUPPORTED_FILE_SIZE": used,
	"SMB_CONNECT_TIMEOUT_SECONDS": used, "SMB_IO_IDLE_TIMEOUT_SECONDS": used,
	"SMB_MAX_SAVED_SHARES": used,

	// Storage limits.
	"COMMAND_MAX_RECORDS": used, "COMMAND_SET_MAX_RECORDS": used, "COMMAND_SET_MAX_STEPS": used,
	"COMMAND_OS_MAX_ENTRIES": used, "COMMAND_STORE_MAX_BYTES": used, "COMMAND_CONFIG_MAX_BYTES": used,
	"PROFILE_MAX_RECORDS": used, "JUMP_HOST_MAX_RECORDS": used, "SOCKS_PROXY_MAX_RECORDS": used,
	"CONNECTION_STORE_MAX_BYTES": used, "CONNECTION_CONFIG_MAX_BYTES": used,
	"CONNECTION_STORE_RECOVERY_MAX_BYTES": used, "CONNECTION_STORE_RECOVERY_MAX_RECORDS": used,
	"SSH_KEY_MAX_RECORDS": used, "SSH_KEY_STORE_MAX_BYTES": used,
	"MAX_WEBAUTHN_JSON_SIZE": used, "MAX_RECOVERY_JSON_SIZE": used,
	"AUDIT_LOG_MAX_BYTES": used, "AUDIT_LOG_BACKUP_COUNT": used,
	"BACKUP_MAX_MEMBERS": used, "BACKUP_MAX_FILE_SIZE": used, "BACKUP_MAX_TOTAL_SIZE": used,
	"BACKUP_MAX_COMPRESSION_RATIO": used, "BACKUP_MAX_MANIFEST_SIZE": used,
	"BACKUP_UPLOAD_MAX_SIZE": used, "BACKUP_OPERATION_TIMEOUT": used, "BACKUP_DOWNLOAD_TTL": used,

	// Python runtime and image.
	"PYTHONDONTWRITEBYTECODE": obsolete, "PYTHONUNBUFFERED": obsolete, "PYTHON_DOTENV_DISABLED": used,
	"WEBSSH_SECRET_KEY_SOURCE": internal, "WEBSSH_REVISION": internal, "SERVER_SOFTWARE": internal,
	"XDG_RUNTIME_DIR": internal, "HOME": internal, "TMPDIR": internal, "TEMP": internal, "TMP": internal,
	// Read by Compose only.
	"WEBSSH_ORIGIN": internal, "WEBSSH_PIDS_LIMIT": internal, "WEBSSH_MEMORY_LIMIT": internal,
	"WEBSSH_TMPFS_SIZE": internal, "WEBSSH_RUNTIME_UID": internal, "WEBSSH_RUNTIME_GID": internal,
}

// explicitKeys is EXPLICIT_ENVIRONMENT_KEYS restricted to the known
// variables: those whose value is not blank.
func explicitKeys(lookup LookupFunc) map[string]bool {
	out := map[string]bool{}
	for name := range variables {
		if v, ok := lookup(name); ok && pyStrip(v) != "" {
			out[name] = true
		}
	}
	return out
}

// obsoleteReasons explain the obsolete variables that do more than the
// Gunicorn settings did. A value listed in quietValues is the one the
// Go release behaves like, so it is not reported.
var obsoleteReasons = map[string]string{
	"RATELIMIT_STORAGE_URL":   "is ignored: the Go release keeps rate limit counters in the process, so they start over after a restart",
	"TRANSFER_TEMP_DIR":       "is ignored: the Go release streams folder downloads and keeps no temporary archives",
	"BACKUP_RECOVERY_DURABLE": "is no longer needed: the Go release keeps the rollback state of a restore on the data volume, so online restore works without it",
}

var quietValues = map[string]string{
	"RATELIMIT_STORAGE_URL":   "memory://",
	"BACKUP_RECOVERY_DURABLE": "true",
}

// usageWarnings reports the explicitly set variables that have no meaning
// in the Go release, in name order.
func usageWarnings(p *parser, c *Config) {
	names := make([]string, 0, len(c.explicit))
	for name := range c.explicit {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if variables[name] != obsolete {
			continue
		}
		if quiet, ok := quietValues[name]; ok && strings.EqualFold(pyStrip(p.raw(name, "")), quiet) {
			continue
		}
		if reason, ok := obsoleteReasons[name]; ok {
			p.warn(WarnObsolete, name, "%s", reason)
			continue
		}
		p.warn(WarnObsolete, name, "has no meaning in the Go release; it is still checked like in the Python release, so a return to Python keeps starting")
	}
}
