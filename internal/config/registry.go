package config

import (
	"slices"
	"strings"
)

// usage says what this preview does with a variable.
type usage int

const (
	// used: the preview reads the variable into Config.
	used usage = iota
	// inert: documented and validated like the Python release, but the
	// feature behind it is not part of this preview (decision D-16).
	inert
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
	"TRANSFER_TEMP_DIR": inert, "BACKUP_TEMP_DIR": inert, "BACKUP_RECOVERY_DURABLE": inert,
	"HOST_DISCOVERY_ENABLED": inert,

	// Feature switches.
	"HOST_KEY_MANAGEMENT_ENABLED": used, "RECOVERY_CODES_ENABLED": used, "TOTP_ENABLED": used,
	"WEBAUTHN_ENABLED": used, "WEBAUTHN_RP_ID": used, "WEBAUTHN_RP_NAME": used, "WEBAUTHN_ORIGIN": used,
	"TMUX_ENABLED": used, "TMUX_DEFAULT": used, "TMUX_SESSION_PREFIX": used,
	"AUTOMATION_ENABLED": inert, "AUTOMATION_ALLOW_INSECURE_LOOPBACK": inert,
	"SERVER_OPERATIONS_ENABLED": inert, "SFTP_CHMOD_ENABLED": inert, "AUDIT_EXPORT_ENABLED": inert,
	"TAILSCALE_SSH_ENABLED": inert, "TAILSCALE_SSH_ALLOWED_WEBSSH_USERS": inert,
	"TAILSCALE_SSH_ALLOWED_TARGETS": inert, "TAILSCALE_SSH_ALLOWED_REMOTE_USERS": inert,
	"TAILSCALE_SSH_INTERFACE": inert, "SMB_ENABLED": inert, "SMB_ALLOWED_TARGETS": inert,

	// OIDC, LDAP and outbound TLS.
	"OIDC_ENABLED": inert, "OIDC_ISSUER": inert, "OIDC_CLIENT_ID": inert,
	"OIDC_CLIENT_SECRET_FILE": inert, "OIDC_REDIRECT_URI": inert, "OIDC_ALLOWED_SUBJECTS": inert,
	"OIDC_ALLOWED_DOMAINS": inert, "OIDC_LOGIN_RATE_LIMIT": inert, "OIDC_MFA_AMR_VALUES": inert,
	"OIDC_MFA_ACR_VALUES": inert, "OIDC_PHISHING_RESISTANT_AMR_VALUES": inert,
	"OIDC_PHISHING_RESISTANT_ACR_VALUES": inert, "OIDC_STEP_UP_ACR_VALUES": inert,
	"STEP_UP_MAX_AGE_SECONDS": used,
	"LDAP_ENABLED":            inert, "LDAP_AUTO_PROVISION": inert, "LDAP_PROVIDER_ID": inert, "LDAP_URL": inert,
	"LDAP_BACKUP_URL": inert, "LDAP_BASE_DN": inert, "LDAP_BIND_DN": inert,
	"LDAP_BIND_PASSWORD_FILE": inert, "LDAP_CA_FILE": inert, "LDAP_USER_FILTER": inert,
	"LDAP_UNIQUE_ID_ATTRIBUTE": inert, "LDAP_LOGIN_RATE_LIMIT": inert, "LDAP_CONNECT_TIMEOUT": inert,
	"LDAP_OPERATION_TIMEOUT": inert, "LDAP_SESSION_REVALIDATION_SECONDS": inert,
	// The trust anchors of the outbound TLS clients (GitHub sign-in).
	"REQUESTS_CA_BUNDLE": used, "CURL_CA_BUNDLE": used,

	// Rate limits.
	"RATELIMIT_ENABLED": used, "RATELIMIT_LOGIN_LIMIT": used, "RATELIMIT_DEFAULT": used,
	"RATELIMIT_REAUTH": used, "SSH_CONNECT_RATELIMIT": used, "SSH_KEY_WRITE_RATELIMIT": used,
	"SSH_KEY_LIST_RATELIMIT": used, "CONNECTION_MUTATION_RATELIMIT": used,
	"RATELIMIT_STORAGE_URL": obsolete, "RATELIMIT_BACKUP_CREATE": inert,
	"RATELIMIT_BACKUP_UPLOAD": inert, "RATELIMIT_BACKUP_DOWNLOAD": inert,
	"RATELIMIT_BACKUP_RESTORE": inert, "COMMAND_MUTATION_RATELIMIT": inert,
	"SMB_CONNECT_RATELIMIT": inert, "SMB_SHARE_MUTATION_RATELIMIT": inert, "SMB_SHARE_LIST_RATELIMIT": inert,

	// Capacity, quotas, process.
	"QUOTA_SSH_SESSION_GLOBAL": used, "QUOTA_SSH_SESSION_PER_USER": used,
	"QUOTA_QUICK_CONNECTION_GLOBAL": inert, "QUOTA_QUICK_CONNECTION_PER_USER": inert,
	"QUOTA_TRANSFER_GLOBAL": inert, "QUOTA_TRANSFER_PER_USER": inert,
	"QUOTA_TEMP_BYTES_GLOBAL": inert, "QUOTA_TEMP_BYTES_PER_USER": inert,
	"QUOTA_BACKGROUND_JOB_GLOBAL": inert, "QUOTA_BACKGROUND_JOB_PER_USER": inert,
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
	"SFTP_OPERATION_TIMEOUT": inert, "MAX_UPLOAD_SIZE": inert, "MAX_EDITOR_FILE_SIZE": inert,
	"EDITOR_SAVE_BYTES_PER_MINUTE": inert, "FILE_CONTROL_MAX_PATH_BYTES": inert,
	"REMOTE_FILENAME_MAX_BYTES": inert, "REMOTE_LISTING_MAX_METADATA_BYTES": inert,
	"REMOTE_LISTING_PAGE_SIZE": inert, "REMOTE_LISTING_SNAPSHOT_TTL_SECONDS": inert,
	"REMOTE_LISTING_SNAPSHOT_MAX_STATES": inert, "REMOTE_LISTING_SNAPSHOT_MAX_PER_USER": inert,
	"SFTP_MAX_PACKET_BYTES": inert, "SFTP_MAX_HANDLE_BYTES": inert,
	"FILE_CONTROL_BYTES_PER_MINUTE": inert, "MAX_DOWNLOAD_SIZE": inert,
	"MAX_ZIP_DOWNLOAD_SIZE": inert, "MAX_TRANSFER_MEMBERS": inert, "MAX_PREVIEW_SIZE": inert,
	"MAX_PREVIEW_TAIL_LINES": inert, "MAX_SUPPORTED_FILE_SIZE": inert,
	"SMB_CONNECT_TIMEOUT_SECONDS": inert, "SMB_IO_IDLE_TIMEOUT_SECONDS": inert,
	"SMB_MAX_SAVED_SHARES": inert,

	// Storage limits.
	"COMMAND_MAX_RECORDS": inert, "COMMAND_SET_MAX_RECORDS": inert, "COMMAND_SET_MAX_STEPS": inert,
	"COMMAND_OS_MAX_ENTRIES": inert, "COMMAND_STORE_MAX_BYTES": inert, "COMMAND_CONFIG_MAX_BYTES": inert,
	"PROFILE_MAX_RECORDS": used, "JUMP_HOST_MAX_RECORDS": used, "SOCKS_PROXY_MAX_RECORDS": used,
	"CONNECTION_STORE_MAX_BYTES": used, "CONNECTION_CONFIG_MAX_BYTES": used,
	"CONNECTION_STORE_RECOVERY_MAX_BYTES": used, "CONNECTION_STORE_RECOVERY_MAX_RECORDS": used,
	"SSH_KEY_MAX_RECORDS": used, "SSH_KEY_STORE_MAX_BYTES": used,
	"MAX_WEBAUTHN_JSON_SIZE": used, "MAX_RECOVERY_JSON_SIZE": used,
	"AUDIT_LOG_MAX_BYTES": inert, "AUDIT_LOG_BACKUP_COUNT": inert,
	"BACKUP_MAX_MEMBERS": inert, "BACKUP_MAX_FILE_SIZE": inert, "BACKUP_MAX_TOTAL_SIZE": inert,
	"BACKUP_MAX_COMPRESSION_RATIO": inert, "BACKUP_MAX_MANIFEST_SIZE": inert,
	"BACKUP_UPLOAD_MAX_SIZE": inert, "BACKUP_OPERATION_TIMEOUT": inert, "BACKUP_DOWNLOAD_TTL": inert,

	// Python runtime and image.
	"PYTHONDONTWRITEBYTECODE": obsolete, "PYTHONUNBUFFERED": obsolete, "PYTHON_DOTENV_DISABLED": obsolete,
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

// usageWarnings reports the explicitly set variables this preview does
// not act on, in name order.
func usageWarnings(p *parser, c *Config) {
	names := make([]string, 0, len(c.explicit))
	for name := range c.explicit {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		switch variables[name] {
		case inert:
			p.warn(WarnNoEffect, name, "accepted, but without effect in this preview")
		case obsolete:
			if name == "RATELIMIT_STORAGE_URL" && strings.EqualFold(pyStrip(p.raw(name, "")), "memory://") {
				continue
			}
			if name == "RATELIMIT_STORAGE_URL" {
				p.warn(WarnObsolete, name, "is ignored: the Go release keeps rate limit counters in the process, so they start over after a restart")
				continue
			}
			p.warn(WarnObsolete, name, "has no meaning in the Go release; it is still checked like in the Python release, so a return to Python keeps starting")
		}
	}
}
