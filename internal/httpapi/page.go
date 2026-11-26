// Package httpapi is the HTTP edge of WebSSH: server, routing, middleware,
// health, static files and the server-rendered pages.
package httpapi

// PageData holds every value the server-rendered pages read. It replaces
// the keyword arguments and context processor values of the Python
// templates; the JSON names are the Python variable names, which the
// parity test between both template sets relies on.
//
// The composition root fills it from consumer interfaces of the
// capabilities. Values that come from users (names, labels, flash
// messages) are plain strings: html/template escapes them for the context
// they appear in, and no field may carry template.HTML.
type PageData struct {
	// BasePath is the path the application is reached under, as seen by
	// the browser; links and asset URLs start with it. URLPrefix is the
	// configured APPLICATION_ROOT, published to the scripts in the
	// app-root meta tag. Both are empty at the root.
	BasePath  string `json:"script_root"`
	URLPrefix string `json:"url_prefix"`

	CSRFToken string  `json:"csrf_token"`
	User      User    `json:"current_user"`
	Flashes   []Flash `json:"flashes"`

	Theme           string `json:"theme"`
	BackgroundScope string `json:"background_scope"`
	WebSSHVersion   string `json:"webssh_version"`

	// Installation features.
	RegistrationEnabled      bool   `json:"registration_enabled"`
	AdminPanelEnabled        bool   `json:"admin_panel_enabled"`
	SSHGatewayEnabled        bool   `json:"ssh_gateway_enabled"`
	HerdrEnabled             bool   `json:"herdr_enabled"`
	TmuxEnabled              bool   `json:"tmux_enabled"`
	TmuxDefault              bool   `json:"tmux_default"`
	WebAuthnEnabled          bool   `json:"webauthn_enabled"`
	WebAuthnOrigin           string `json:"webauthn_origin"`
	WebAuthnRPID             string `json:"webauthn_rp_id"`
	TOTPEnabled              bool   `json:"totp_enabled"`
	OIDCEnabled              bool   `json:"oidc_enabled"`
	GitHubAuthEnabled        bool   `json:"github_auth_enabled"`
	LDAPEnabled              bool   `json:"ldap_enabled"`
	LDAPProviderID           string `json:"ldap_provider_id"`
	LDAPManaged              bool   `json:"ldap_managed"`
	RecoveryCodesEnabled     bool   `json:"recovery_codes_enabled"`
	HostKeyManagementEnabled bool   `json:"host_key_management_enabled"`
	AuditExportEnabled       bool   `json:"audit_export_enabled"`
	TailscaleSSHAllowed      bool   `json:"tailscale_ssh_allowed"`
	SupportLinksEnabled      bool   `json:"support_links_enabled"`
	AutomationEnabled        bool   `json:"automation_enabled"`
	SMBEnabled               bool   `json:"smb_enabled"`
	SFTPChmodEnabled         bool   `json:"sftp_chmod_enabled"`
	HostDiscoveryAvailable   bool   `json:"host_discovery_available"`

	// User settings.
	StartPage                            string               `json:"start_page"`
	OverviewLayout                       string               `json:"overview_layout"`
	OverviewReachability                 string               `json:"overview_reachability"`
	OverviewPreferences                  *OverviewPreferences `json:"overview_preferences"`
	TerminalAppearance                   map[string]any       `json:"terminal_appearance"`
	SyncTerminalDirectory                bool                 `json:"sync_terminal_directory"`
	ConfirmSessionClose                  bool                 `json:"confirm_session_close"`
	DisconnectSessionAction              string               `json:"disconnect_session_action"`
	AuthenticationSessionDurationMinutes int                  `json:"authentication_session_duration_minutes"`

	// Workspace page.
	InitialInventory       any            `json:"initial_inventory"`
	ConnectionHistoryScope string         `json:"connection_history_scope"`
	MaxEditorFileSize      int64          `json:"max_editor_file_size"`
	TransferLimits         TransferLimits `json:"transfer_limits"`
	SSHInputLimits         SSHInputLimits `json:"ssh_input_limits"`
	AuthSessionExpiresAt   int64          `json:"auth_session_expires_at"`
	AuthServerNow          int64          `json:"auth_server_now"`

	// Sign-in page.
	AuthSource  string   `json:"auth_source"`
	MFARequired bool     `json:"mfa_required"`
	MFAMethods  []string `json:"mfa_methods"`
	LDAPError   string   `json:"ldap_error"`

	// Settings page.
	RecoveryMode                bool         `json:"recovery_mode"`
	AuthenticationMethods       []AuthMethod `json:"authentication_methods"`
	AuthenticationPrimaryMethod string       `json:"authentication_primary_method"`
	AccountMFAEnabled           bool         `json:"account_mfa_enabled"`
	GitHubIdentityLinked        bool         `json:"github_identity_linked"`
	GitHubManaged               bool         `json:"github_managed"`

	// Error page.
	Status    int    `json:"status"`
	Kind      string `json:"kind"`
	ActionURL string `json:"action_url"`
	Detail    string `json:"detail"`

	// Preview describes the parts the preview build does not offer. It
	// has no Python counterpart.
	Preview PreviewNotice `json:"preview"`
}

// User is the signed-in account. Python passes it as current_user and,
// on the settings page, again as username and is_admin.
type User struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	IsAdmin       bool   `json:"is_admin"`
	Authenticated bool   `json:"is_authenticated"`
}

// Flash is one message queued for the next page, with its category.
type Flash struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

// AuthMethod is one method of the current sign-in, as shown on the
// settings page.
type AuthMethod struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	I18nKey string `json:"i18n_key"`
}

// OverviewPreferences are the saved overview panels; Panels is stored
// as the browser sent it.
type OverviewPreferences struct {
	Panels    any      `json:"panels"`
	Dismissed []string `json:"dismissed"`
}

// TransferLimits are the transfer size limits the browser checks before
// it starts a transfer.
type TransferLimits struct {
	UploadBytes         int64 `json:"uploadBytes"`
	DownloadBytes       int64 `json:"downloadBytes"`
	ArchiveBytes        int64 `json:"archiveBytes"`
	RemoteTransferBytes int64 `json:"remoteTransferBytes"`
}

// SSHInputLimits bound one terminal input event.
type SSHInputLimits struct {
	MaxEventBytes int64 `json:"maxEventBytes"`
}

// PreviewNotice is published to the preview notice script as JSON.
// Unavailable lists area identifiers the script hides or marks; Message is
// the fallback text for languages the script does not know.
type PreviewNotice struct {
	Enabled     bool     `json:"enabled"`
	Unavailable []string `json:"unavailable"`
	Message     string   `json:"message"`
}
