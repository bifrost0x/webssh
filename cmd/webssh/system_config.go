package main

import (
	cmdlib "github.com/bifrost0x/webssh/internal/commands"
	"os"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/settings"
)

// adminSwitchDefaults are the boolean administrator switches the settings
// fall back to, with the defaults of config.py (_admin_switch_env).
var adminSwitchDefaults = map[string]bool{
	"AUTOMATION_ENABLED":        false,
	"SERVER_OPERATIONS_ENABLED": false,
	"SFTP_CHMOD_ENABLED":        false,
	"TMUX_ENABLED":              true,
	"TMUX_DEFAULT":              false,
}

// envSwitch is _admin_switch_env: a stripped, non-empty value is true
// only for "true" in any case; otherwise the default applies.
func envSwitch(lookup config.LookupFunc, name string, def bool) bool {
	v, ok := lookup(name)
	if v = strings.TrimSpace(v); !ok || v == "" {
		return def
	}
	return strings.ToLower(v) == "true"
}

// envFlag is os.environ.get(name, 'false').lower() == 'true'.
func envFlag(lookup config.LookupFunc, name string) bool {
	v, _ := lookup(name)
	return strings.ToLower(v) == "true"
}

// settingsEnvironment is what the application settings fall back to or
// are locked by.
func settingsEnvironment(cfg config.Config, lookup config.LookupFunc) settings.Environment {
	env := settings.Environment{
		Values:           map[string]bool{"REGISTRATION_ENABLED": cfg.Accounts.RegistrationEnabled},
		Explicit:         map[string]bool{},
		Production:       cfg.Profile == config.ProfileProduction,
		AuditBackupCount: cfg.Audit.BackupCount,
	}
	for name, def := range adminSwitchDefaults {
		env.Values[name] = envSwitch(lookup, name, def)
	}
	for name := range env.Values {
		env.Explicit[name] = cfg.Explicit(name)
	}
	return env
}

// tourDeployment are the deployment facts of the introduction tour, the
// configuration values as in the Python release; the runtime switches
// replace chmod, server operations and tmux. tmux is false where the
// build cannot run tmux sessions.
func tourDeployment(cfg config.Config, lookup config.LookupFunc, tmux bool) settings.TourDeployment {
	return settings.TourDeployment{
		Values: map[string]bool{
			"SMB_ENABLED":               cfg.SMB.Enabled,
			"SFTP_CHMOD_ENABLED":        envSwitch(lookup, "SFTP_CHMOD_ENABLED", false),
			"SERVER_OPERATIONS_ENABLED": envSwitch(lookup, "SERVER_OPERATIONS_ENABLED", false),
			"TMUX_ENABLED":              tmux && cfg.Features.Tmux.Value, "TAILSCALE_SSH_ENABLED": cfg.Network.TailscaleSSHEnabled,
			"OIDC_ENABLED": cfg.OIDC.Enabled, "LDAP_ENABLED": cfg.LDAP.Enabled,
			"TOTP_ENABLED": cfg.Features.TOTP, "WEBAUTHN_ENABLED": cfg.Features.WebAuthn,
			"BOOTSTRAP_REGISTRATION_ENABLED": cfg.Accounts.BootstrapRegistrationEnabled,
			"SESSION_COOKIE_SECURE":          cfg.Cookies.Secure,
		},
		AdminPanelEnabled: cfg.Accounts.AdminPanelEnabled,
		ProcessRoot:       processRoot(),
	}
}

// featureDeployment is the deployment ceiling of each security feature.
func featureDeployment(cfg config.Config, lookup config.LookupFunc) map[string]bool {
	return map[string]bool{
		"passkey":  cfg.Features.WebAuthn,
		"totp":     cfg.Features.TOTP,
		"recovery": cfg.Features.RecoveryCodes,
		"oidc":     envFlag(lookup, "OIDC_ENABLED"),
		"ldap":     envFlag(lookup, "LDAP_ENABLED"),
	}
}

// featureReadiness is the start-up readiness of each security feature.
// Passkeys, OIDC and LDAP become ready when their capability registers
// and sets itself up; until then they are "not ready", as in the Python
// release.
func featureReadiness() map[string]operations.Readiness {
	return map[string]operations.Readiness{
		"totp":     {Ready: true},
		"recovery": {Ready: true},
		"passkey":  {},
		"oidc":     {},
		"ldap":     {},
	}
}

// Rate limits of the sign-in forms and the realtime messages, with the
// defaults of config.py where a value does not parse.
var (
	ruleLogin    = auth.Rule{Limit: 5, Window: time.Minute}
	ruleDefault  = auth.Rule{Limit: 200, Window: time.Hour}
	ruleReauth   = auth.Rule{Limit: 10, Window: time.Minute}
	ruleConnect  = auth.Rule{Limit: 10, Window: time.Minute}
	ruleKeyWrite = auth.Rule{Limit: 30, Window: time.Minute}
	ruleKeyList  = auth.Rule{Limit: 30, Window: time.Minute}
	ruleMutation = auth.Rule{Limit: 60, Window: time.Minute}

	ruleSMBConnect  = auth.Rule{Limit: 5, Window: time.Minute}
	ruleSMBMutation = auth.Rule{Limit: 30, Window: time.Minute}
	ruleSMBList     = auth.Rule{Limit: 60, Window: time.Minute}

	// CAPABILITY_RATE_LIMIT of the SFTP probe.
	ruleSFTPProbe = auth.Rule{Limit: 10, Window: time.Minute}
)

// realtimeLimiter is the limiter of the realtime messages, separate from
// the sign-in limiter so that realtime traffic cannot use up the sign-in
// budget. The buckets are those of the Python socket handlers.
func realtimeLimiter(cfg config.Config) *auth.Limiter {
	l := auth.NewLimiter()
	l.Realtime = map[string]auth.Rule{
		"ssh_connect":         auth.ParseRule(cfg.RateLimits.SSHConnect, ruleConnect),
		"ssh_key_list":        auth.ParseRule(cfg.RateLimits.SSHKeyList, ruleKeyList),
		"ssh_key_write":       auth.ParseRule(cfg.RateLimits.SSHKeyWrite, ruleKeyWrite),
		"connection_mutation": auth.ParseRule(cfg.RateLimits.ConnectionMutation, ruleMutation),
		cmdlib.RateMutation:   auth.ParseRule(cfg.RateLimits.CommandMutation, ruleMutation),
		smb.RateConnect:       auth.ParseRule(cfg.SMB.ConnectRateLimit, ruleSMBConnect),
		smb.RateShareMutation: auth.ParseRule(cfg.SMB.ShareMutationRateLimit, ruleSMBMutation),
		smb.RateShareList:     auth.ParseRule(cfg.SMB.ShareListRateLimit, ruleSMBList),
		sftp.RateProbe:        ruleSFTPProbe,
		// A visible workspace polls the directory about 40 times a minute;
		// the budget covers every connection a user may hold.
		sftp.RateDirectory: {Limit: max(90, cfg.Terminal.MaxConnectionsPerUser*60), Window: time.Minute},
	}
	l.RealtimeDefault = ruleMutation
	return l
}

// processRoot reports whether the process runs as root; nil where the
// platform has no user IDs.
func processRoot() *bool {
	uid := os.Geteuid()
	if uid < 0 {
		return nil
	}
	root := uid == 0
	return &root
}
