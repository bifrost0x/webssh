package config

import (
	"strings"
	"time"
)

// pending holds raw values validate_security_config needs beside the
// parsed ones.
type pending struct {
	oidcEnabled, ldapEnabled, smbEnabled, tailscaleEnabled bool
	oidcIssuer, oidcRedirectURI, rawApplicationRoot        string
	ldap                                                   ldapSettings
	smbTargets, tailscaleTargets                           []string
	tailscaleInterface                                     string
	smbConnectTimeout, smbIdleTimeout                      int64
	sessionSecureRaw, rawCORSOrigins                       string
	allowCORSWildcard                                      bool
}

type ldapSettings struct {
	url, backupURL, providerID, baseDN, bindDN, bindPasswordFile, caFile, userFilter, uniqueID string
}

// Load reads the configuration from the environment as config.py of the
// Python release sees it, that is after ResolveDataDir and
// ResolveSecretKey (Bootstrap runs all three). It fails where the Python
// release fails to start, with the same message, and where the Go release
// refuses a value it adds (TRUSTED_PROXY_CIDRS). The warnings are meant for the startup log.
func Load(lookup LookupFunc) (Config, []Warning, error) {
	c, warns, _, err := load(lookup)
	return c, warns, err
}

// load also returns the Python view for the differential tests.
func load(lookup LookupFunc) (Config, []Warning, map[string]any, error) {
	p := newParser(lookup)
	var c Config
	var in pending
	loadCore(p, &c, &in)
	loadIdentity(p, &c, &in)
	loadLimits(p, &c)
	loadSessions(p, &c, &in)
	loadWeb(p, &c, &in)
	loadNetwork(p, &c, &in)
	validateSecurity(p, &c, &in)
	if p.failed() {
		return Config{}, p.warns, p.view, p.err
	}
	c.explicit = explicitKeys(lookup)
	goChecks(p, &c, lookup)
	if p.failed() {
		return Config{}, p.warns, p.view, p.err
	}
	return c, p.warns, p.view, nil
}

func seconds(v int64) time.Duration { return time.Duration(v) * time.Second }

// loadCore follows config.py from DEPLOYMENT_PROFILE to the feature
// switches.
func loadCore(p *parser, c *Config, in *pending) {
	profile := pyLower(pyStrip(p.raw("DEPLOYMENT_PROFILE", "homelab")))
	if profile != string(ProfileHomelab) && profile != string(ProfileProduction) {
		p.fail(configError("DEPLOYMENT_PROFILE", `CONFIGURATION ERROR: DEPLOYMENT_PROFILE must be either "homelab" or "production"`))
		return
	}
	c.Profile = Profile(profile)
	p.record("DEPLOYMENT_PROFILE", profile)

	c.DataDir = pyPath(p.raw("DATA_DIR", defaultDataDir))
	p.record("DATA_DIR", c.DataDir)
	p.record("TRANSFER_TEMP_DIR", pyPath(p.raw("TRANSFER_TEMP_DIR", c.DataDir+"/tmp")))

	c.Features.WebAuthn = p.flag("WEBAUTHN_ENABLED", "WEBAUTHN_ENABLED", "false")
	c.WebAuthn.RPID = p.str("WEBAUTHN_RP_ID", "WEBAUTHN_RP_ID", "localhost", true)
	c.WebAuthn.RPName = p.str("WEBAUTHN_RP_NAME", "WEBAUTHN_RP_NAME", "WebSSH", true)
	c.WebAuthn.Origin = p.str("WEBAUTHN_ORIGIN", "WEBAUTHN_ORIGIN", "https://localhost", true)

	c.Features.HostKeyManagement = p.flag("HOST_KEY_MANAGEMENT_ENABLED", "HOST_KEY_MANAGEMENT_ENABLED", "true")
	p.adminSwitch("AUTOMATION_ENABLED", false)
	c.Features.AutomationInsecureLoopback = p.flag("AUTOMATION_ALLOW_INSECURE_LOOPBACK", "AUTOMATION_ALLOW_INSECURE_LOOPBACK", "false")
	p.adminSwitch("SERVER_OPERATIONS_ENABLED", false)
	c.Features.RecoveryCodes = p.flag("RECOVERY_CODES_ENABLED", "RECOVERY_CODES_ENABLED", "true")
	c.Audit.ExportEnabled = p.flag("AUDIT_EXPORT_ENABLED", "AUDIT_EXPORT_ENABLED", "true")
}

// loadIdentity follows config.py through OIDC, LDAP and the step-up age.
func loadIdentity(p *parser, c *Config, in *pending) {
	o := &c.OIDC
	in.oidcEnabled = p.flag("OIDC_ENABLED", "OIDC_ENABLED", "false")
	in.oidcIssuer = strings.TrimRight(p.str("OIDC_ISSUER", "OIDC_ISSUER", "", true), "/")
	p.record("OIDC_ISSUER", in.oidcIssuer)
	o.ClientID = p.str("OIDC_CLIENT_ID", "OIDC_CLIENT_ID", "", true)
	o.ClientSecretFile = p.str("OIDC_CLIENT_SECRET_FILE", "OIDC_CLIENT_SECRET_FILE", "", true)
	in.oidcRedirectURI = p.str("OIDC_REDIRECT_URI", "OIDC_REDIRECT_URI", "", true)
	o.AllowedSubjects = p.csvSet("OIDC_ALLOWED_SUBJECTS", "OIDC_ALLOWED_SUBJECTS", nil)
	o.AllowedDomains = p.csvSet("OIDC_ALLOWED_DOMAINS", "OIDC_ALLOWED_DOMAINS", pyLower)
	o.LoginRateLimit = p.str("OIDC_LOGIN_RATE_LIMIT", "OIDC_LOGIN_RATE_LIMIT", "10 per minute", false)
	o.Enabled, o.Issuer, o.RedirectURI = in.oidcEnabled, in.oidcIssuer, in.oidcRedirectURI

	in.ldapEnabled = p.flag("LDAP_ENABLED", "LDAP_ENABLED", "false")
	autoProvision := p.flag("LDAP_AUTO_PROVISION", "LDAP_AUTO_PROVISION", "false")
	l := &in.ldap
	l.providerID = p.str("LDAP_PROVIDER_ID", "LDAP_PROVIDER_ID", "default", true)
	l.url = p.str("LDAP_URL", "LDAP_URL", "", true)
	l.backupURL = p.str("LDAP_BACKUP_URL", "LDAP_BACKUP_URL", "", true)
	l.baseDN = p.str("LDAP_BASE_DN", "LDAP_BASE_DN", "", true)
	l.bindDN = p.str("LDAP_BIND_DN", "LDAP_BIND_DN", "", true)
	l.bindPasswordFile = p.str("LDAP_BIND_PASSWORD_FILE", "LDAP_BIND_PASSWORD_FILE", "/run/webssh-auth/ldap_bind_password", true)
	l.caFile = p.str("LDAP_CA_FILE", "LDAP_CA_FILE", "/run/webssh-auth/ldap_ca.pem", true)
	l.userFilter = p.str("LDAP_USER_FILTER", "LDAP_USER_FILTER", "", true)
	l.uniqueID = p.str("LDAP_UNIQUE_ID_ATTRIBUTE", "LDAP_UNIQUE_ID_ATTRIBUTE", "", true)
	ldapRate := p.str("LDAP_LOGIN_RATE_LIMIT", "LDAP_LOGIN_RATE_LIMIT", "5 per minute", false)

	c.Terminal.SessionTimeout = seconds(p.positive("SESSION_TIMEOUT", 1800))

	connect := p.bounded("LDAP_CONNECT_TIMEOUT", 5, 1, 15)
	operation := p.bounded("LDAP_OPERATION_TIMEOUT", 5, 1, 30)
	revalidation := p.bounded("LDAP_SESSION_REVALIDATION_SECONDS", 300, 60, 3600)
	c.LDAP = l.public(in.ldapEnabled, autoProvision, ldapRate, connect, operation, revalidation)
	c.Features.TOTP = p.flag("TOTP_ENABLED", "TOTP_ENABLED", "true")
	for name, dst := range map[string]*[]string{
		"OIDC_MFA_AMR_VALUES": &o.MFAAMR, "OIDC_MFA_ACR_VALUES": &o.MFAACR,
		"OIDC_PHISHING_RESISTANT_AMR_VALUES": &o.PhishingAMR, "OIDC_PHISHING_RESISTANT_ACR_VALUES": &o.PhishingACR,
		"OIDC_STEP_UP_ACR_VALUES": &o.StepUpACR,
	} {
		*dst = p.csvSet(name, name, nil)
	}
	c.StepUpMaxAge = seconds(p.bounded("STEP_UP_MAX_AGE_SECONDS", 300, 60, 900))
}
