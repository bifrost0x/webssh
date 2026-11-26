package config

import (
	"errors"
	"strings"
)

// validateSecurity is validate_security_config of config.py, which the
// Python release runs at import time: its errors stop the start, its
// homelab warnings are logged.
func validateSecurity(p *parser, c *Config, in *pending) {
	if p.failed() {
		return
	}
	pairs, malformed := 0, false
	if in.tailscaleEnabled {
		for _, t := range in.tailscaleTargets {
			if _, _, err := tailscaleTarget(t); err == nil || errors.Is(err, errNonASCIIHost) {
				pairs++
			} else {
				malformed = true
			}
		}
	}
	if in.smbEnabled && len(in.smbTargets) == 0 {
		p.fail(configError("SMB_ALLOWED_TARGETS", "SECURITY ERROR: SMB_ALLOWED_TARGETS is required when SMB_ENABLED is true"))
		return
	}
	for _, t := range in.smbTargets {
		if _, err := smbTarget(t); err != nil && !errors.Is(err, errNonASCIIHost) {
			p.fail(configError("SMB_ALLOWED_TARGETS", "SECURITY ERROR: SMB_ALLOWED_TARGETS must contain exact hostnames or IP addresses without ports, paths, or wildcards"))
			return
		}
	}
	if in.smbConnectTimeout > 60 || in.smbIdleTimeout > 300 {
		p.fail(configError("SMB_CONNECT_TIMEOUT_SECONDS", "SECURITY ERROR: SMB timeout values exceed their bounded limits"))
		return
	}
	if in.ldapEnabled {
		if err := validateLDAP(&in.ldap); err != nil {
			p.fail(err)
			return
		}
	}
	if c.Features.WebAuthn {
		if err := validateWebAuthn(c); err != nil {
			p.fail(err)
			return
		}
	}
	if in.oidcEnabled {
		if err := validateOIDC(c, in); err != nil {
			p.fail(err)
			return
		}
	}
	if c.Profile == ProfileProduction {
		if v := productionViolations(c, in, pairs, malformed); v != "" {
			p.fail(configError("DEPLOYMENT_PROFILE", "SECURITY ERROR: unsafe production profile: "+v))
		}
		return
	}
	homelabWarnings(p, c, in, pairs, malformed)
}

func homelabWarnings(p *parser, c *Config, in *pending, pairs int, malformed bool) {
	w := func(variable, msg string) { p.warn(WarnSecurity, variable, "%s", msg) }
	if c.Origins.AllowAny || in.allowCORSWildcard {
		w("CORS_ORIGINS", "CORS_ORIGINS wildcard compatibility is enabled for the homelab profile")
	}
	if !c.Cookies.Secure {
		w("SESSION_COOKIE_SECURE", "SESSION_COOKIE_SECURE is disabled for the homelab profile")
	} else if !c.Debug && in.sessionSecureRaw != "true" && in.sessionSecureRaw != "false" {
		w("SESSION_COOKIE_SECURE", `SESSION_COOKIE_SECURE defaults to true: browsers drop the session cookie on plain HTTP addresses other than localhost, and every sign-in then fails with "The form expired". Serve WebSSH over HTTPS, or set SESSION_COOKIE_SECURE=false on a trusted network; set it to true to silence this warning`)
	}
	if c.Accounts.RegistrationEnabled {
		w("REGISTRATION_ENABLED", "REGISTRATION_ENABLED is enabled for the homelab profile")
	}
	if c.Accounts.BootstrapRegistrationEnabled {
		w("BOOTSTRAP_REGISTRATION_ENABLED", "BOOTSTRAP_REGISTRATION_ENABLED permits one browser-created administrator while no user account exists")
	}
	if !c.Network.BlockInternalSSH {
		w("BLOCK_INTERNAL_SSH", "BLOCK_INTERNAL_SSH is disabled for the homelab profile")
		if len(c.Network.AllowedInternalNetworks) > 0 {
			w("SSH_ALLOWED_INTERNAL_NETWORKS", "SSH_ALLOWED_INTERNAL_NETWORKS has no effect while BLOCK_INTERNAL_SSH is disabled")
		}
	}
	if in.tailscaleEnabled {
		if len(in.tailscaleTargets) == 0 {
			w("TAILSCALE_SSH_ALLOWED_TARGETS", "TAILSCALE_SSH_ALLOWED_TARGETS is empty; Tailscale SSH connections fail closed in the homelab profile")
		} else if malformed {
			w("TAILSCALE_SSH_ALLOWED_TARGETS", "TAILSCALE_SSH_ALLOWED_TARGETS contains malformed entries; those entries are ignored in the homelab profile")
		}
		if len(in.tailscaleTargets) > 0 && pairs == 0 {
			w("TAILSCALE_SSH_ALLOWED_TARGETS", "TAILSCALE_SSH_ALLOWED_TARGETS contains no valid targets; Tailscale SSH connections fail closed in the homelab profile")
		}
		if in.tailscaleInterface == "" {
			w("TAILSCALE_SSH_INTERFACE", "TAILSCALE_SSH_INTERFACE is empty; Tailscale SSH connections fail closed in the homelab profile")
		}
	}
}

func productionViolations(c *Config, in *pending, pairs int, malformed bool) string {
	var v []string
	if c.Debug {
		v = append(v, "DEBUG must be False")
	}
	valid := true
	for part := range strings.SplitSeq(in.rawCORSOrigins, ",") {
		origin := pyStrip(part)
		u, err := pyURLSplit(origin)
		if origin == "" || err != nil || u.scheme != "https" || u.netloc == "" || u.hasCredentials() || u.path != "" || u.query != "" || u.fragment != "" {
			valid = false
			break
		}
	}
	if c.Origins.AllowAny || !valid {
		v = append(v, "CORS_ORIGINS must explicitly list trusted HTTPS origins")
	}
	if in.allowCORSWildcard {
		v = append(v, "ALLOW_CORS_WILDCARD must be false")
	}
	if c.Origins.SkipSameOrigin {
		v = append(v, "SOCKETIO_ALLOW_ANY_ORIGIN must be false")
	}
	if !c.Cookies.Secure {
		v = append(v, "SESSION_COOKIE_SECURE must be true")
	}
	if c.Accounts.RegistrationEnabled {
		v = append(v, "REGISTRATION_ENABLED must be False")
	}
	if c.Accounts.BootstrapRegistrationEnabled {
		v = append(v, "BOOTSTRAP_REGISTRATION_ENABLED must be false")
	}
	if !c.Network.BlockInternalSSH {
		v = append(v, "BLOCK_INTERNAL_SSH must be true")
	}
	if in.tailscaleEnabled {
		switch {
		case len(in.tailscaleTargets) == 0:
			v = append(v, "TAILSCALE_SSH_ALLOWED_TARGETS must contain exact host and port entries when TAILSCALE_SSH_ENABLED is true")
		case malformed:
			v = append(v, "TAILSCALE_SSH_ALLOWED_TARGETS contains a malformed target")
		case pairs == 0:
			v = append(v, "TAILSCALE_SSH_ALLOWED_TARGETS must contain at least one valid target")
		}
		if in.tailscaleInterface == "" {
			v = append(v, "TAILSCALE_SSH_INTERFACE must name the trusted Tailscale network interface")
		}
	}
	if !c.Proxies.HopsExplicit {
		v = append(v, "TRUSTED_PROXIES must be set explicitly, including 0 when no proxy headers are trusted")
	}
	return strings.Join(v, "; ")
}

func validateWebAuthn(c *Config) error {
	u, err := pyURLSplit(c.WebAuthn.Origin)
	if err != nil {
		return configError("WEBAUTHN_ORIGIN", "WEBAUTHN_ORIGIN cannot be parsed as a URL")
	}
	host := pyLower(u.hostname())
	localHTTP := u.scheme == "http" && host == "localhost" && c.Profile == ProfileHomelab
	if host == "" || u.hasCredentials() || u.path != "" || u.query != "" || u.fragment != "" || u.scheme != "https" && !localHTTP {
		return configError("WEBAUTHN_ORIGIN", "SECURITY ERROR: WEBAUTHN_ORIGIN must be an exact HTTPS origin (HTTP is allowed only for localhost in homelab)")
	}
	rpID := strings.TrimRight(pyLower(c.WebAuthn.RPID), ".")
	_, ipErr := pyIPAddress(rpID)
	if rpID == "" || ipErr == nil || host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return configError("WEBAUTHN_RP_ID", "SECURITY ERROR: WEBAUTHN_RP_ID must be the origin domain or one of its parent domains, not an IP address")
	}
	return nil
}

func validateOIDC(c *Config, in *pending) error {
	issuer, err := pyURLSplit(in.oidcIssuer)
	if err != nil {
		return configError("OIDC_ISSUER", "OIDC_ISSUER cannot be parsed as a URL")
	}
	if issuer.scheme != "https" || issuer.hostname() == "" || issuer.hasCredentials() || issuer.query != "" || issuer.fragment != "" {
		return configError("OIDC_ISSUER", "SECURITY ERROR: OIDC_ISSUER must be an exact HTTPS issuer URL")
	}
	redirect, err := pyURLSplit(in.oidcRedirectURI)
	if err != nil {
		return configError("OIDC_REDIRECT_URI", "OIDC_REDIRECT_URI cannot be parsed as a URL")
	}
	host := pyLower(redirect.hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	localHTTP := redirect.scheme == "http" && loopback && c.Profile == ProfileHomelab
	callback := strings.TrimRight(in.rawApplicationRoot, "/") + "/oidc/callback"
	if host == "" || redirect.hasCredentials() || redirect.path != callback || redirect.query != "" || redirect.fragment != "" || redirect.scheme != "https" && !localHTTP {
		return configError("OIDC_REDIRECT_URI", "SECURITY ERROR: OIDC_REDIRECT_URI must be the exact HTTPS callback URL for /oidc/callback (HTTP is allowed only for loopback hosts in homelab)")
	}
	return nil
}
