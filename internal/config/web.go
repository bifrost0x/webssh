package config

import (
	"regexp"
	"strings"
)

var defaultCORSOrigins = []string{"http://localhost:5000", "http://127.0.0.1:5000"}

// loadWeb follows config.py from ALLOW_CORS_WILDCARD to APPLICATION_ROOT.
func loadWeb(p *parser, c *Config, in *pending) {
	in.allowCORSWildcard = p.flag("ALLOW_CORS_WILDCARD", "ALLOW_CORS_WILDCARD", "false")
	c.Origins.AllowWildcard = in.allowCORSWildcard
	if !p.failed() {
		loadCORS(p, c, in)
	}
	c.Origins.SkipSameOrigin = p.flag("SOCKETIO_ALLOW_ANY_ORIGIN", "SOCKETIO_ALLOW_ANY_ORIGIN", "false")

	discovery := pyStrip(p.raw("HOST_DISCOVERY_ENABLED", ""))
	if discovery == "" {
		discovery = "true"
		if c.Profile == ProfileProduction {
			discovery = "false"
		}
	}
	c.Features.HostDiscovery = pyLower(discovery) == "true"
	p.record("HOST_DISCOVERY_ENABLED", c.Features.HostDiscovery)

	r := &c.RateLimits
	r.Enabled = p.flag("RATELIMIT_ENABLED", "RATELIMIT_ENABLED", "true")
	p.str("RATELIMIT_STORAGE_URL", "RATELIMIT_STORAGE_URL", "memory://", false)
	r.Login = p.str("RATELIMIT_LOGIN_LIMIT", "RATELIMIT_LOGIN_LIMIT", "5 per minute", false)
	r.Default = p.str("RATELIMIT_DEFAULT", "RATELIMIT_DEFAULT", "200 per hour", false)
	r.Reauth = p.str("RATELIMIT_REAUTH", "RATELIMIT_REAUTH", "10 per minute", false)
	p.str("RATELIMIT_BACKUP_CREATE", "RATELIMIT_BACKUP_CREATE", "3 per hour", false)
	p.str("RATELIMIT_BACKUP_UPLOAD", "RATELIMIT_BACKUP_UPLOAD", "5 per hour", false)
	p.str("RATELIMIT_BACKUP_DOWNLOAD", "RATELIMIT_BACKUP_DOWNLOAD", "10 per hour", false)
	p.str("RATELIMIT_BACKUP_RESTORE", "RATELIMIT_BACKUP_RESTORE", "3 per hour", false)
	// Five variables are named differently from their Python constant.
	r.SSHConnect = p.str("RATELIMIT_SSH_CONNECT", "SSH_CONNECT_RATELIMIT", "10 per minute", false)
	r.SSHKeyWrite = p.str("RATELIMIT_SSH_KEY_WRITE", "SSH_KEY_WRITE_RATELIMIT", "30 per minute", false)
	r.SSHKeyList = p.str("RATELIMIT_SSH_KEY_LIST", "SSH_KEY_LIST_RATELIMIT", "30 per minute", false)
	r.CommandMutation = p.str("RATELIMIT_COMMAND_MUTATION", "COMMAND_MUTATION_RATELIMIT", "60 per minute", false)
	r.ConnectionMutation = p.str("RATELIMIT_CONNECTION_MUTATION", "CONNECTION_MUTATION_RATELIMIT", "60 per minute", false)

	registration := "False"
	if c.Debug {
		registration = "True"
	}
	c.Accounts.RegistrationEnabled = p.flag("REGISTRATION_ENABLED", "REGISTRATION_ENABLED", registration)
	bootstrap := "false"
	if c.Profile == ProfileHomelab {
		bootstrap = "true"
	}
	c.Accounts.BootstrapRegistrationEnabled = p.flag("BOOTSTRAP_REGISTRATION_ENABLED", "BOOTSTRAP_REGISTRATION_ENABLED", bootstrap)

	in.rawApplicationRoot = p.raw("APPLICATION_ROOT", "")
	c.ApplicationRoot = strings.TrimRight(in.rawApplicationRoot, "/")
	if c.ApplicationRoot != "" {
		p.record("APPLICATION_ROOT", c.ApplicationRoot)
		if !strings.HasPrefix(c.ApplicationRoot, "/") {
			p.warn(WarnQuirk, "APPLICATION_ROOT", "the value %q does not start with a slash; it is used as written, as in the Python release", c.ApplicationRoot)
		}
	}
}

func loadCORS(p *parser, c *Config, in *pending) {
	raw := p.raw("CORS_ORIGINS", "")
	in.rawCORSOrigins = raw
	switch {
	case raw == "*":
		if !c.Debug && !in.allowCORSWildcard {
			p.fail(configError("CORS_ORIGINS", "SECURITY ERROR: CORS_ORIGINS cannot be wildcard (*) in production. Set it to your specific domain(s), e.g., CORS_ORIGINS=https://ssh.example.com Or set ALLOW_CORS_WILDCARD=true if you understand the risks (e.g., homelab use)."))
			return
		}
		if !c.Debug {
			p.warn(WarnPython, "CORS_ORIGINS", "CORS wildcard (*) enabled via ALLOW_CORS_WILDCARD - use only in trusted networks!")
		} else {
			p.warn(WarnPython, "CORS_ORIGINS", "DEBUG MODE: CORS set to wildcard (*) - not for production!")
		}
		c.Origins.AllowAny = true
		p.record("CORS_ORIGINS", "*")
	case raw != "" && !isOriginPlaceholder(raw):
		for part := range strings.SplitSeq(raw, ",") {
			origin := pyStrip(part)
			c.Origins.List = append(c.Origins.List, origin)
			switch {
			case origin == "":
				p.warn(WarnQuirk, "CORS_ORIGINS", "an empty entry is kept as in the Python release; it matches no browser origin")
			case origin == "*":
				p.warn(WarnQuirk, "CORS_ORIGINS", "\"*\" inside a list is not the wildcard; only CORS_ORIGINS=* without other characters is")
			}
		}
		p.record("CORS_ORIGINS", c.Origins.List)
	default:
		c.Origins.List = append([]string(nil), defaultCORSOrigins...)
		if !c.Debug {
			p.warn(WarnInfo, "CORS_ORIGINS", "CORS_ORIGINS not set, using localhost only. Set CORS_ORIGINS for other origins.")
		}
		p.record("CORS_ORIGINS", c.Origins.List)
	}
}

func isOriginPlaceholder(raw string) bool {
	v := strings.Trim(pyStrip(raw), "<>")
	return v == "YOUR-DOMAIN" || v == "YOUR-ORIGIN"
}

var tmuxPrefixUnsafe = regexp.MustCompile(`[^A-Za-z0-9_]`)

// loadTmux follows config.py's tmux settings.
func loadTmux(p *parser, c *Config) {
	c.Features.Tmux = p.adminSwitch("TMUX_ENABLED", true)
	prefix := truncateRunes(tmuxPrefixUnsafe.ReplaceAllString(pyStrip(p.raw("TMUX_SESSION_PREFIX", "")), "_"), 80)
	if prefix == "" {
		prefix = "webssh"
	}
	c.Features.TmuxSessionPrefix = prefix
	p.record("TMUX_SESSION_PREFIX", prefix)
	c.Features.TmuxDefault = p.adminSwitch("TMUX_DEFAULT", false)
}
