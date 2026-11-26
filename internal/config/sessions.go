package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
)

// secretPlaceholders are the values config.py treats as "no secret" after
// strip() and lower().
var secretPlaceholders = map[string]bool{
	"<your-secret-key>": true, "changeme": true, "secret": true, "your-secret-key": true,
}

// randomSecret is replaceable in tests.
var randomSecret = func() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var cookieName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// loadSessions follows config.py from ADMIN_USERS to the output flow
// limits.
func loadSessions(p *parser, c *Config, in *pending) {
	c.Accounts.AdminUsers = p.csvList("ADMIN_USERS", "ADMIN_USERS")
	c.Accounts.AdminPanelEnabled = p.flag("ADMIN_PANEL_ENABLED", "ADMIN_PANEL_ENABLED", "true")

	in.tailscaleEnabled = p.flag("TAILSCALE_SSH_ENABLED", "TAILSCALE_SSH_ENABLED", "false")
	ts := &c.Network.Tailscale
	ts.AllowedWebSSHUsers = p.csvSet("TAILSCALE_SSH_ALLOWED_WEBSSH_USERS", "TAILSCALE_SSH_ALLOWED_WEBSSH_USERS", nil)
	in.tailscaleTargets = p.csvSet("TAILSCALE_SSH_ALLOWED_TARGETS", "TAILSCALE_SSH_ALLOWED_TARGETS", nil)
	ts.AllowedRemoteUsers = p.csvSet("TAILSCALE_SSH_ALLOWED_REMOTE_USERS", "TAILSCALE_SSH_ALLOWED_REMOTE_USERS", nil)
	in.tailscaleInterface = p.str("TAILSCALE_SSH_INTERFACE", "TAILSCALE_SSH_INTERFACE", "tailscale0", true)
	c.Network.TailscaleSSHEnabled, c.Network.TailscaleInterface = in.tailscaleEnabled, in.tailscaleInterface
	for _, raw := range in.tailscaleTargets {
		if host, port, err := tailscaleTarget(raw); err == nil {
			hp := HostPort{Host: host, Port: port}
			if !slices.Contains(ts.AllowedTargets, hp) {
				ts.AllowedTargets = append(ts.AllowedTargets, hp)
			}
		}
	}

	c.Debug = p.flag("DEBUG", "DEBUG", "False")
	loadSecret(p, c)

	sessionName := cookie(p, "SESSION_COOKIE_NAME", "session")
	rememberName := cookie(p, "REMEMBER_COOKIE_NAME", "remember_token")
	if !p.failed() && sessionName == rememberName {
		p.fail(configError("REMEMBER_COOKIE_NAME", "SESSION_COOKIE_NAME and REMEMBER_COOKIE_NAME must differ"))
	}
	c.Cookies.SessionName, c.Cookies.RememberName = sessionName, rememberName
	in.sessionSecureRaw = pyLower(p.raw("SESSION_COOKIE_SECURE", ""))
	switch in.sessionSecureRaw {
	case "true":
		c.Cookies.Secure = true
	case "false":
		c.Cookies.Secure = false
	default:
		c.Cookies.Secure = !c.Debug
		if in.sessionSecureRaw != "" {
			p.warn(WarnQuirk, "SESSION_COOKIE_SECURE", "the value %q counts as not set, as in the Python release; write true or false", p.raw("SESSION_COOKIE_SECURE", ""))
		}
	}
	p.record("SESSION_COOKIE_SECURE", c.Cookies.Secure)

	c.Proxies.HopsExplicit = p.present("TRUSTED_PROXIES")
	c.Proxies.Hops = int(min(p.nonNegative("TRUSTED_PROXIES", 0), 1<<31-1))

	threads := p.bounded("GUNICORN_THREADS", 64, 8, 256)
	sockets := p.bounded("MAX_SOCKET_CONNECTIONS", 48, 1, 252)
	perUser := p.bounded("MAX_SOCKET_CONNECTIONS_PER_USER", 8, 1, 64)
	if !p.failed() && perUser > sockets {
		p.fail(configError("MAX_SOCKET_CONNECTIONS_PER_USER", "CONFIGURATION ERROR: MAX_SOCKET_CONNECTIONS_PER_USER cannot exceed MAX_SOCKET_CONNECTIONS"))
	}
	if !p.failed() && threads-sockets < 4 {
		p.fail(configError("MAX_SOCKET_CONNECTIONS", "CONFIGURATION ERROR: MAX_SOCKET_CONNECTIONS must leave at least 4 Gunicorn threads available for HTTP"))
	}
	c.Terminal.MaxConnections, c.Terminal.MaxConnectionsPerUser = int(sockets), int(perUser)

	o := &c.Terminal.Output
	o.BytesPerSocket = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_BYTES_PER_SOCKET", 512*kib, 256*kib, 16*mib))
	o.EventsPerSocket = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET", 128, 8, 4096))
	o.EventsPerUser = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER", 1024, int64(o.EventsPerSocket), 32768))
	o.EventsGlobal = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL", 8192, int64(o.EventsPerUser), 131072))
	o.BytesPerUser = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_BYTES_PER_USER", 4*mib, int64(o.BytesPerSocket), 64*mib))
	o.BytesGlobal = int(p.bounded("SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL", 32*mib, int64(o.BytesPerUser), 256*mib))
	o.AckTimeout = seconds(p.bounded("SSH_OUTPUT_ACK_TIMEOUT_SECONDS", 10, 1, 120))
}

// loadSecret applies config.py's checks to the secret the process sees,
// which ResolveSecretKey has already taken from the environment or the
// data directory.
func loadSecret(p *parser, c *Config) {
	if p.failed() {
		return
	}
	key, ok := p.get("SECRET_KEY")
	if !ok || key == "" || secretPlaceholders[pyLower(pyStrip(key))] {
		if !c.Debug {
			p.fail(configError("SECRET_KEY", `SECURITY ERROR: SECRET_KEY environment variable is required in production. Generate one with: python -c "import secrets; print(secrets.token_hex(32))"`))
			return
		}
		generated, err := randomSecret()
		if err != nil {
			p.fail(fmt.Errorf("config: generate a temporary SECRET_KEY: %w", err))
			return
		}
		key = generated
		c.SecretSource = SecretEphemeral
		p.warn(WarnPython, "SECRET_KEY", "DEBUG MODE: Using auto-generated SECRET_KEY (not for production!)")
	}
	if !c.Debug && runeLen(key) < 32 {
		p.warn(WarnPython, "SECRET_KEY", `SECRET_KEY is shorter than 32 characters. Generate a longer one with: python -c "import secrets; print(secrets.token_hex(32))"`)
	}
	c.SecretKey = NewSecret([]byte(key))
	if c.SecretSource == "" {
		// The Python CLI treats every value but "environment" as the file.
		c.SecretSource = SecretFromFile
		if p.raw(secretSourceVariable, "") == string(SecretFromEnvironment) {
			c.SecretSource = SecretFromEnvironment
		}
	}
}

func cookie(p *parser, name, def string) string {
	if p.failed() {
		return ""
	}
	v := p.raw(name, def)
	if !cookieName.MatchString(v) {
		p.fail(configError(name, name+" must be a non-empty cookie name containing only letters, digits, dots, underscores or hyphens"))
		return ""
	}
	p.record(name, v)
	return v
}
