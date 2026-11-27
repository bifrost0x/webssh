package config

import (
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// pythonAnswer is what testdata/pyprobe.py reports for one environment.
type pythonAnswer struct {
	Error            string         `json:"error,omitempty"`
	ErrorType        string         `json:"error_type,omitempty"`
	View             map[string]any `json:"view,omitempty"`
	SecurityWarnings []string       `json:"security_warnings,omitempty"`
	SecretKey        string         `json:"secret_key,omitempty"`
	Explicit         []string       `json:"explicit,omitempty"`
	Printed          []string       `json:"printed,omitempty"`
}

type envCase struct {
	Env    map[string]string `json:"env"`
	Python pythonAnswer      `json:"python"`
}

// The checked-in file holds the view of the default environment on its
// first line and then one case per line with only the entries that differ
// from it.

const testSecret = "0123456789abcdef0123456789abcdef-test"

func baseEnv() map[string]string {
	return map[string]string{"SECRET_KEY": testSecret, "DATA_DIR": "/app/data"}
}

var (
	boolPool = []string{"true", "TRUE", "True", " true", "true ", "false", "False", "1", "0", "yes", "", " ", "tRuE", "İ"}
	intPool  = []string{"", "0", "1", "-1", "+5", " 7 ", "1_0", "1__0", "٣", "0x10", "4", "5", "8", "10", "12", "59", "60", "64", "65", "128", "252", "253", "256", "300", "900", "901", "4096", "65536", "262144", "524288", "1048576", "4194304", "33554432", "999999999999999999999999", "007"}
	strPool  = []string{"", " ", "x", "a,b", " a , ,b ", "*", " *", "https://ssh.example.com", "https://a.example,http://b.example:8080", "<YOUR-DOMAIN>", "YOUR-ORIGIN", "/webssh/", "webssh", "//x", "session", "remember_token", "my.cookie-1", "bad cookie", "café", "10.0.0.0/8", "192.168.1.0/24,fd00::/8", "8.8.8.8", "10.0.0.1/8", "host.example", "Host.Example.", "1.2.3.4", "a..b", "-bad", "ldap://dir.example", "ldaps://dir.example:636", "ldap://u@dir.example", "ldap://dir.example/x", "localhost", "example.com", "https://localhost", "http://localhost", "https://sub.example.com", "https://example.com/path", "changeme", "Change Me", "short", strings.Repeat("k", 40), "(uid={username})", "uid={username}{x}", "entryUUID", "1.2.3", "/run/x", "relative", "homelab", "HomeLab ", "prod", "memory://", "redis://x", "fd00::1%a", "[::1]:22", "tail.example:22", "İ", "ΑΣ", "https://[::1]", "https://[1.2.3.4]"}
)

// scenarios switch on features whose validation is deep, so random
// mutations reach it.
var scenarios = []map[string]string{
	{},
	{"LDAP_ENABLED": "true", "LDAP_URL": "ldaps://dir.example", "LDAP_BASE_DN": "dc=example", "LDAP_BIND_DN": "cn=svc", "LDAP_USER_FILTER": "(uid={username})", "LDAP_UNIQUE_ID_ATTRIBUTE": "entryUUID"},
	{"OIDC_ENABLED": "true", "OIDC_ISSUER": "https://idp.example/realm/", "OIDC_REDIRECT_URI": "https://ssh.example/oidc/callback"},
	{"WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "https://ssh.example.com", "WEBAUTHN_RP_ID": "example.com"},
	{"SMB_ENABLED": "true", "SMB_ALLOWED_TARGETS": "nas.example,10.0.0.5"},
	{"TAILSCALE_SSH_ENABLED": "true", "TAILSCALE_SSH_ALLOWED_TARGETS": "host.example:22,[fd7a::1]"},
	{"CORS_ORIGINS": "*", "ALLOW_CORS_WILDCARD": "true"},
	{"DEBUG": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com,https://b.example", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "0", "SESSION_COOKIE_SECURE": "true"},
}

// fixedEnvCases pin the behaviour named in the plan and in config.py.
var fixedEnvCases = []map[string]string{
	{"STEP_UP_MAX_AGE_SECONDS": ""},
	{"STEP_UP_MAX_AGE_SECONDS": "1_000"},
	{"STEP_UP_MAX_AGE_SECONDS": " 300 "},
	{"ADMIN_PANEL_ENABLED": " true"},
	{"ADMIN_PANEL_ENABLED": ""},
	{"TMUX_ENABLED": ""},
	{"TMUX_ENABLED": " FALSE "},
	{"TMUX_SESSION_PREFIX": " my.prefix:x "},
	{"TMUX_SESSION_PREFIX": strings.Repeat("é", 90)},
	{"SECRET_KEY": ""},
	{"SECRET_KEY": " changeme "},
	{"SECRET_KEY": " changeme"},
	{"SECRET_KEY": "short"},
	{"SECRET_KEY": "", "DEBUG": "true"},
	{"CORS_ORIGINS": "*"},
	{"CORS_ORIGINS": "*", "DEBUG": "True"},
	{"CORS_ORIGINS": " *"},
	{"CORS_ORIGINS": "https://a.example, ,https://b.example"},
	{"CORS_ORIGINS": " <YOUR-DOMAIN> "},
	{"SESSION_COOKIE_NAME": "remember_token"},
	{"SESSION_COOKIE_NAME": "a b"},
	{"SESSION_COOKIE_SECURE": "yes"},
	{"SESSION_COOKIE_SECURE": "FALSE"},
	{"TRUSTED_PROXIES": "-1"},
	{"TRUSTED_PROXIES": "2"},
	{"MAX_SOCKET_CONNECTIONS": "61"},
	{"MAX_SOCKET_CONNECTIONS": "60"},
	{"MAX_SOCKET_CONNECTIONS_PER_USER": "49"},
	{"GUNICORN_THREADS": "8", "MAX_SOCKET_CONNECTIONS": "4", "MAX_SOCKET_CONNECTIONS_PER_USER": "4"},
	{"QUOTA_SSH_SESSION_PER_USER": "10"},
	{"QUOTA_TEMP_BYTES_PER_USER": "1073741824"},
	{"QUOTA_SSH_SESSION_GLOBAL": "200"},
	{"QUOTA_SSH_SESSION_GLOBAL": "999999999999999999999999", "QUOTA_SSH_SESSION_PER_USER": "5"},
	{"BACKGROUND_WORKERS": "3"},
	{"BACKGROUND_WORKERS": "129"},
	{"RUNTIME_SHUTDOWN_GRACE_SECONDS": "31"},
	{"MAX_EDITOR_FILE_SIZE": "999999999999999999999999"},
	{"MAX_WEBAUTHN_JSON_SIZE": "100000"},
	{"MAX_DOWNLOAD_SIZE": "-5"},
	{"SSH_INPUT_MAX_BYTES": "262144", "SSH_INPUT_SESSION_BURST_BYTES": "131072"},
	{"SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET": "4096"},
	{"SSH_ALLOWED_INTERNAL_NETWORKS": "10.0.0.0/8, 192.168.0.0/255.255.0.0,fd00::/8"},
	{"SSH_ALLOWED_INTERNAL_NETWORKS": "127.0.0.0/8"},
	{"SSH_ALLOWED_INTERNAL_NETWORKS": "10.0.0.1/8"},
	{"BLOCK_INTERNAL_SSH": "true", "SSH_ALLOWED_INTERNAL_NETWORKS": "10.1.0.0/16"},
	{"SOCKS_REMOTE_DNS_ALLOWLIST": "Bastion.Example., bastion.example"},
	{"SOCKS_REMOTE_DNS_ALLOWLIST": "10.0.0.1"},
	{"SOCKS_REMOTE_DNS_ALLOWLIST": "*.example"},
	{"PROXY_JUMP_REMOTE_DNS_ALLOWLIST": " a , b ,a"},
	{"APPLICATION_ROOT": "/webssh///"},
	{"APPLICATION_ROOT": "///"},
	{"ADMIN_USERS": " alice, ,bob ,alice"},
	{"DEPLOYMENT_PROFILE": " HomeLab "},
	{"DEPLOYMENT_PROFILE": "PRODUCTİON"},
	{"DEPLOYMENT_PROFILE": "staging"},
	{"DEPLOYMENT_PROFILE": "production"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "DEBUG": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "REGISTRATION_ENABLED": "true", "BOOTSTRAP_REGISTRATION_ENABLED": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "SESSION_COOKIE_SECURE": "false", "ALLOW_CORS_WILDCARD": "true", "SOCKETIO_ALLOW_ANY_ORIGIN": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "http://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://u@ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com/", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com, ", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "*", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "false", "TRUSTED_PROXIES": "1"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "TAILSCALE_SSH_ENABLED": "true"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "TAILSCALE_SSH_ENABLED": "true", "TAILSCALE_SSH_ALLOWED_TARGETS": "bad host", "TAILSCALE_SSH_INTERFACE": ""},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "TAILSCALE_SSH_ENABLED": "true", "TAILSCALE_SSH_ALLOWED_TARGETS": "host.example:22"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "http://localhost", "WEBAUTHN_RP_ID": "localhost"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "OIDC_ENABLED": "true", "OIDC_ISSUER": "https://idp.example", "OIDC_REDIRECT_URI": "http://localhost/oidc/callback"},
	{"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "HOST_DISCOVERY_ENABLED": "true", "SECRET_KEY": "short"},
	{"HOST_DISCOVERY_ENABLED": " "},
	{"HOST_DISCOVERY_ENABLED": "", "DEPLOYMENT_PROFILE": "production"},
	{"REGISTRATION_ENABLED": "true", "BOOTSTRAP_REGISTRATION_ENABLED": "false"},
	{"WEBAUTHN_ENABLED": "true"},
	{"WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "http://localhost", "WEBAUTHN_RP_ID": "localhost"},
	{"WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "https://ssh.example.com", "WEBAUTHN_RP_ID": "other.com"},
	{"WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "https://10.0.0.1", "WEBAUTHN_RP_ID": "10.0.0.1"},
	{"WEBAUTHN_ENABLED": "true", "WEBAUTHN_ORIGIN": "https://[::1", "WEBAUTHN_RP_ID": "x"},
	{"SMB_ENABLED": "true"},
	{"SMB_ALLOWED_TARGETS": "nas:445"},
	{"SMB_CONNECT_TIMEOUT_SECONDS": "61"},
	{"TAILSCALE_SSH_ENABLED": "true"},
	{"TAILSCALE_SSH_ENABLED": "true", "TAILSCALE_SSH_ALLOWED_TARGETS": "bad host", "TAILSCALE_SSH_INTERFACE": " "},
	{"DATA_DIR": "/srv/webssh//data/"},
	{"TRANSFER_TEMP_DIR": "relative/tmp"},
	{"BACKUP_TEMP_DIR": "/app/recovery"},
	{"TMPDIR": "/var/tmp/"},
}

func vectorEnvs(n int) []map[string]string {
	r := rand.New(rand.NewPCG(11, 26))
	names := slices.Sorted(maps.Keys(variables))
	var out []map[string]string
	add := func(extra map[string]string) {
		env := baseEnv()
		maps.Copy(env, extra)
		out = append(out, env)
	}
	for _, s := range scenarios {
		add(s)
	}
	for _, f := range fixedEnvCases {
		add(f)
	}
	for range n {
		env := maps.Clone(scenarios[r.IntN(len(scenarios))])
		for range 1 + r.IntN(4) {
			name := names[r.IntN(len(names))]
			if variables[name] == internal || name == "TRUSTED_PROXY_CIDRS" || name == "PYTHON_DOTENV_DISABLED" {
				continue
			}
			pool := strPool
			switch {
			case strings.HasSuffix(name, "_ENABLED") || strings.HasPrefix(name, "ALLOW") || name == "DEBUG" || strings.HasSuffix(name, "_SSH") || strings.HasSuffix(name, "_ORIGIN") && name == "SOCKETIO_ALLOW_ANY_ORIGIN":
				pool = boolPool
			case r.IntN(3) > 0 && looksNumeric(name):
				pool = intPool
			}
			env[name] = pool[r.IntN(len(pool))]
		}
		add(env)
	}
	return out
}

func looksNumeric(name string) bool {
	for _, s := range []string{"MAX", "TIMEOUT", "SECONDS", "QUOTA", "BYTES", "RECORDS", "COUNT", "SIZE", "TTL", "WORKERS", "THREADS", "CONNECTIONS", "STEPS", "ENTRIES", "PROXIES", "RATIO", "MEMBERS", "LINES", "PORT"} {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

// pythonOnlyErrors are messages of the Python release that Go words
// differently: urlsplit raises a ValueError without a configuration prefix.
func exactPythonError(a pythonAnswer) bool {
	return strings.HasPrefix(a.Error, "CONFIGURATION ERROR") || strings.HasPrefix(a.Error, "SECURITY ERROR") || strings.Contains(a.Error, "COOKIE_NAME")
}

func lookupMap(env map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

// compareEnv checks one environment against the Python answer.
func compareEnv(t *testing.T, env map[string]string, py pythonAnswer) bool {
	t.Helper()
	c, warns, view, err := load(lookupMap(env))
	fail := func(format string, args ...any) bool {
		t.Errorf("env %q: "+format, append([]any{env}, args...)...)
		return false
	}
	if py.Error != "" {
		if err == nil {
			return fail("Python fails with %q, Go starts", py.Error)
		}
		if exactPythonError(py) && err.Error() != py.Error {
			return fail("Go error %q, Python %q", err, py.Error)
		}
		return true
	}
	if err != nil {
		return fail("Go fails with %q, Python starts", err)
	}
	for key, want := range py.View {
		got, ok := view[key]
		if !ok {
			return fail("Go has no value for %s", key)
		}
		if canonicalJSON(got) != canonicalJSON(want) {
			return fail("%s: Go %s, Python %s", key, canonicalJSON(got), canonicalJSON(want))
		}
	}
	for key := range view {
		if _, ok := py.View[key]; !ok {
			return fail("Go reports %s, Python has no such constant", key)
		}
	}
	var printed, security []string
	for _, w := range warns {
		switch w.Kind {
		case WarnPython:
			printed = append(printed, "WARNING: "+w.Message)
		case WarnInfo:
			printed = append(printed, "INFO: "+w.Message)
		case WarnSecurity:
			security = append(security, w.Message)
		}
	}
	slices.Sort(printed)
	pyPrinted := slices.Sorted(slices.Values(py.Printed))
	if canonicalJSON(nonNil(printed)) != canonicalJSON(nonNil(pyPrinted)) {
		return fail("printed: Go %q, Python %q", printed, py.Printed)
	}
	if canonicalJSON(nonNil(security)) != canonicalJSON(nonNil(py.SecurityWarnings)) {
		return fail("security warnings: Go %q, Python %q", security, py.SecurityWarnings)
	}
	var explicit []string
	for _, name := range py.Explicit {
		if _, known := variables[name]; known {
			explicit = append(explicit, name)
		}
	}
	gotExplicit := slices.Sorted(maps.Keys(c.explicit))
	if canonicalJSON(nonNil(gotExplicit)) != canonicalJSON(nonNil(explicit)) {
		return fail("explicit: Go %q, Python %q", gotExplicit, explicit)
	}
	if c.SecretSource != SecretEphemeral && string(c.SecretKey.value) != py.SecretKey {
		return fail("SECRET_KEY differs")
	}
	return true
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

const envVectorFile = "python_env.jsonl"

// TestPythonEnvVectors loads every checked-in environment with Go and
// compares values, errors and warnings with config.py.
func TestPythonEnvVectors(t *testing.T) {
	if *update {
		o := requireOracle(t)
		var def pythonAnswer
		o.ask(t, map[string]any{"env": baseEnv()}, &def)
		cases := []envCase{{Env: baseEnv(), Python: def}}
		for _, env := range vectorEnvs(700) {
			var a pythonAnswer
			o.ask(t, map[string]any{"env": env}, &a)
			for k, v := range a.View {
				if canonicalJSON(v) == canonicalJSON(def.View[k]) {
					delete(a.View, k)
				}
			}
			cases = append(cases, envCase{Env: env, Python: a})
		}
		writeJSONLines(t, envVectorFile, cases)
	}
	cases := readJSONLines[envCase](t, envVectorFile)
	if len(cases) < 500 {
		t.Fatalf("only %d vectors", len(cases))
	}
	def := cases[0].Python.View
	failures := 0
	for _, c := range cases {
		if c.Python.Error == "" {
			full := maps.Clone(def)
			maps.Copy(full, c.Python.View)
			c.Python.View = full
		}
		if !compareEnv(t, c.Env, c.Python) {
			if failures++; failures > 20 {
				t.Fatal("too many mismatches")
			}
		}
	}
}

// TestPythonEnvLive compares many more random environments with the
// oracle.
func TestPythonEnvLive(t *testing.T) {
	if testing.Short() {
		t.Skip("long differential run")
	}
	o := requireOracle(t)
	failures := 0
	for _, env := range vectorEnvs(4000) {
		var a pythonAnswer
		o.ask(t, map[string]any{"env": env}, &a)
		if !compareEnv(t, env, a) {
			if failures++; failures > 20 {
				t.Fatal("too many mismatches")
			}
		}
	}
}
