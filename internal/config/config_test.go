package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustLoad(t *testing.T, extra map[string]string) (Config, []Warning) {
	t.Helper()
	env := baseEnv()
	maps.Copy(env, extra)
	c, warns, err := Load(lookupMap(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c, warns
}

func loadErr(t *testing.T, extra map[string]string) *Error {
	t.Helper()
	env := baseEnv()
	maps.Copy(env, extra)
	_, _, err := Load(lookupMap(env))
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("Load error %v, want *Error", err)
	}
	return ce
}

// warningFor reports a warning of kind about variable; an empty kind or
// variable matches any.
func warningFor(warns []Warning, kind WarningKind, variable string) bool {
	for _, w := range warns {
		if (kind == "" || w.Kind == kind) && (variable == "" || w.Variable == variable) {
			return true
		}
	}
	return false
}

func hasWarning(warns []Warning, kind WarningKind, variable, fragment string) bool {
	for _, w := range warns {
		if w.Kind == kind && w.Variable == variable && strings.Contains(w.Message, fragment) {
			return true
		}
	}
	return false
}

func TestDefaults(t *testing.T) {
	c, _ := mustLoad(t, nil)
	if c.Profile != ProfileHomelab || c.Debug || c.DataDir != "/app/data" {
		t.Errorf("profile %q debug %v data %q", c.Profile, c.Debug, c.DataDir)
	}
	if !c.Cookies.Secure || c.Cookies.SessionName != "session" || c.Cookies.RememberName != "remember_token" {
		t.Errorf("cookies %+v", c.Cookies)
	}
	if c.StepUpMaxAge != 5*time.Minute || c.Terminal.SessionTimeout != 30*time.Minute || c.Terminal.Output.AckTimeout != 10*time.Second {
		t.Errorf("durations %v %v %v", c.StepUpMaxAge, c.Terminal.SessionTimeout, c.Terminal.Output.AckTimeout)
	}
	if c.Accounts.RegistrationEnabled || !c.Accounts.BootstrapRegistrationEnabled || !c.Accounts.AdminPanelEnabled {
		t.Errorf("accounts %+v", c.Accounts)
	}
	if c.Terminal.MaxConnections != 48 || c.Terminal.MaxConnectionsPerUser != 8 || c.Terminal.Input.MaxBytes != 128<<10 {
		t.Errorf("terminal %+v", c.Terminal)
	}
	if c.Features.Tmux != (Switch{Value: true}) || c.Features.TmuxSessionPrefix != "webssh" {
		t.Errorf("tmux %+v", c.Features)
	}
	if c.Listen != (Listen{Host: "127.0.0.1", Port: 5000}) || c.SecretSource != SecretFromFile {
		t.Errorf("listen %+v source %q", c.Listen, c.SecretSource)
	}
	if c.RateLimits.Login != "5 per minute" || c.RateLimits.SSHConnect != "10 per minute" {
		t.Errorf("rate limits %+v", c.RateLimits)
	}
}

func TestProductionProfile(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{
		"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com",
		"BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1", "TRUSTED_PROXY_CIDRS": "172.31.250.10",
	})
	if c.Profile != ProfileProduction || c.Features.HostDiscovery || c.Accounts.BootstrapRegistrationEnabled || !c.Cookies.Secure {
		t.Errorf("production values %+v %+v", c.Features, c.Accounts)
	}
	for _, w := range warns {
		if w.Kind == WarnSecurity || w.Kind == WarnProxy {
			t.Errorf("unexpected warning %v", w)
		}
	}
	// An unsafe production configuration keeps the Python message.
	e := loadErr(t, map[string]string{"DEPLOYMENT_PROFILE": "production"})
	if !strings.HasPrefix(e.Message, "SECURITY ERROR: unsafe production profile: ") || e.Variable != "DEPLOYMENT_PROFILE" {
		t.Errorf("error %+v", e)
	}
	for name, value := range map[string]string{
		"DEBUG": "true", "CORS_ORIGINS": "http://ssh.example.com", "ALLOW_CORS_WILDCARD": "true",
		"SOCKETIO_ALLOW_ANY_ORIGIN": "true", "SESSION_COOKIE_SECURE": "false", "REGISTRATION_ENABLED": "true",
		"BOOTSTRAP_REGISTRATION_ENABLED": "true", "BLOCK_INTERNAL_SSH": "false", "TAILSCALE_SSH_ENABLED": "true",
	} {
		env := map[string]string{
			"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com",
			"BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "0",
		}
		env[name] = value
		if e := loadErr(t, env); !strings.HasPrefix(e.Message, "SECURITY ERROR: ") {
			t.Errorf("%s=%s: %+v", name, value, e)
		}
	}
}

// Condition H1: in production TRUSTED_PROXIES without TRUSTED_PROXY_CIDRS
// is reported as a missing required setting.
func TestProductionProxyCIDRs(t *testing.T) {
	env := map[string]string{
		"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com",
		"BLOCK_INTERNAL_SSH": "true", "TRUSTED_PROXIES": "1",
	}
	_, warns := mustLoad(t, env)
	if !hasWarning(warns, WarnProxy, "TRUSTED_PROXY_CIDRS", "required beside TRUSTED_PROXIES in the production profile") {
		t.Errorf("no H1 warning: %v", warns)
	}
	env["TRUSTED_PROXIES"] = "0"
	if _, warns = mustLoad(t, env); warningFor(warns, WarnProxy, "") {
		t.Errorf("warning without proxies: %v", warns)
	}
}

func TestTrustedProxyCIDRs(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{"TRUSTED_PROXIES": "1", "TRUSTED_PROXY_CIDRS": " 10.0.0.0/8, 192.0.2.7 ,10.0.0.0/8,2001:db8::/32,"})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("2001:db8::/32")}
	if fmt.Sprint(c.Proxies.CIDRs) != fmt.Sprint(want) {
		t.Errorf("CIDRs %v, want %v", c.Proxies.CIDRs, want)
	}
	if hasWarning(warns, WarnProxy, "TRUSTED_PROXIES", "") {
		t.Error("hop warning despite CIDRs")
	}
	for _, bad := range []string{"10.0.0.1/8", "fe80::1%eth0", "example.com", "10.0.0.0/33", "*"} {
		if e := loadErr(t, map[string]string{"TRUSTED_PROXY_CIDRS": bad}); e.Variable != "TRUSTED_PROXY_CIDRS" {
			t.Errorf("%q: %+v", bad, e)
		}
	}
	_, warns = mustLoad(t, map[string]string{"TRUSTED_PROXIES": "2"})
	if !hasWarning(warns, WarnProxy, "TRUSTED_PROXIES", "TRUSTED_PROXY_CIDRS") {
		t.Errorf("no D-19 warning: %v", warns)
	}
	_, warns = mustLoad(t, map[string]string{"TRUSTED_PROXY_CIDRS": "10.0.0.0/8"})
	if !hasWarning(warns, WarnProxy, "TRUSTED_PROXY_CIDRS", "no effect") {
		t.Errorf("no warning for CIDRs without hops: %v", warns)
	}
}

func TestOriginWarnings(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{"CORS_ORIGINS": "*", "ALLOW_CORS_WILDCARD": "true"})
	if !c.Origins.AllowAny || len(c.Origins.List) != 0 || !hasWarning(warns, WarnOrigin, "CORS_ORIGINS", "only from the address") {
		t.Errorf("origins %+v warns %v", c.Origins, warns)
	}
	_, warns = mustLoad(t, map[string]string{"CORS_ORIGINS": "*", "ALLOW_CORS_WILDCARD": "true", "SOCKETIO_ALLOW_ANY_ORIGIN": "true"})
	if !hasWarning(warns, WarnOrigin, "SOCKETIO_ALLOW_ANY_ORIGIN", "any web page") {
		t.Errorf("warns %v", warns)
	}
	c, warns = mustLoad(t, map[string]string{"CORS_ORIGINS": " *"})
	if c.Origins.AllowAny || len(c.Origins.List) != 1 || !hasWarning(warns, WarnQuirk, "CORS_ORIGINS", "not the wildcard") {
		t.Errorf("origins %+v warns %v", c.Origins, warns)
	}
}

func TestQuirkWarnings(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{"ADMIN_PANEL_ENABLED": " true", "STEP_UP_MAX_AGE_SECONDS": "1_0_0", "SESSION_COOKIE_SECURE": "yes", "TMUX_DEFAULT": "on"})
	if c.Accounts.AdminPanelEnabled || c.StepUpMaxAge != 100*time.Second || !c.Cookies.Secure || c.Features.TmuxDefault != (Switch{Locked: true}) {
		t.Errorf("values %+v %v %+v %+v", c.Accounts, c.StepUpMaxAge, c.Cookies, c.Features.TmuxDefault)
	}
	for _, v := range []string{"ADMIN_PANEL_ENABLED", "STEP_UP_MAX_AGE_SECONDS", "SESSION_COOKIE_SECURE", "TMUX_DEFAULT"} {
		if !hasWarning(warns, WarnQuirk, v, "") {
			t.Errorf("no quirk warning for %s: %v", v, warns)
		}
	}
	_, warns = mustLoad(t, map[string]string{"ADMIN_PANEL_ENABLED": "TRUE", "STEP_UP_MAX_AGE_SECONDS": "100"})
	for _, w := range warns {
		if w.Kind == WarnQuirk {
			t.Errorf("unexpected %v", w)
		}
	}
}

func TestUsageWarnings(t *testing.T) {
	_, warns := mustLoad(t, map[string]string{
		"HOST_DISCOVERY_ENABLED": "true", "OIDC_ENABLED": "false", "GUNICORN_THREADS": "64", "RATELIMIT_STORAGE_URL": "redis://cache:6379/0",
		"SMB_ENABLED": " ", "TRANSFER_TEMP_DIR": "/srv/tmp", "BACKUP_RECOVERY_DURABLE": "false", "SERVER_OPERATIONS_ENABLED": "true",
	})
	for name, fragment := range map[string]string{
		"GUNICORN_THREADS": "no meaning", "RATELIMIT_STORAGE_URL": "restart",
		"TRANSFER_TEMP_DIR": "streams folder downloads", "BACKUP_RECOVERY_DURABLE": "no longer needed",
	} {
		if !hasWarning(warns, WarnObsolete, name, fragment) {
			t.Errorf("%s not reported: %v", name, warns)
		}
	}
	for _, name := range []string{"HOST_DISCOVERY_ENABLED", "OIDC_ENABLED", "SMB_ENABLED", "SERVER_OPERATIONS_ENABLED"} {
		if warningFor(warns, WarnObsolete, name) {
			t.Errorf("used variable %s reported: %v", name, warns)
		}
	}
	_, warns = mustLoad(t, map[string]string{"RATELIMIT_STORAGE_URL": "memory://", "BACKUP_RECOVERY_DURABLE": "true"})
	if warningFor(warns, WarnObsolete, "") {
		t.Errorf("default values reported: %v", warns)
	}
}

// Every variable is either acted on or obsolete; there is no category of
// accepted variables without effect.
func TestEveryVariableHasEffect(t *testing.T) {
	for name, u := range variables {
		if u != used && u != obsolete && u != internal {
			t.Errorf("%s has usage %d", name, u)
		}
	}
	for _, name := range []string{"SMB_ENABLED", "TAILSCALE_SSH_ENABLED", "HOST_DISCOVERY_ENABLED", "SERVER_OPERATIONS_ENABLED",
		"QUOTA_TRANSFER_GLOBAL", "FILE_CONTROL_MAX_PATH_BYTES", "AUDIT_LOG_MAX_BYTES", "SMB_MAX_SAVED_SHARES", "PYTHON_DOTENV_DISABLED"} {
		if variables[name] != used {
			t.Errorf("%s is not used", name)
		}
	}
}

// The registry knows every variable config.py of the Python release names
// (testdata/python_config_names.txt, recorded from its source).
func TestRegistryCoversConfigPy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "python_config_names.txt"))
	if err != nil {
		t.Fatal(err)
	}
	quotaKinds := map[string]bool{"SSH_SESSION": true, "QUICK_CONNECTION": true, "TRANSFER": true, "TEMP_BYTES": true, "BACKGROUND_JOB": true}
	valid := regexp.MustCompile(`^[A-Z][A-Z0-9_]{3,}$`)
	var names []string
	for line := range strings.Lines(string(raw)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !valid.MatchString(line) {
			t.Fatalf("python_config_names.txt: %q is not a variable name", line)
		}
		names = append(names, line)
	}
	if len(names) < 150 {
		t.Fatalf("only %d names recorded from config.py", len(names))
	}
	for _, name := range names {
		if _, ok := variables[name]; !ok && !quotaKinds[name] {
			t.Errorf("config.py names %s, the registry does not", name)
		}
	}
}

func TestFilePathLimit(t *testing.T) {
	for raw, want := range map[string]int{"4096": 4096, "512": 512, "2048": 2048, "16384": 4096} {
		c, _ := mustLoad(t, map[string]string{"FILE_CONTROL_MAX_PATH_BYTES": raw})
		if c.Files.MaxPathBytes != want {
			t.Errorf("%q: %d, want %d", raw, c.Files.MaxPathBytes, want)
		}
	}
}

func TestExplicit(t *testing.T) {
	c, _ := mustLoad(t, map[string]string{"TMUX_ENABLED": "false", "AUTOMATION_ENABLED": "  "})
	if !c.Explicit("TMUX_ENABLED") || c.Explicit("AUTOMATION_ENABLED") || c.Explicit("UNKNOWN") {
		t.Error("explicit keys wrong")
	}
}

// Python converts the entries with IDNA 2003 (xn--caf-dma is
// 'café.example'.encode('idna')).
func TestSOCKSInternationalizedName(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{"SOCKS_REMOTE_DNS_ALLOWLIST": "bastion.example,Caf\u00e9.example"})
	if fmt.Sprint(c.Network.SOCKSRemoteDNS) != "[bastion.example xn--caf-dma.example]" || warningFor(warns, "", "SOCKS_REMOTE_DNS_ALLOWLIST") {
		t.Errorf("names %v warns %v", c.Network.SOCKSRemoteDNS, warns)
	}
}

func TestListen(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{"HOST": "0.0.0.0", "PORT": "abc"})
	if c.Listen != (Listen{Host: "0.0.0.0", Port: 5000}) || !hasWarning(warns, WarnQuirk, "PORT", "5000") {
		t.Errorf("listen %+v warns %v", c.Listen, warns)
	}
	c, _ = mustLoad(t, map[string]string{"PORT": " 8080 "})
	if c.Listen.Port != 8080 {
		t.Errorf("port %d", c.Listen.Port)
	}
}

func TestTimeZoneWarning(t *testing.T) {
	load := func(name string) error {
		if name == "Europe/Berlin" || name == "/etc/localtime" {
			return nil
		}
		return errors.New("unknown")
	}
	for tz, want := range map[string]string{
		"Europe/Berlin": "", ":Europe/Berlin": "", "UTC": "", "": "", "/etc/localtime": "",
		"Mars/Base": "cannot be loaded", "CET-1CEST,M3.5.0,M10.5.0/3": "POSIX",
	} {
		w, ok := timeZoneWarning(lookupMap(map[string]string{"TZ": tz}), load)
		if ok != (want != "") || ok && !strings.Contains(w.Message, want) {
			t.Errorf("TZ=%q: %v %v", tz, w, ok)
		}
	}
	if _, ok := timeZoneWarning(lookupMap(nil), load); ok {
		t.Error("warning without TZ")
	}
	if err := loadZone("UTC"); err != nil {
		t.Errorf("loadZone(UTC): %v", err)
	}
}

func TestSecretRedaction(t *testing.T) {
	c, _ := mustLoad(t, nil)
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "secret", c.SecretKey, "config", c)
	js, _ := json.Marshal(c)
	for _, out := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), logs.String(), string(js), c.SecretKey.String()} {
		if strings.Contains(out, testSecret) {
			t.Errorf("secret leaked: %s", out)
		}
	}
	if string(c.SecretKey.Bytes()) != testSecret {
		t.Error("Bytes lost the secret")
	}
}

func TestDebugEphemeralSecret(t *testing.T) {
	restore := randomSecret
	t.Cleanup(func() { randomSecret = restore })
	randomSecret = func() (string, error) { return strings.Repeat("ab", 32), nil }
	c, warns := mustLoad(t, map[string]string{"SECRET_KEY": "", "DEBUG": "true"})
	if c.SecretSource != SecretEphemeral || string(c.SecretKey.Bytes()) != strings.Repeat("ab", 32) || !hasWarning(warns, WarnPython, "SECRET_KEY", "DEBUG MODE") {
		t.Errorf("source %q warns %v", c.SecretSource, warns)
	}
	randomSecret = func() (string, error) { return "", errors.New("no entropy") }
	if _, _, err := Load(lookupMap(map[string]string{"DEBUG": "true"})); err == nil {
		t.Error("entropy failure ignored")
	}
}

func TestBootstrap(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	var prepared string
	prepare := func(dir string) error { prepared = dir; return os.MkdirAll(dir, 0o700) }
	c, warns, err := Bootstrap(lookupMap(map[string]string{"DATA_DIR": dataDir}), prepare)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != dataDir || c.DataDir != dataDir || c.SecretSource != SecretFromFile || !hexSecret.Match(c.SecretKey.Bytes()) {
		t.Errorf("config %q %q %q", prepared, c.DataDir, c.SecretSource)
	}
	if !hasWarning(warns, WarnSecret, "", "Generated a new SECRET_KEY") {
		t.Errorf("warns %v", warns)
	}
	// The second start reads the same secret.
	c2, _, err := Bootstrap(lookupMap(map[string]string{"DATA_DIR": dataDir}), prepare)
	if err != nil || !bytes.Equal(c2.SecretKey.Bytes(), c.SecretKey.Bytes()) {
		t.Fatalf("second start: %v", err)
	}
	c3, _, err := Bootstrap(lookupMap(map[string]string{"DATA_DIR": dataDir, "SECRET_KEY": testSecret}), prepare)
	if err != nil || c3.SecretSource != SecretFromEnvironment || string(c3.SecretKey.Bytes()) != testSecret {
		t.Fatalf("environment secret: %v %q", err, c3.SecretSource)
	}
	// An empty secret file stops the start, as config.py does.
	empty := filepath.Join(root, "empty")
	writeFile(t, filepath.Join(empty, "secret_key"), "\n", 0o600)
	if _, _, err := Bootstrap(lookupMap(map[string]string{"DATA_DIR": empty}), prepare); err == nil || !strings.Contains(err.Error(), "SECRET_KEY environment variable is required") {
		t.Errorf("empty secret file: %v", err)
	}
	if _, _, err := Bootstrap(lookupMap(map[string]string{"DATA_DIR": dataDir}), func(string) error { return errors.New("not writable") }); err == nil {
		t.Error("prepare error ignored")
	}
}

// BootstrapReadOnly reads an existing secret but never writes one: a
// directory without SECRET_KEY and secret_key is refused and stays empty.
func TestBootstrapReadOnly(t *testing.T) {
	dir := t.TempDir()
	check := func(string) error { return nil }
	_, _, err := BootstrapReadOnly(lookupMap(map[string]string{"DATA_DIR": dir}), check)
	if err == nil || !strings.Contains(err.Error(), "neither SECRET_KEY nor") {
		t.Fatalf("missing secret: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the read-only bootstrap wrote %v", entries)
	}
	writeFile(t, filepath.Join(dir, "secret_key"), testSecret+"\n", 0o600)
	c, _, err := BootstrapReadOnly(lookupMap(map[string]string{"DATA_DIR": dir}), check)
	if err != nil || c.SecretSource != SecretFromFile || string(c.SecretKey.Bytes()) != testSecret {
		t.Fatalf("file secret: %v %q", err, c.SecretSource)
	}
	if _, _, err := BootstrapReadOnly(lookupMap(map[string]string{"DATA_DIR": dir}), func(string) error { return errors.New("missing") }); err == nil {
		t.Error("check error ignored")
	}
}

func TestSecretGeneratedBesideExistingData(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.db"), "", 0o600)
	_, warns, err := ResolveSecretKey(dir, lookupMap(nil))
	if err != nil || !hasWarning(warns, WarnSecret, "SECRET_KEY", "cannot be read") {
		t.Errorf("err %v warns %v", err, warns)
	}
}

func TestSecretFileNeverFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	symlink(t, target, filepath.Join(dir, "secret_key"))
	if _, _, err := ResolveSecretKey(dir, lookupMap(nil)); err == nil {
		t.Fatal("wrote through a dangling link")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("link target created: %v", err)
	}
}

func TestSecretFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secret_key"), strings.Repeat("k", maxExportedSecret+1), 0o600)
	if _, _, err := ResolveSecretKey(dir, lookupMap(nil)); err == nil {
		t.Error("oversized secret accepted")
	}
	writeFile(t, filepath.Join(dir, "secret_key"), strings.Repeat("k", maxExportedSecret)+"\n", 0o600)
	if _, _, err := ResolveSecretKey(dir, lookupMap(nil)); err != nil {
		t.Errorf("largest secret refused: %v", err)
	}
}

func TestPlaceholderSecretWarning(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secret_key"), "k\n", 0o600)
	res, warns, err := ResolveSecretKey(dir, lookupMap(map[string]string{"SECRET_KEY": "Change Me"}))
	if err != nil || res.Source != SecretFromFile || !hasWarning(warns, WarnSecret, "SECRET_KEY", "placeholder") {
		t.Errorf("res %+v warns %v err %v", res, warns, err)
	}
	if strings.Contains(fmt.Sprint(warns), "Change Me") {
		t.Error("warning repeats the secret value")
	}
}

func selfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCABundle(t *testing.T) {
	dir := t.TempDir()
	cert := selfSigned(t)
	writeFile(t, filepath.Join(dir, "ca.pem"), string(cert), 0o600)
	writeFile(t, filepath.Join(dir, "certs", "a.0"), string(cert), 0o600)
	writeFile(t, filepath.Join(dir, "bad.pem"), "not a certificate", 0o600)

	c, warns := mustLoad(t, map[string]string{"REQUESTS_CA_BUNDLE": "", "CURL_CA_BUNDLE": filepath.Join(dir, "ca.pem")})
	if c.CABundle.Variable != "CURL_CA_BUNDLE" || warningFor(warns, "", "CURL_CA_BUNDLE") {
		t.Errorf("bundle %+v", c.CABundle)
	}
	block, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "certs")} {
		pool, err := CABundle{Path: path, Variable: "REQUESTS_CA_BUNDLE"}.CertPool()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			t.Errorf("%s: certificate not trusted: %v", path, err)
		}
	}
	for _, path := range []string{filepath.Join(dir, "bad.pem"), filepath.Join(dir, "missing.pem")} {
		if _, err := (CABundle{Path: path, Variable: "REQUESTS_CA_BUNDLE"}).CertPool(); err == nil {
			t.Errorf("%s accepted", path)
		}
	}
	if pool, err := (CABundle{}).CertPool(); err != nil || pool == nil {
		t.Errorf("system pool: %v", err)
	}
}

func TestErrorAndWarningText(t *testing.T) {
	e := &Error{Variable: "X", Message: "m"}
	if e.Error() != "m" {
		t.Error(e.Error())
	}
	if s := (Warning{Kind: WarnQuirk, Variable: "X", Message: "m"}).String(); s != "quirk: X: m" {
		t.Error(s)
	}
	if s := (Warning{Kind: WarnSecret, Message: "m"}).String(); s != "secret: m" {
		t.Error(s)
	}
}

func TestBackupTempDir(t *testing.T) {
	t.Parallel()
	c, _ := mustLoad(t, map[string]string{"BACKUP_TEMP_DIR": "/app/recovery//ops/"})
	if c.BackupTempDir != "/app/recovery/ops" {
		t.Errorf("BackupTempDir = %q", c.BackupTempDir)
	}
	c, _ = mustLoad(t, map[string]string{"TMPDIR": "/var/tmp"})
	if c.BackupTempDir != "/var/tmp/webssh-backup-operations" {
		t.Errorf("default BackupTempDir = %q", c.BackupTempDir)
	}
}

func TestTailscaleNetwork(t *testing.T) {
	t.Parallel()
	c, _ := mustLoad(t, nil)
	if c.Network.TailscaleSSHEnabled || c.Network.TailscaleInterface != "tailscale0" || c.Explicit("TAILSCALE_SSH_INTERFACE") {
		t.Errorf("defaults: %+v", c.Network)
	}
	c, _ = mustLoad(t, map[string]string{"TAILSCALE_SSH_INTERFACE": " ts1 "})
	if c.Network.TailscaleInterface != "ts1" || !c.Explicit("TAILSCALE_SSH_INTERFACE") {
		t.Errorf("interface: %+v", c.Network)
	}
}

func TestAllowedHosts(t *testing.T) {
	c, _ := mustLoad(t, map[string]string{"ALLOWED_HOSTS": " SSH.example.com , webssh.lan. ,, "})
	if got := c.Origins.AllowedHosts; len(got) != 2 || got[0] != "ssh.example.com" || got[1] != "webssh.lan" {
		t.Fatalf("ALLOWED_HOSTS: %q", got)
	}
	c, warns := mustLoad(t, nil)
	if c.Origins.AllowedHosts != nil {
		t.Fatalf("unset ALLOWED_HOSTS: %q", c.Origins.AllowedHosts)
	}
	if c.Profile == ProfileHomelab && !slices.ContainsFunc(warns, func(w Warning) bool { return w.Variable == "ALLOWED_HOSTS" && w.Kind == WarnOrigin }) {
		t.Fatalf("no hint for an unset ALLOWED_HOSTS in the homelab profile: %v", warns)
	}
	if e := loadErr(t, map[string]string{"ALLOWED_HOSTS": "ssh.example.com:443"}); e == nil || e.Variable != "ALLOWED_HOSTS" {
		t.Fatalf("a host with a port: %v", e)
	}
}
