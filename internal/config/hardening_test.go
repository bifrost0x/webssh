package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretEveryVerbRedacted(t *testing.T) {
	c, _ := mustLoad(t, nil)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U"} {
		for _, v := range []any{c, c.SecretKey, &c} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, testSecret) || strings.Contains(out, fmt.Sprint([]byte(testSecret)[:4])) {
				t.Errorf("%s leaks the secret: %s", verb, out)
			}
		}
	}
}

func TestBoundedReadsRefuseDevices(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	if _, err := (CABundle{Path: "/dev/zero", Variable: "REQUESTS_CA_BUNDLE"}).CertPool(); !errors.Is(err, errNotRegular) {
		t.Errorf("CA bundle /dev/zero: %v", err)
	}
	if err := loadZone("/dev/zero"); !errors.Is(err, errNotRegular) {
		t.Errorf("TZ=/dev/zero: %v", err)
	}
	if _, err := (osFS{}).ReadFile("/dev/zero"); !errors.Is(err, errNotRegular) {
		t.Errorf("secret /dev/zero: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big")
	writeFile(t, big, strings.Repeat("\n", maxSecretFile+1), 0o600)
	if _, err := (osFS{}).ReadFile(big); !errors.Is(err, errTooLarge) {
		t.Errorf("oversized file: %v", err)
	}
}

func TestCABundleFollowsHashedLinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "store", "ca.pem"), string(selfSigned(t)), 0o600)
	if err := os.MkdirAll(filepath.Join(dir, "hashed"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(dir, "store", "ca.pem"), filepath.Join(dir, "hashed", "1a2b3c4d.0"))
	if _, err := (CABundle{Path: filepath.Join(dir, "hashed"), Variable: "REQUESTS_CA_BUNDLE"}).CertPool(); err != nil {
		t.Errorf("c_rehash directory: %v", err)
	}
}

func TestProxyCIDRsTrustEveryone(t *testing.T) {
	_, warns := mustLoad(t, map[string]string{"TRUSTED_PROXIES": "1", "TRUSTED_PROXY_CIDRS": "0.0.0.0/0"})
	if !hasWarning(warns, WarnProxy, "TRUSTED_PROXY_CIDRS", "every address") {
		t.Errorf("warns %v", warns)
	}
}

func TestSecretFileCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret_key")
	if err := createSecretFile(path, []byte("a\n")); err != nil {
		t.Fatal(err)
	}
	if err := createSecretFile(path, []byte("b\n")); err == nil {
		t.Error("existing secret replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "a\n" {
		t.Errorf("secret %q, %v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left: %v", entries)
	}
	if err := createSecretFile(filepath.Join(dir, "missing", "secret_key"), []byte("x")); err == nil {
		t.Error("created in a missing directory")
	}
}
