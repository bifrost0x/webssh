package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"testing"
)

const rootsChildEnv = "WEBSSH_TEST_FALLBACK_ROOTS_CHILD"

// TestFallbackRootsWithoutBundle runs the test binary again with every
// certificate location pointing nowhere: the system pool must then hold the
// embedded fallback roots instead of being empty. The pool is loaded once
// per process, hence the child process.
func TestFallbackRootsWithoutBundle(t *testing.T) {
	if os.Getenv(rootsChildEnv) == "1" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			t.Fatalf("SystemCertPool: %v", err)
		}
		if pool.Equal(x509.NewCertPool()) {
			t.Fatal("system pool is empty without a bundle")
		}
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestFallbackRootsWithoutBundle$") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), rootsChildEnv+"=1", "SSL_CERT_FILE=/nonexistent", "SSL_CERT_DIR=/nonexistent")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
