package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RS4-07: a change of the legacy source while Go serves reaches the
// whole chain: the source watch notices it, the server enters permanent
// maintenance and /ready and the sign-in page answer 503, /health stays
// 200.
func TestLegacySourceChangeWhileServingEntersMaintenance(t *testing.T) {
	interval := sourceWatchInterval
	sourceWatchInterval = 50 * time.Millisecond
	t.Cleanup(func() { sourceWatchInterval = interval })
	dir := migratedBesideLegacy(t)
	env := hostEnv(t)
	env["DATA_DIR"] = dir
	_, ts, _ := openEnv(t, env)
	c := &http.Client{Timeout: 5 * time.Second}
	if resp, _ := get(t, c, ts.URL+"/ready"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready before the change: %d", resp.StatusCode)
	}
	// Another process (the Python release) writes to the legacy source.
	f, err := os.OpenFile(filepath.Join(dir, "users", "user_3", "automation.json"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, _ := get(t, c, ts.URL+"/ready")
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ready after the change: %d", resp.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp, _ := get(t, c, ts.URL+"/login"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login after the change: %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, ts.URL+"/health"); resp.StatusCode != http.StatusOK {
		t.Fatalf("health after the change: %d", resp.StatusCode)
	}
}
