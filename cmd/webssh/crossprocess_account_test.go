package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

type noMAC struct{}

func (noMAC) MAC(keyring.Purpose, []byte) []byte { return make([]byte, 32) }

// A lock in another process reaches the running server although the
// account has no session: the account-wide entry of the revocation journal
// ends its persistent tmux sessions there, as revoke_user_access did.
func TestAccountLockInAnotherProcessEndsServerTmux(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the server as a process")
	}
	dir := t.TempDir()
	port := freePort(t)
	base := "http://127.0.0.1:" + port
	dataDir := filepath.Join(dir, "data")
	env := []string{"DATA_DIR=" + dataDir, "SECRET_KEY=cross-process-test-secret-0123456789abcdef",
		"SESSION_COOKIE_SECURE=false", "BOOTSTRAP_REGISTRATION_ENABLED=true", "TMPDIR=" + dir}
	server := webssh(t, env, "serve", "--bind", "127.0.0.1:"+port)
	logs, _ := os.Create(filepath.Join(dir, "server.log"))
	server.Stdout, server.Stderr = logs, logs
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Signal(os.Interrupt)
		_ = server.Wait()
		if t.Failed() {
			out, _ := os.ReadFile(filepath.Join(dir, "server.log"))
			t.Logf("server log:\n%s", out)
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(base + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server not ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	signUp(t, base, "admin1", "first-password-1")

	// This test process is the other process: it opens the same database.
	db, err := store.Open(t.Context(), filepath.Join(dataDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.CloseShared() })
	acc := &accounts.Service{DB: db}
	sessions := session.New(db, noMAC{}, acc, nil)
	acc.Sessions = sessions
	var bob int64
	err = db.Write(t.Context(), func(tx *store.Tx) error {
		var err error
		if bob, err = acc.ProvisionTx(t.Context(), tx, "bob", "ldap"); err != nil {
			return err
		}
		_, err = tx.ExecContext(t.Context(), `INSERT INTO terminal_persistent_sessions (session_id, user_id, host, port, username,
			auth_type, tmux_session_name, via_socks, reconnect_route_known, connected) VALUES ('old', ?, 'h.example', 22, 'u',
			'password', 'webssh_bob_build', 0, 1, 0)`, bob)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acc.Manage(t.Context(), principaltest.Admin(1), bob, accounts.ActionLock); err != nil {
		t.Fatal(err)
	}
	locked := time.Now()
	for {
		var n int
		if err := db.Read(t.Context(), func(tx *store.Tx) error {
			return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM terminal_persistent_sessions WHERE user_id = ?`, bob).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Since(locked) > 5*time.Second {
			t.Fatal("the server kept the tmux session of the locked account")
		}
		time.Sleep(100 * time.Millisecond)
	}
	audit, err := os.ReadFile(filepath.Join(dataDir, "logs", "security_audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "TMUX_SESSION_NOT_ENDED") || !strings.Contains(string(audit), "webssh_bob_build") {
		t.Fatalf("the detached tmux session is not in the audit log:\n%s", audit)
	}
}
