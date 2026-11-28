package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// issue-factor-bootstrap prints a code only for a factorless account
// GitHub created, and the code then confirms that account's first factor.
func TestIssueFactorBootstrapCommand(t *testing.T) {
	adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	cfg, _ := loadConfig()
	g, err := openGoData(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var octo int64
	err = g.db.Write(t.Context(), func(tx *store.Tx) error {
		var err error
		if octo, err = g.accounts.ProvisionTx(t.Context(), tx, "octo", "github"); err != nil {
			return err
		}
		now := time.Now().UTC()
		return github.ImportIdentityTx(t.Context(), tx, github.Identity{ID: 1, UserID: octo, GitHubUserID: "1001", Login: "octo",
			Provisioned: true, CreatedAt: now, UpdatedAt: now})
	})
	if err := errors.Join(err, g.Close()); err != nil {
		t.Fatal(err)
	}
	code, out, e := runIn(t, "", "webssh", "issue-factor-bootstrap", "--username", "octo", "--action", "totp.enroll")
	re := regexp.MustCompile(`^Enrollment code: ([A-Za-z0-9_-]{43})\nExpires at: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?Z\. ` +
		`This code is single-use and bound to octo and totp\.enroll\.\n$`)
	m := re.FindStringSubmatch(out)
	if code != 0 || m == nil {
		t.Fatalf("issue: %d %q %q", code, out, e)
	}
	if code, _, e := runIn(t, "", "webssh", "issue-factor-bootstrap", "--username", "admin1", "--action", "totp.enroll"); code != 1 ||
		e != "Error: Only a factorless GitHub-provisioned account is eligible.\n" {
		t.Fatalf("local account: %d %q", code, e)
	}
	g, err = openGoData(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	boot := newBootstrap(g.db, g.ring, g.accounts, nil, nil)
	if ok, err := boot.Redeem(t.Context(), octo, principal.ActionPasskeyEnroll, m[1]); ok || err != nil {
		t.Fatalf("redeemed for another action: %v %v", ok, err)
	}
	if ok, err := boot.Redeem(t.Context(), octo, principal.ActionTOTPEnroll, m[1]); !ok || err != nil {
		t.Fatalf("redeem: %v %v", ok, err)
	}
	var _ auth.BootstrapStanding = bootstrapStanding{}
}

// issue-factor-bootstrap is refused while a restore is unfinished, as the
// Python release refused it during restore maintenance: the code would be
// written into a database the activation replaces.
func TestIssueFactorBootstrapRefusedDuringRestore(t *testing.T) {
	adminEnv(t)
	if code, _, e := runIn(t, "password1\npassword1\n", "webssh", "create-admin", "--username", "admin1"); code != 0 {
		t.Fatal(e)
	}
	cfg, _ := loadConfig()
	// The server holds the Go lock between staging and its restart.
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	server, err := legacy.Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	journal := `{"format":1,"operation_id":"op","state":"in_progress","kind":"go","staged":".restore-op",` +
		`"started_at":"2026-11-27T00:00:00Z","updated_at":"2026-11-27T00:00:00Z","message":"Restore in progress"}`
	if err := os.WriteFile(filepath.Join(cfg.DataDir, keyring.GoDirName, backup.JournalName), []byte(journal), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, e := runIn(t, "", "webssh", "issue-factor-bootstrap", "--username", "admin1", "--action", "totp.enroll")
	if code != 1 || out != "" || e != "Error: Factor bootstrap is unavailable during restore maintenance.\n" {
		t.Fatalf("during a restore: %d %q %q", code, out, e)
	}
}
