package main

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
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
