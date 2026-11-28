package legacy

import (
	"context"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// E25 grants every account it takes over the one-time upgrade notice, in
// a table of its own next to the settings; an account created after the
// migration never gets it.
func TestMigratedAccountsGetTheUpgradeNotice(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	ctx := t.Context()
	svc := settings.New(m.db, settings.Environment{})
	if len(golden.manifest.Values.Users) == 0 {
		t.Fatal("the golden set has no accounts")
	}
	for name, want := range golden.manifest.Values.Users {
		got, err := svc.Notices(ctx, want.ID)
		if err != nil || !slices.Equal(got, []string{settings.NoticeUpgrade}) {
			t.Errorf("%s: notices %v, %v", name, got, err)
		}
	}
	if !slices.ContainsFunc(m.report.Coverage, func(c Coverage) bool { return c.Entity == "E25" && c.Version == 2 }) {
		t.Errorf("E25 coverage: %+v", m.report.Coverage)
	}

	hasher, err := local.NewHasher(local.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}, 2)
	if err != nil {
		t.Fatal(err)
	}
	acc := &accounts.Service{DB: m.db}
	acc.Credentials = &local.Provider{DB: m.db, Accounts: acc, Hasher: hasher}
	created, err := acc.Create(ctx, accounts.CreateRequest{Username: "after_upgrade", Password: "after-upgrade-password-1", ByAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Notices(ctx, created.ID); err != nil || len(got) != 0 {
		t.Fatalf("an account created after the migration: %v, %v", got, err)
	}
}

// The verification of E25 notices a missing or an already acknowledged
// upgrade notice.
func TestM2VerificationDetectsTamperedNotice(t *testing.T) {
	t.Parallel()
	for name, tamper := range map[string]func(context.Context, *store.Tx, Sealer) error{
		"missing":      execTx(`DELETE FROM settings_notices WHERE user_id = 3`),
		"acknowledged": execTx(`UPDATE settings_notices SET acknowledged_us = 1 WHERE user_id = 3`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			before := legacySnapshot(t, dir)
			m := M1{}
			m.wrap = func(s Step) Step { return &tamperStep{Step: s, target: "E25", tamper: tamper} }
			_, err := startClosed(m1Options(t, dir, m))
			if se := assertStop(t, err, "E25"); se.Code != CodeVerifyFailed {
				t.Fatalf("code %s: %v", se.Code, se)
			}
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
		})
	}
}
