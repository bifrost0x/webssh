package stepup

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// RS8-R01: a demotion drops the account's grants and intents of
// administrator actions, from both channels; a grant for the account's
// own action and the grants of other accounts stay.
func TestRevokeAdminDropsAdministratorGrants(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	admin, other := principaltest.Admin(1), principaltest.Admin(2)
	adminGrant := e.grantFor(t, admin, principal.ActionSettingsUpdate, "global")
	selfGrant := e.grantFor(t, admin, principal.ActionKeyReplace, "k")
	otherGrant := e.grantFor(t, other, principal.ActionSettingsUpdate, "global")
	pending, err := e.svc.Begin(ctx, admin, principal.ActionUserManage, "5", ChannelAdmin)
	if err != nil || pending.Intent == "" {
		t.Fatalf("admin intent: %+v %v", pending, err)
	}
	if err := e.svc.DB.Write(ctx, func(tx *store.Tx) error { return e.svc.RevokeAdminTx(ctx, tx, admin.UserID) }); err != nil {
		t.Fatal(err)
	}
	// Promoted again: nothing from before the demotion serves.
	if err := e.svc.Consume(ctx, admin, principal.ActionSettingsUpdate, "global", adminGrant); err == nil {
		t.Fatal("an administrator grant from before the demotion was accepted")
	}
	if _, err := e.svc.Prove(ctx, admin, pending.Intent, Proof{Method: MethodPassword, Secret: "secret"}); err == nil {
		t.Fatal("an administrator intent from before the demotion was proven")
	}
	if err := e.svc.Consume(ctx, admin, principal.ActionKeyReplace, "k", selfGrant); err != nil {
		t.Fatalf("the account's own grant was dropped: %v", err)
	}
	if err := e.svc.Consume(ctx, other, principal.ActionSettingsUpdate, "global", otherGrant); err != nil {
		t.Fatalf("another administrator's grant was dropped: %v", err)
	}
}
