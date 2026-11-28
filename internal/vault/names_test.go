package vault

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// Key names are unique per user, trimmed and case-folded. A taken name is
// refused before the step-up, so the grant is not spent.
func TestKeyNamesAreUnique(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	first := r.upload(t, alice, "Deploy key", newEd25519PEM(t))
	calls := len(r.stepUp.Calls())
	grant := r.grant(alice, principal.ActionKeyUpload, userTarget(alice))
	_, err := r.svc.Upload(as(alice), Upload{Name: "  DEPLOY KEY ", Content: string(newEd25519PEM(t)), Grant: grant})
	if codeOf(err) != fault.DuplicateName {
		t.Fatalf("upload with a taken name: %v", err)
	}
	if n := len(r.stepUp.Calls()); n != calls {
		t.Errorf("the refused upload asked for the step-up (%d calls, before %d)", n, calls)
	}
	second := r.upload(t, alice, "Backup key", newEd25519PEM(t))
	if _, err := r.svc.Rename(as(alice), second.ID, "deploy key"); codeOf(err) != fault.DuplicateName {
		t.Errorf("rename onto a taken name: %v", err)
	}
	if _, err := r.svc.Rename(as(alice), first.ID, "DEPLOY KEY"); err != nil {
		t.Errorf("changing the case of the own name: %v", err)
	}
	bob := principaltest.User(2)
	r.upload(t, bob, "Deploy key", newEd25519PEM(t))
}

// Keys migrated with the same name stay usable and renamable under it.
func TestMigratedDuplicateKeyNamesStay(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	if err := r.db.Write(context.Background(), func(tx *store.Tx) error {
		for _, id := range []string{"legacy-a", "legacy-b"} {
			if _, err := ImportKey(context.Background(), tx, r.ring, Imported{ID: id, UserID: 1, Name: "Twin",
				KeyType: "ssh-ed25519", UploadedAt: "2025-01-02T03:04:05", PEM: newEd25519PEM(t)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("migrating duplicate key names: %v", err)
	}
	if list, err := r.svc.List(as(alice)); err != nil || len(list) != 2 {
		t.Fatalf("list %v %v", list, err)
	}
	if _, err := r.svc.Rename(as(alice), "legacy-b", " twin"); err != nil {
		t.Errorf("renaming a duplicate to its own name: %v", err)
	}
	if _, err := r.svc.Rename(as(alice), "legacy-b", "Twin B"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Rename(as(alice), "legacy-b", "TWIN"); codeOf(err) != fault.DuplicateName {
		t.Errorf("rename back onto the other copy's name: %v", err)
	}
}

func TestSavedPasswordNamesAreUnique(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	p := principaltest.User(1)
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "Lab", "password": "a"}); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]map[string]any{
		"create": {"name": " LAB ", "password": "b"},
	} {
		if _, err := r.do(t, p, MethodCreate, "", payload); codeOf(err) != fault.DuplicateName {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.do(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "ssh", "confirm_target": true,
		"name": "lab", "password": "c", "resource": newResources["ssh"]}); codeOf(err) != fault.DuplicateName {
		t.Errorf("create_for_resource with a taken password name: %v", err)
	}
	if n := r.resourceCount(t); n != 0 {
		t.Errorf("%d resources stored with a refused password", n)
	}
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "Other", "password": "d"}); err != nil {
		t.Fatal(err)
	}
	other := r.state(t, p).credential("Other")
	if _, err := r.do(t, p, MethodUpdate, other, map[string]any{"name": "lab"}); codeOf(err) != fault.DuplicateName {
		t.Errorf("rename onto a taken name: %v", err)
	}
	if _, err := r.do(t, p, MethodUpdate, other, map[string]any{"name": "OTHER", "password": "e"}); err != nil {
		t.Errorf("own name in another case: %v", err)
	}
	if n := len(r.state(t, p).Credentials); n != 2 {
		t.Errorf("%d passwords, want 2", n)
	}
	if _, err := r.do(t, principaltest.User(2), MethodCreate, "", map[string]any{"name": "Lab", "password": "f"}); err != nil {
		t.Errorf("another user's name blocks: %v", err)
	}
}

// The legacy vault import brings passwords back under the names of their
// resources, as 3.3 stored them; a name already in use does not stop it.
func TestLegacyImportKeepsRepeatedNames(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	v := o.Vaults[len(o.Vaults)-1]
	r := newCredRig(t)
	p := principaltest.User(o.User)
	r.stores.set(o.User, o.records())
	name, _ := asString(ResourcesFromRecords(o.records())[0].Name)
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": name, "password": "existing"}); err != nil {
		t.Fatal(err)
	}
	if err := r.db.Write(t.Context(), func(tx *store.Tx) error {
		return ImportLegacyVaultTx(t.Context(), tx, o.User, []byte(v.Document), v.Version)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.doGrant(t, p, MethodImport, "", map[string]any{"passphrase": o.Passphrase}, "issue"); err != nil {
		t.Fatalf("import with a repeated name: %v", err)
	}
	if n := len(r.state(t, p).Credentials); n != len(v.Records)+1 {
		t.Errorf("%d passwords after the import, want %d", n, len(v.Records)+1)
	}
}
