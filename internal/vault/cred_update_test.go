package vault

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// hostOf returns the stored host member of record id in the fake stores.
func (r *credRig) hostOf(t *testing.T, id string) string {
	t.Helper()
	recs, err := r.stores.Records(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range recs.Profiles {
		if s, _ := stringMember(p, "id"); s == id {
			h, _ := stringMember(p, "host")
			return h
		}
	}
	return ""
}

func edited(host string) map[string]any {
	return map[string]any{"id": "p1", "name": "p1", "host": host, "port": 22, "username": "root", "auth_type": "password"}
}

// An edit that binds a saved password asks for the step-up before
// anything changes; with it, the edit and the assignment are stored in one
// transaction.
func TestEditWithSavedPasswordIsOneStep(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	req := map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true,
		"resource": edited("moved.example"), "target": map[string]any{"host": "moved.example", "port": 22, "username": "root", "auth_type": "password"}}
	for _, grant := range []string{"", "forged"} {
		if _, err := r.doGrant(t, p, MethodAssign, "", req, grant); codeOf(err) != fault.StepUpRequired {
			t.Fatalf("grant %q: %v", grant, err)
		}
		if h := r.hostOf(t, "p1"); h != "a.example" {
			t.Fatalf("grant %q: the host changed to %q before the step-up", grant, h)
		}
		if s, _ := r.state(t, p).profile("p1"); s != "missing" {
			t.Fatalf("grant %q: assignment %s before the step-up", grant, s)
		}
	}
	out, err := r.doGrant(t, p, MethodAssign, "", req, "issue")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"resource":{"id":"p1"`) {
		t.Errorf("result %s", out)
	}
	if h := r.hostOf(t, "p1"); h != "moved.example" {
		t.Errorf("host %q after the edit", h)
	}
	if s, c := r.state(t, p).profile("p1"); s != "ready" || c != id {
		t.Errorf("after the edit: %s %s, want ready %s", s, c, id)
	}
}

// When the assignment fails, the edit is not stored either.
func TestEditStoresNothingWhenTheAssignmentFails(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	// The page names the old target although the edit moves the host.
	stale := map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true, "resource": edited("moved.example"),
		"target": map[string]any{"host": "a.example", "port": 22, "username": "root", "auth_type": "password"}}
	if _, err := r.doGrant(t, p, MethodAssign, "", stale, "issue"); codeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("stale target: %v", err)
	}
	newPassword := map[string]any{"resource_id": "p1", "name": "Main", "password": "x", "confirm_target": true, "resource": edited("other.example")}
	if _, err := r.do(t, p, MethodCreate, "", newPassword); codeOf(err) != fault.DuplicateName {
		t.Fatalf("new password with a taken name: %v", err)
	}
	if h := r.hostOf(t, "p1"); h != "a.example" {
		t.Errorf("host %q after failed edits", h)
	}
	if r.stores.rolledBack != 2 {
		t.Errorf("%d edits rolled back, want 2", r.stores.rolledBack)
	}
	if s, _ := r.state(t, p).profile("p1"); s != "missing" {
		t.Errorf("assignment %s after failed edits", s)
	}
	// A taken host name from the store is reported as such.
	r.stores.refuse = fault.New(fault.DuplicateName, "taken")
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"resource_id": "p1", "name": "Fresh", "password": "x",
		"confirm_target": true, "resource": edited("other.example")}); codeOf(err) != fault.DuplicateName {
		t.Fatalf("taken host name: %v", err)
	}
}

// A new password and removing the assignment need no step-up and are
// stored with the edit as well.
func TestEditWithNewPasswordOrWithoutPassword(t *testing.T) {
	t.Parallel()
	r, p, _ := seeded(t)
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"resource_id": "p1", "name": "Fresh", "password": "x",
		"confirm_target": true, "resource": edited("new.example")}); err != nil {
		t.Fatal(err)
	}
	st := r.state(t, p)
	if s, c := st.profile("p1"); s != "ready" || c != st.credential("Fresh") || r.hostOf(t, "p1") != "new.example" {
		t.Fatalf("after the edit with a new password: %s %s %s", s, c, r.hostOf(t, "p1"))
	}
	// Removing it while editing replaces nothing, so it needs no
	// confirmation of a replacement.
	if _, err := r.do(t, p, MethodAssign, "", map[string]any{"resource_id": "p1", "credential_id": nil,
		"resource": edited("last.example")}); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.state(t, p).profile("p1"); s != "missing" || r.hostOf(t, "p1") != "last.example" {
		t.Errorf("after removing the password: %s %s", s, r.hostOf(t, "p1"))
	}
	// Replacing an assigned password still needs its confirmation.
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"resource_id": "p1", "name": "One", "password": "x",
		"confirm_target": true, "resource": edited("last.example")}); err != nil {
		t.Fatal(err)
	}
	_, err := r.do(t, p, MethodCreate, "", map[string]any{"resource_id": "p1", "name": "Two", "password": "x",
		"confirm_target": true, "resource": edited("again.example")})
	if codeOf(err) != fault.ReplacementConfirmationRequired || r.hostOf(t, "p1") != "last.example" {
		t.Errorf("unconfirmed replacement: %v, host %s", err, r.hostOf(t, "p1"))
	}
}

func TestEditRefusesAnotherRecord(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	other := edited("x.example")
	other["id"] = "p2"
	if _, err := r.doGrant(t, p, MethodAssign, "", map[string]any{"resource_id": "p1", "credential_id": id,
		"confirm_target": true, "resource": other}, "issue"); codeOf(err) != fault.InvalidRequest {
		t.Fatalf("edit naming another record: %v", err)
	}
	if r.stores.updated != 0 {
		t.Errorf("%d records written", r.stores.updated)
	}
}
