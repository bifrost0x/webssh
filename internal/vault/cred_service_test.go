package vault

import (
	"bytes"
	"encoding/json/jsontext"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func profileJSON(id, host string) jsontext.Value {
	return jsontext.Value(`{"id":"` + id + `","name":"Host ` + id + `","host":"` + host + `","port":22,"username":"root","auth_type":"password","key_id":null,"jump_host_id":null}`)
}

func hostTarget(id, host string) Target {
	port, user, auth := int64(22), "root", "password"
	return Target{ID: &id, Kind: ResourceSSH, Host: &host, Port: &port, Username: &user, AuthType: &auth}
}

// seeded returns a rig whose user 1 has two saved hosts and one password
// "Main" ("hunter2-ü").
func seeded(t *testing.T) (*credRig, principal.Principal, string) {
	t.Helper()
	r := newCredRig(t)
	p := principaltest.User(1)
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "a.example"), profileJSON("p2", "b.example")}, SMB: true})
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "Main", "username": "root", "password": "hunter2-ü"}); err != nil {
		t.Fatal(err)
	}
	id := r.state(t, p).credential("Main")
	if id == "" {
		t.Fatal("created password missing")
	}
	return r, p, id
}

func TestCredentialLifecycle(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	st := r.state(t, p)
	if !st.Enabled || len(st.Credentials) != 1 || st.Credentials[0].Username != "root" || len(st.Profiles) != 2 {
		t.Fatalf("state %+v", st)
	}
	if s, _ := st.profile("p1"); s != "missing" {
		t.Errorf("unassigned status %s", s)
	}
	version := st.Credentials[0].Version
	if _, err := r.do(t, p, MethodUpdate, id, map[string]any{"name": "Renamed"}); err != nil {
		t.Fatal(err)
	}
	st = r.state(t, p)
	if st.Credentials[0].Name != "Renamed" || st.Credentials[0].Version != version {
		t.Errorf("rename changed the version or failed: %+v", st.Credentials[0])
	}
	if _, err := r.do(t, p, MethodUpdate, id, map[string]any{"password": "new secret"}); err != nil {
		t.Fatal(err)
	}
	if r.state(t, p).Credentials[0].Version == version {
		t.Error("a new password keeps the version")
	}
	if _, err := r.do(t, p, MethodDelete, id, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.state(t, p).Credentials) != 0 {
		t.Error("delete kept the password")
	}
	if strings.Join(r.audit.actions, ",") != "create,update,update,delete" {
		t.Errorf("audit %v", r.audit.actions)
	}
}

func TestCreateValidatesLikePython(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	p := principaltest.User(1)
	for _, payload := range []map[string]any{
		{"name": " ", "password": "x"}, {"name": "n", "password": "   "}, {"name": "n", "password": "a\x00b"},
		{"name": strings.Repeat("n", 129), "password": "x"}, {"name": "n", "password": strings.Repeat("x", 4097)},
		{"name": "n", "password": "x", "username": nil}, {"name": "n"},
	} {
		if _, err := r.do(t, p, MethodCreate, "", payload); codeOf(err) != fault.InvalidRequest {
			t.Errorf("%v: %v", payload, err)
		}
	}
	long := strings.Repeat("é", 2048) // 4096 bytes
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "Long", "password": long}); err != nil {
		t.Fatal(err)
	}
	for i := range MaxCredentials - 1 {
		if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "n" + string(rune('A'+i%26)), "password": "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "one too many", "password": "x"}); codeOf(err) != fault.StorageLimit {
		t.Errorf("101st password: %v", err)
	}
}

func TestAssignNeedsStepUpAndBindsTheTarget(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	assign := map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true}
	if _, err := r.do(t, p, MethodAssign, "", assign); codeOf(err) != fault.StepUpRequired {
		t.Fatalf("assign without grant: %v", err)
	}
	if _, err := r.doGrant(t, p, MethodAssign, "", assign, "issue"); err != nil {
		t.Fatal(err)
	}
	if s, c := r.state(t, p).profile("p1"); s != "ready" || c != id {
		t.Fatalf("p1 = %s %s", s, c)
	}
	// One step-up covers further bindings of the session for a while.
	if _, err := r.do(t, p, MethodAssign, "", map[string]any{"resource_id": "p2", "credential_id": id, "confirm_target": true}); err != nil {
		t.Fatalf("second binding: %v", err)
	}
	other := p
	other.SessionID = "another-session"
	if _, err := r.do(t, other, MethodAssign, "", map[string]any{"resource_id": "p2", "credential_id": nil}); err != nil {
		t.Fatalf("unassign needs no step-up: %v", err)
	}
	secret, err := r.svc.Password(t.Context(), 1, "p1", hostTarget("p1", "a.example"))
	if err != nil || string(secret) != "hunter2-ü" {
		t.Fatalf("Password = %q, %v", secret, err)
	}
	if _, err := r.svc.Password(t.Context(), 1, "p1", hostTarget("p1", "evil.example")); codeOf(err) != fault.CredentialTargetChanged {
		t.Errorf("other target: %v", err)
	}
	if _, err := r.svc.Password(t.Context(), 2, "p1", hostTarget("p1", "a.example")); codeOf(err) != fault.InvalidTargets {
		t.Errorf("other user: %v", err)
	}
	if _, err := r.svc.Password(t.Context(), 1, "p2", hostTarget("p2", "b.example")); codeOf(err) != fault.CredentialMissing {
		t.Errorf("unassigned: %v", err)
	}
	// The host moves: the assignment is "changed" and nothing is sent.
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "moved.example"), profileJSON("p2", "b.example")}, SMB: true})
	if s, _ := r.state(t, p).profile("p1"); s != "changed" {
		t.Errorf("moved host status %s", s)
	}
	if _, err := r.svc.Password(t.Context(), 1, "p1", hostTarget("p1", "moved.example")); codeOf(err) != fault.CredentialTargetChanged {
		t.Errorf("moved host: %v", err)
	}
	r.policy.set(false, "rev1")
	if _, err := r.svc.Password(t.Context(), 1, "p1", hostTarget("p1", "moved.example")); codeOf(err) != fault.CredentialsDisabled {
		t.Errorf("disabled: %v", err)
	}
	if s, _ := r.state(t, p).profile("p2"); s != "disabled" {
		t.Errorf("disabled status %s", s)
	}
}

func TestStepUpGrantIsBoundToTheIntent(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	assign := map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true}
	token, err := r.prepare(t, p, MethodAssign, "", assign)
	if err != nil {
		t.Fatal(err)
	}
	wrong := r.grant(p, principal.ActionCredentialsVault, "another-intent")
	body := obj(t, map[string]any{"intent": token, "resource_id": "p1", "credential_id": id, "confirm_target": true})
	if _, err := r.svc.Apply(as(p), MethodAssign, "", body, wrong); codeOf(err) != fault.StepUpRequired {
		t.Fatalf("grant for another target: %v", err)
	}
	// The intent survives the refused attempt, so the page can retry.
	if _, err := r.svc.Apply(as(p), MethodAssign, "", body, r.grant(p, principal.ActionCredentialsVault, token)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Apply(as(p), MethodAssign, "", body, ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("replayed intent: %v", err)
	}
}

func TestIntentIsBoundToMutationSessionAndPolicy(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	token, err := r.prepare(t, p, MethodUpdate, id, map[string]any{"name": "A"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := obj(t, map[string]any{"intent": token, "name": "B"})
	if _, err := r.svc.Apply(as(p), MethodUpdate, id, tampered, ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("other mutation: %v", err)
	}
	other := p
	other.SessionID = "s2"
	good := obj(t, map[string]any{"intent": token, "name": "A"})
	if _, err := r.svc.Apply(as(other), MethodUpdate, id, good, ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("other session: %v", err)
	}
	r.policy.set(true, "rev2")
	if _, err := r.svc.Apply(as(p), MethodUpdate, id, good, ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("new policy revision: %v", err)
	}
}

func TestIntentLimits(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	var tokens []string
	for range IntentsPerUser + 1 {
		tok, err := r.prepare(t, p, MethodUpdate, id, map[string]any{"name": "A"})
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
	}
	body := func(tok string) jsontext.Value { return obj(t, map[string]any{"intent": tok, "name": "A"}) }
	if _, err := r.svc.Apply(as(p), MethodUpdate, id, body(tokens[0]), ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("oldest intent beyond the bound: %v", err)
	}
	if _, err := r.svc.Apply(as(p), MethodUpdate, id, body(tokens[IntentsPerUser]), ""); err != nil {
		t.Errorf("newest intent: %v", err)
	}
	// Expiry.
	tok, _ := r.prepare(t, p, MethodUpdate, id, map[string]any{"name": "A"})
	r.svc.creds.intents.now = func() time.Time { return fixedNow.Add(IntentTTL) }
	if _, err := r.svc.Apply(as(p), MethodUpdate, id, body(tok), ""); codeOf(err) != fault.InvalidIntent {
		t.Errorf("expired intent: %v", err)
	}
}

func TestReplacementAndPreviewChecks(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	if _, err := r.doGrant(t, p, MethodAssign, "", map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true}, "issue"); err != nil {
		t.Fatal(err)
	}
	create := map[string]any{"resource_id": "p1", "name": "Second", "password": "pw2", "confirm_target": true}
	if _, err := r.do(t, p, MethodCreate, "", create); codeOf(err) != fault.ReplacementConfirmationRequired {
		t.Fatalf("unconfirmed replacement: %v", err)
	}
	create["replace_credential_id"] = id
	// The host changes between preview and apply.
	token, err := r.prepare(t, p, MethodCreate, "", create)
	if err != nil {
		t.Fatal(err)
	}
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "moved.example"), profileJSON("p2", "b.example")}, SMB: true})
	body := map[string]any{"intent": token}
	for k, v := range create {
		body[k] = v
	}
	if _, err := r.svc.Apply(as(p), MethodCreate, "", obj(t, body), ""); codeOf(err) != fault.PreviewChanged {
		t.Fatalf("moved host: %v", err)
	}
	if n := len(r.state(t, p).Credentials); n != 1 {
		t.Errorf("a refused replacement created a password (%d)", n)
	}
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "a.example"), profileJSON("p2", "b.example")}, SMB: true})
	create["target"] = map[string]any{"host": "elsewhere.example", "port": 22, "username": "root", "auth_type": "password"}
	if _, err := r.do(t, p, MethodCreate, "", create); codeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("other target: %v", err)
	}
	create["target"] = map[string]any{"host": "a.example", "port": 22, "username": "root", "auth_type": "password", "jump_host_id": nil}
	if _, err := r.do(t, p, MethodCreate, "", create); err != nil {
		t.Fatal(err)
	}
	st := r.state(t, p)
	if s, c := st.profile("p1"); s != "ready" || c != st.credential("Second") {
		t.Errorf("p1 = %s %s", s, c)
	}
}

func TestDeleteKeepsLiveAssignments(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	if _, err := r.doGrant(t, p, MethodAssign, "", map[string]any{"resource_id": "p1", "credential_id": id, "confirm_target": true}, "issue"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.do(t, p, MethodDelete, id, nil); codeOf(err) != fault.CredentialInUse {
		t.Fatalf("delete assigned: %v", err)
	}
	// The host is deleted: its assignment no longer counts.
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p2", "b.example")}, SMB: true})
	if uses := r.state(t, p).Credentials[0].Uses; len(uses) != 0 {
		t.Errorf("uses of a deleted host: %v", uses)
	}
	if _, err := r.do(t, p, MethodDelete, id, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteWhileDisabledAndUnknownSMB(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "a.example")},
		SMBShares: []jsontext.Value{jsontext.Value(`{"id":"m1","name":"Files","host":"f.example","username":"u","share":"data","domain":""}`)}, SMB: true})
	if _, err := r.doGrant(t, p, MethodAssign, "", map[string]any{"resource_id": "smb:m1", "credential_id": id, "confirm_target": true}, "issue"); err != nil {
		t.Fatal(err)
	}
	// Without an SMB store the share's assignment still protects the password.
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "a.example")}})
	if _, err := r.do(t, p, MethodDelete, id, nil); codeOf(err) != fault.CredentialInUse {
		t.Fatalf("delete with unknown SMB share: %v", err)
	}
	r.policy.set(false, "rev1")
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": "x", "password": "y"}); codeOf(err) != fault.CredentialsDisabled {
		t.Fatalf("create while disabled: %v", err)
	}
	if _, err := r.do(t, p, MethodDelete, id, nil); err != nil {
		t.Fatalf("erase while disabled: %v", err)
	}
}

func TestAuthorizedTargetForQuickConnect(t *testing.T) {
	t.Parallel()
	r, p, id := seeded(t)
	target := map[string]any{"host": "quick.example", "port": 2222, "username": "ops", "auth_type": "password", "jump_host_id": nil}
	payload := map[string]any{"credential_id": id, "target": target, "confirm_target": true}
	if _, err := r.do(t, p, MethodAuthorizeTarget, "", payload); codeOf(err) != fault.StepUpRequired {
		t.Fatalf("without grant: %v", err)
	}
	out, err := r.doGrant(t, p, MethodAuthorizeTarget, "", payload, "issue")
	if err != nil {
		t.Fatal(err)
	}
	token, ok := stringMember(out, "credential_target_token")
	if !ok {
		t.Fatalf("result %s", out)
	}
	host, user, auth := "quick.example", "ops", "password"
	port := int64(2222)
	conn := Target{Kind: ResourceSSH, Host: &host, Port: &port, Username: &user, AuthType: &auth}
	for range 2 { // a reconnect within the lifetime reuses the token
		secret, err := r.svc.TargetPassword(as(p), p, id, token, conn)
		if err != nil || string(secret) != "hunter2-ü" {
			t.Fatalf("TargetPassword = %q, %v", secret, err)
		}
	}
	evil := "evil.example"
	moved := conn
	moved.Host = &evil
	if _, err := r.svc.TargetPassword(as(p), p, id, token, moved); codeOf(err) != fault.CredentialTargetChanged {
		t.Errorf("other host: %v", err)
	}
	other := p
	other.SessionID = "s2"
	if _, err := r.svc.TargetPassword(as(other), other, id, token, conn); codeOf(err) != fault.InvalidIntent {
		t.Errorf("other session: %v", err)
	}
	if _, err := r.do(t, p, MethodUpdate, id, map[string]any{"password": "rotated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.TargetPassword(as(p), p, id, token, conn); codeOf(err) != fault.CredentialTargetChanged {
		t.Errorf("after the password changed: %v", err)
	}
	if _, err := r.do(t, p, MethodAuthorizeTarget, "", map[string]any{"credential_id": id, "target": target}); codeOf(err) != fault.ConfirmationRequired {
		t.Errorf("unconfirmed target: %v", err)
	}
}

func TestCreateForResource(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	p := principaltest.User(1)
	out, err := r.do(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "ssh", "confirm_target": true,
		"name": "Box", "password": "box-pw",
		"resource": map[string]any{"name": "Box", "host": "box.example", "port": 22, "username": "root", "auth_type": "password"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stringMember(out, "credential"); ok {
		t.Error("credential is not an object")
	}
	if !bytes.Contains(out, []byte(`"resource":{"id":"new1"`)) {
		t.Errorf("result %s", out)
	}
	if s, c := r.state(t, p).profile("new1"); s != "ready" || c == "" {
		t.Errorf("new host %s %s", s, c)
	}
	// A password that cannot be stored removes the resource again.
	_, err = r.do(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "jump", "confirm_target": true,
		"name": " ", "password": "x",
		"resource": map[string]any{"name": "J", "host": "j.example", "port": 22, "username": "u", "auth_type": "password"}})
	if codeOf(err) != fault.InvalidRequest {
		t.Fatalf("invalid name: %v", err)
	}
	if recs, _ := r.stores.Records(t.Context(), 1); len(recs.JumpHosts) != 0 {
		t.Error("the jump host stayed after the password failed")
	}
	if _, err := r.do(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "ssh", "confirm_target": true,
		"name": "K", "password": "x", "resource": map[string]any{"auth_type": "key"}}); codeOf(err) != fault.InvalidTargets {
		t.Errorf("key host: %v", err)
	}
}
