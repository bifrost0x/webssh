package vault

import (
	"context"
	json "encoding/json/v2"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func route(t *testing.T, s *Service, typ string) protocol.Route {
	t.Helper()
	for _, r := range s.Routes() {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no route %s", typ)
	return protocol.Route{}
}

func TestRoutesCoverKeysCatalog(t *testing.T) {
	r := newRig(t, Limits{})
	var got []string
	for _, rt := range r.svc.Routes() {
		got = append(got, rt.Type)
		write := rt.Type != protocol.TypeKeysList
		if rt.Spec.Mutates != write {
			t.Errorf("%s: Mutates %v", rt.Type, rt.Spec.Mutates)
		}
		if want := map[bool]string{true: RateKeyWrite, false: RateKeyList}[write]; rt.Spec.RateKey != want {
			t.Errorf("%s: rate key %q", rt.Type, rt.Spec.RateKey)
		}
	}
	var want []string
	for _, m := range protocol.V1() {
		if m.Owner == "internal/vault" {
			want = append(want, m.Name)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("routes %v, catalog %v", got, want)
	}
}

// The wire round trip through the routes, with the shapes the page reads.
func TestRoutesWire(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	peer := protocoltest.NewPeer(t, alice)
	ctx := context.Background()
	content := string(goldenByLabel(t, "ed25519-openssh").pem(t))

	_, werr := protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysUpload), peer, map[string]any{"name": "k", "key_content": content})
	if werr == nil || werr.Code != fault.StepUpRequired {
		t.Fatalf("upload without grant: %+v", werr)
	}
	grant := r.grant(alice, principal.ActionKeyUpload, "1")
	raw, werr := protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysUpload), peer, map[string]any{"name": "k", "key_content": content, "step_up": grant})
	if werr != nil {
		t.Fatalf("upload: %+v", werr)
	}
	var up struct {
		Key map[string]any `json:"key"`
	}
	if err := json.Unmarshal(raw, &up); err != nil {
		t.Fatal(err)
	}
	id, _ := up.Key["id"].(string)
	wantKey := map[string]any{"id": id, "name": "k", "filename": id + ".pem", "key_type": "Ed25519", "encrypted": true, "uploaded_at": "2026-11-26T10:11:12.345678+00:00", "usable": true}
	if len(up.Key) != len(wantKey) {
		t.Fatalf("key members %v", up.Key)
	}
	for k, v := range wantKey {
		if up.Key[k] != v {
			t.Errorf("key.%s = %v, want %v", k, up.Key[k], v)
		}
	}

	raw, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysList), peer, nil)
	if werr != nil || !strings.Contains(string(raw), `"keys":[{"id":"`+id) {
		t.Fatalf("list %s %+v", raw, werr)
	}
	raw, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysRename), peer, map[string]any{"key_id": id, "name": "renamed"})
	if werr != nil || !strings.Contains(string(raw), `"name":"renamed"`) {
		t.Fatalf("rename %s %+v", raw, werr)
	}
	// A protected key without passphrase: the page reads err.details.
	protected := string(goldenByLabel(t, "ecdsa-p256-openssh-passphrase").pem(t))
	_, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysReplace), peer, map[string]any{"key_id": id, "key_content": protected})
	if werr == nil || werr.Details[DetailPassphraseRequired] != true || werr.Message != textPassphraseMissing {
		t.Fatalf("replace with protected key: %+v", werr)
	}
	// Unknown members are refused (strict payloads).
	_, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysDelete), peer, map[string]any{"key_id": id, "force": true})
	if werr == nil || werr.Code != fault.InvalidRequest {
		t.Fatalf("unknown member: %+v", werr)
	}
	raw, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysDelete), peer, map[string]any{"key_id": id, "step_up": r.grant(alice, principal.ActionKeyDelete, id)})
	if werr != nil || string(raw) != "{}" {
		t.Fatalf("delete %s %+v", raw, werr)
	}
	// A key of 64 KiB fits the payload limit even JSON-escaped.
	big := strings.Repeat("\n", MaxKeyBytes)
	_, werr = protocoltest.Call(ctx, route(t, r.svc, protocol.TypeKeysUpload), peer, map[string]any{"name": "k", "key_content": big})
	if werr == nil || werr.Code != fault.InvalidValue {
		t.Fatalf("64 KiB upload: %+v", werr)
	}
}

// All KDF slots taken: the upload of a protected key is refused as busy,
// without waiting and without spending a grant.
func TestKDFSlotsBounded(t *testing.T) {
	r := newRig(t, Limits{})
	for range kdfSlots {
		r.svc.kdf <- struct{}{}
	}
	alice := principaltest.User(1)
	_, err := r.svc.Upload(as(alice), Upload{Name: "k", Content: string(goldenByLabel(t, "ed25519-openssh-passphrase").pem(t)), Passphrase: goldenPassphrase, Grant: "g"})
	wantCode(t, err, fault.Busy)
	if fault.RetryAfter(err) <= 0 {
		t.Fatal("busy without retry hint")
	}
	// Keys without passphrase need no slot.
	r.upload(t, alice, "plain", newEd25519PEM(t))
}
