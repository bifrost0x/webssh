package hosts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func v(s string) jsontext.Value { return jsontext.Value(s) }

// seeded returns a service whose user 3 has the golden stores plus extra
// records.
func seeded(t *testing.T, extra Legacy) *Service {
	t.Helper()
	c := readOracle(t)
	s := oracleService(t, c)
	if extra.Profiles == nil && extra.JumpHosts == nil && extra.SOCKSProxies == nil {
		return s
	}
	legacy := Legacy{
		Profiles:     append(values(c.Base.Profiles), extra.Profiles...),
		JumpHosts:    append(values(c.Base.JumpHosts), extra.JumpHosts...),
		SOCKSProxies: append(values(c.Base.SOCKSProxies), extra.SOCKSProxies...),
	}
	if err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, oracleUser, legacy, DefaultLimits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func code(err error) fault.Code { return fault.CodeOf(err) }

func TestOraclePresetValidation(t *testing.T) {
	for _, c := range readOracle(t).Presets {
		if got := validPresets(jsontext.Value(c.Value)); got != c.Valid {
			t.Errorf("validPresets(%s) = %v, Python %v", c.Value, got, c.Valid)
		}
	}
}

func TestPreviewRefusals(t *testing.T) {
	s := seeded(t, Legacy{})
	base := protocol.HostsProfileSave{Name: v(`"n"`), Host: v(`"h.example"`), Username: v(`"u"`), AuthType: v(`"password"`)}
	tailscale := base
	tailscale.AuthType = v(`"tailscale"`)
	gateway := base
	gateway.Username = v(`"user:target"`)
	command := base
	command.StartupMode, command.CommandID = v(`"command"`), v(`"cmd-1"`)
	newSet := base
	newSet.StartupMode, newSet.CommandSetID = v(`"command_set"`), v(`"867426f3-ca2f-40df-837c-6430d34fa3c9"`)
	for name, req := range map[string]protocol.HostsProfileSave{
		"tailscale": tailscale, "gateway": gateway, "command": command, "new command set": newSet,
	} {
		if _, err := s.SaveProfile(t.Context(), oracleUser, req); code(err) != fault.NotAvailableInPreview {
			t.Errorf("%s: %v, want not_available_in_preview", name, err)
		}
	}
	// A saved host keeps the command set it already has.
	keep := newSet
	keep.ID = v(`"1bd77053-ce70-4437-9be1-c35f332d2f4c"`)
	keep.AuthType, keep.KeyID = v(`"key"`), v(`"d12ad3cd-eb07-4418-8967-a3169ba3de68"`)
	if _, err := s.SaveProfile(t.Context(), oracleUser, keep); err != nil {
		t.Errorf("unchanged command set refused: %v", err)
	}
	other := keep
	other.CommandSetID = v(`"another-set"`)
	if _, err := s.SaveProfile(t.Context(), oracleUser, other); code(err) != fault.NotAvailableInPreview {
		t.Errorf("changed command set: %v, want not_available_in_preview", err)
	}
}

func TestUnknownFieldsSurviveEverySave(t *testing.T) {
	s := seeded(t, Legacy{Profiles: []jsontext.Value{v(`{"zz_future":{"x":[1,2]},"id":"keep","name":"Keep",` +
		`"host":"keep.example","port":22,"username":"k","auth_type":"password","key_id":null,` +
		`"startup_mode":"none","sort_order":20,"big":123456789012345678901234567890}`)}})
	save := protocol.HostsProfileSave{ID: v(`"keep"`), Name: v(`"Kept"`), Host: v(`"other.example"`),
		Username: v(`"k"`), AuthType: v(`"password"`), Group: v(`"G"`)}
	if _, err := s.SaveProfile(t.Context(), oracleUser, save); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OrganizeProfile(t.Context(), oracleUser, protocol.HostsProfileOrganize{ProfileID: v(`"keep"`), Favorite: v(`true`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MoveProfile(t.Context(), oracleUser, protocol.HostsProfileMove{ProfileID: v(`"keep"`),
		ExpectedSourceGroup: v(`"G"`), TargetGroup: v(`""`), TargetIndex: v(`0`), ConfirmSourceGroupRemoval: v(`true`)}); err != nil {
		t.Fatal(err)
	}
	profiles, err := s.Profiles(t.Context(), oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	var kept string
	for _, p := range profiles {
		if strings.Contains(string(p), `"id":"keep"`) {
			kept = string(p)
		}
	}
	if !strings.HasPrefix(kept, `{"zz_future":{"x":[1,2]},"big":123456789012345678901234567890,"name":"Kept"`) {
		t.Fatalf("unknown fields lost or moved: %s", kept)
	}
}

func TestRecordLimitsRefuseOnlyGrowth(t *testing.T) {
	s := seeded(t, Legacy{})
	s.Limits.ProfileMaxRecords = 10 // the golden user already has 13
	newHost := protocol.HostsProfileSave{Name: v(`"n"`), Host: v(`"n.example"`), Username: v(`"u"`), AuthType: v(`"password"`)}
	if _, err := s.SaveProfile(t.Context(), oracleUser, newHost); code(err) != fault.QuotaExceeded ||
		!strings.Contains(err.Error(), "more than 10 records are not allowed") {
		t.Fatalf("growth beyond the limit: %v", err)
	}
	edit := protocol.HostsProfileSave{ID: v(`"syn-extra"`), Name: v(`"Edited"`), Host: v(`"extra.golden.test"`),
		Username: v(`"x"`), AuthType: v(`"password"`)}
	if _, err := s.SaveProfile(t.Context(), oracleUser, edit); err != nil {
		t.Fatalf("editing a store above the limit refused: %v", err)
	}
	if err := s.DeleteProfile(t.Context(), oracleUser, v(`"syn-extra"`)); err != nil {
		t.Fatalf("shrinking a store above the limit refused: %v", err)
	}
	listed, err := s.Profiles(t.Context(), oracleUser)
	if err != nil || len(listed) != 12 {
		t.Fatalf("a store above the limit must stay readable: %d, %v", len(listed), err)
	}
}

func TestByteLimitsRefuseOnlyGrowth(t *testing.T) {
	s := seeded(t, Legacy{})
	s.Limits.StoreMaxBytes = 1 << 10
	long := protocol.HostsProfileSave{Name: v(`"n"`), Host: v(`"n.example"`), Username: v(`"u"`), AuthType: v(`"password"`),
		StartupMode: v(`"free_text"`), StartupCommands: jsonString(strings.Repeat("x", 4000))}
	if _, err := s.SaveProfile(t.Context(), oracleUser, long); code(err) != fault.QuotaExceeded {
		t.Fatalf("store growth beyond the byte limit: %v", err)
	}
	if err := s.DeleteProfile(t.Context(), oracleUser, v(`"syn-free"`)); err != nil {
		t.Fatalf("shrinking an oversized store refused: %v", err)
	}
	s.Limits = DefaultLimits
	s.Limits.ConfigMaxBytes = 1 << 10
	if _, err := s.SaveJumpHost(t.Context(), oracleUser, protocol.HostsJumpSave{Name: v(`"j"`), Host: v(`"j.example"`),
		Username: v(`"u"`), AuthType: v(`"password"`)}); err == nil || !strings.Contains(err.Error(), "combined connection data") {
		t.Fatalf("combined growth: %v", err)
	}
}

func TestOwnersAreSeparate(t *testing.T) {
	s := seeded(t, Legacy{})
	if _, err := s.Resolve(t.Context(), 4, "c11ae780-b6eb-4dac-a794-d27d0b23f255"); code(err) != fault.NotFound {
		t.Fatalf("another user's host resolved: %v", err)
	}
	if err := s.DeleteProfile(t.Context(), 4, v(`"c11ae780-b6eb-4dac-a794-d27d0b23f255"`)); code(err) != fault.NotFound {
		t.Fatalf("another user's host deleted: %v", err)
	}
	if err := s.DeleteJumpHost(t.Context(), 4, v(`"2735737b-d93a-4e54-acd5-85b740b63526"`)); code(err) != fault.NotFound {
		t.Fatalf("another user's jump host deleted: %v", err)
	}
	save := protocol.HostsProfileSave{Name: v(`"n"`), Host: v(`"n.example"`), Username: v(`"u"`), AuthType: v(`"password"`),
		JumpHostID: v(`"2735737b-d93a-4e54-acd5-85b740b63526"`)}
	if _, err := s.SaveProfile(t.Context(), 4, save); code(err) != fault.NotFound {
		t.Fatalf("another user's jump host referenced: %v", err)
	}
	if got, _ := s.Profiles(t.Context(), 4); len(got) != 0 {
		t.Fatalf("user 4 sees %d hosts", len(got))
	}
}

func TestResolve(t *testing.T) {
	s := seeded(t, Legacy{
		Profiles: []jsontext.Value{
			v(`{"id":"pw-jump","name":"PJ","host":"pj.example","port":22,"username":"u","auth_type":"password","jump_host_id":"pw-bastion"}`),
			v(`{"id":"login-socks","name":"LS","host":"ls.example","username":"u","auth_type":"password","socks_proxy_id":"ae5c7232-6f7d-4457-bfca-0cc84e323aeb"}`),
			v(`{"id":"umlaut","name":"U","host":"bücher.example","username":"u","auth_type":"password"}`),
			v(`{"id":"ts","name":"T","host":"ts.example","username":"u","auth_type":"tailscale"}`),
			v(`{"id":"gw","name":"G","host":"gw.example","username":"a:b","auth_type":"password"}`),
			v(`{"id":"tmux","name":"Tm","host":"tm.example","username":"u","auth_type":"password","use_tmux":true,"startup_mode":"free_text","startup_commands":"ls"}`),
			v(`{"id":"local-dns","name":"LD","host":"ld.example","username":"u","auth_type":"password","socks_proxy_id":"local"}`),
		},
		JumpHosts:    []jsontext.Value{v(`{"id":"pw-bastion","name":"B","host":"b.example","port":22,"username":"j","auth_type":"password","key_id":null}`)},
		SOCKSProxies: []jsontext.Value{v(`{"id":"local","name":"L","host":"l.example","port":1080,"username":"","auth_type":"none","remote_dns":false,"created_at":"2026-01-01T00:00:00"}`)},
	})
	ctx := t.Context()
	jump, err := s.Resolve(ctx, oracleUser, "0296e087-7c43-42d2-acb0-6703e8f44957")
	if err != nil {
		t.Fatal(err)
	}
	want := client.Target{Owner: oracleUser,
		Hop:     client.Hop{Host: "inner.golden.test", Port: 22, User: "deploy", Auth: client.Auth{KeyID: "80c09d20-daf6-4bf5-bc41-a41341ab13aa"}},
		Jumps:   []client.Hop{{Host: "bastion.golden.test", Port: 22, User: "jumper", Auth: client.Auth{KeyID: "d12ad3cd-eb07-4418-8967-a3169ba3de68"}}},
		Display: client.Display{ProfileID: "0296e087-7c43-42d2-acb0-6703e8f44957", Name: "Via bastion", JumpHostID: "2735737b-d93a-4e54-acd5-85b740b63526"}}
	if !equalTarget(jump, want) {
		t.Fatalf("jump route:\n got %+v\nwant %+v", jump, want)
	}
	socks, err := s.Resolve(ctx, oracleUser, "312f9a10-c676-4ca4-9743-e7aa2e758aa3")
	if err != nil || socks.Proxy == nil || *socks.Proxy != (client.SOCKS{Host: "socks.golden.test", Port: 1080, RemoteDNS: true}) || len(socks.Jumps) != 0 {
		t.Fatalf("SOCKS route: %+v %v", socks, err)
	}
	local, err := s.Resolve(ctx, oracleUser, "local-dns")
	if err != nil || local.Proxy == nil || local.Proxy.RemoteDNS {
		t.Fatalf("remote_dns false must resolve locally: %+v %v", local, err)
	}
	// Password sign-in at the jump host and a SOCKS5 login: the hops carry
	// no secret, the terminal adds it from the request.
	pj, err := s.Resolve(ctx, oracleUser, "pw-jump")
	if err != nil || len(pj.Jumps) != 1 || pj.Jumps[0] != (client.Hop{Host: "b.example", Port: 22, User: "j"}) {
		t.Fatalf("password jump host: %+v %v", pj, err)
	}
	ls, err := s.Resolve(ctx, oracleUser, "login-socks")
	if err != nil || ls.Proxy == nil || ls.Proxy.Username == "" || ls.Proxy.Password != "" {
		t.Fatalf("SOCKS5 login: %+v %v", ls, err)
	}
	tmux, err := s.Resolve(ctx, oracleUser, "tmux")
	if err != nil || !tmux.Display.UseTmux || !tmux.Display.StartupCommand || tmux.Hop.Port != 22 {
		t.Fatalf("display flags: %+v %v", tmux, err)
	}
	for id, want := range map[string]fault.Code{
		"umlaut": fault.ValidationError, "ts": fault.NotAvailableInPreview, "gw": fault.NotAvailableInPreview,
		"missing": fault.NotFound,
	} {
		if _, err := s.Resolve(ctx, oracleUser, id); code(err) != want {
			t.Errorf("Resolve(%s): %v, want %s", id, err, want)
		}
	}
	// The connect path of the Python release refuses names outside ASCII
	// with the format error (_validate_ssh_params).
	if _, err := s.Resolve(ctx, oracleUser, "umlaut"); err == nil || !strings.Contains(err.Error(), "Invalid host format") {
		t.Errorf("umlaut host: %v, want the format refusal", err)
	}
}

func equalTarget(a, b client.Target) bool {
	return a.Owner == b.Owner && a.Hop == b.Hop && slices.Equal(a.Jumps, b.Jumps) && a.Display == b.Display &&
		(a.Proxy == nil) == (b.Proxy == nil) && (a.Proxy == nil || *a.Proxy == *b.Proxy)
}

func TestSSHTargets(t *testing.T) {
	s := seeded(t, Legacy{})
	got, err := s.SSHTargets(t.Context(), oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 14 || got[0] != (Endpoint{ID: "c11ae780-b6eb-4dac-a794-d27d0b23f255", Name: "Password server", Kind: "ssh", Host: "pw.golden.test", Port: 22}) ||
		got[13] != (Endpoint{ID: "2735737b-d93a-4e54-acd5-85b740b63526", Name: "Golden bastion", Kind: "jump", Host: "bastion.golden.test", Port: 22}) {
		t.Fatalf("targets: %+v", got)
	}
	if got[10].ID != "syn-order-b" || got[10].Port != 22 {
		t.Fatalf("a host without port must report 22: %+v", got[10])
	}
}

func TestPersistentSessionsBlockSOCKSDeletion(t *testing.T) {
	s := seeded(t, Legacy{})
	s.Persistent = persistentFake{count: 21, labels: slices.Repeat([]string{"dev@box"}, 21)}
	err := s.DeleteSOCKSProxy(t.Context(), oracleUser, v(`"ae5c7232-6f7d-4457-bfca-0cc84e323aeb"`))
	fe, ok := fault.From(err)
	if !ok || fe.Message != "SOCKS proxy is used by 21 persistent sessions" || len(fe.Details["usages"].([]string)) != 20 {
		t.Fatalf("persistent session refusal: %#v", err)
	}
}

type persistentFake struct {
	count  int
	labels []string
}

func (p persistentFake) UsingSOCKSProxy(context.Context, int64, string) (int, []string, error) {
	return p.count, p.labels, nil
}

func TestRoutesNeedAPrincipalAndAreCatalogued(t *testing.T) {
	s := seeded(t, Legacy{})
	for _, r := range s.Routes() {
		m, ok := protocol.Lookup(r.Type)
		if !ok || m.Owner != "internal/hosts" || m.Dir != protocol.ClientRequest {
			t.Errorf("%s is not a hosts request of the catalog", r.Type)
		}
		mutates := !strings.HasSuffix(r.Type, ".list")
		if r.Spec.Mutates != mutates || (r.Spec.RateKey != "") != mutates {
			t.Errorf("%s: Mutates %v RateKey %q", r.Type, r.Spec.Mutates, r.Spec.RateKey)
		}
		if _, err := r.Run(context.Background(), noPrincipalPeer{protocoltest.NewPeer(t, principal.Principal{})}, nil); code(err) != fault.AuthenticationNeeded {
			t.Errorf("%s without principal: %v", r.Type, err)
		}
	}
}

// noPrincipalPeer is a connection without a signed-in user, which the
// edge never creates; the handlers must still fail closed.
type noPrincipalPeer struct{ *protocoltest.Peer }

func (noPrincipalPeer) Principal() principal.Principal { return principal.Principal{} }

func TestStoredRecordDamageIsReported(t *testing.T) {
	s := seeded(t, Legacy{})
	if err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE hosts_profiles SET field_order = '["id","id"]' WHERE position = 0`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Profiles(t.Context(), oracleUser); code(err) != fault.StorageError {
		t.Fatalf("damaged field order: %v", err)
	}
}

func TestImportRefusesInvalidRecords(t *testing.T) {
	db := storetest.Open(t, Schema())
	for name, in := range map[string]Legacy{
		"tailscale_authorized": {Profiles: []jsontext.Value{v(`{"id":"a","name":"n","tailscale_authorized":true}`)}},
		"port type":            {Profiles: []jsontext.Value{v(`{"id":"a","name":"n","port":"22"}`)}},
		"duplicate member":     {Profiles: []jsontext.Value{v(`{"id":"a","name":"n","id":"b"}`)}},
		"jump without port":    {JumpHosts: []jsontext.Value{v(`{"id":"a","name":"n","host":"h","username":"u","auth_type":"key"}`)}},
		"socks extra field":    {SOCKSProxies: []jsontext.Value{v(`{"id":"a","name":"n","host":"h.example","port":1,"username":"","auth_type":"none","remote_dns":true,"created_at":"x","more":1}`)}},
		"socks duplicate id": {SOCKSProxies: []jsontext.Value{
			v(`{"id":"a","name":"n","host":"h.example","port":1,"username":"","auth_type":"none","remote_dns":true,"created_at":"x"}`),
			v(`{"id":"a","name":"n","host":"h.example","port":1,"username":"","auth_type":"none","remote_dns":true,"created_at":"x"}`)}},
		"presets": {WorkspacePresets: v(`[{"id":"p","name":"n","layout":3,"profile_ids":[]}]`)},
	} {
		err := db.Write(t.Context(), func(tx *store.Tx) error {
			_, err := Import(t.Context(), tx, 1, in, DefaultLimits)
			return err
		})
		if !errors.Is(err, ErrInvalidLegacy) {
			t.Errorf("%s: %v, want ErrInvalidLegacy", name, err)
		}
	}
	var report ImportReport
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		var err error
		report, err = Import(t.Context(), tx, 1, Legacy{Profiles: []jsontext.Value{
			v(`{"id":"u","name":"n","host":"bücher.example","username":"u","auth_type":"password"}`)}}, Limits{ProfileMaxRecords: 0})
		return err
	})
	if err != nil || !slices.Equal(report.OverLimit, []string{"profiles"}) {
		t.Fatalf("report %+v, %v", report, err)
	}
}

func TestWorkspacePresets(t *testing.T) {
	s := seeded(t, Legacy{})
	ctx := t.Context()
	got, err := s.WorkspacePresets(ctx, oracleUser)
	if err != nil || string(got) != "[]" {
		t.Fatalf("no presets: %s %v", got, err)
	}
	presets := v(`[{"id":"p1","name":"Pair","layout":2,"profile_ids":["c11ae780-b6eb-4dac-a794-d27d0b23f255","syn-free"]}]`)
	if got, err = s.SaveWorkspacePresets(ctx, oracleUser, presets); err != nil || string(got) != string(presets) {
		t.Fatalf("save: %s %v", got, err)
	}
	if err := s.DeleteProfile(ctx, oracleUser, v(`"syn-free"`)); err != nil {
		t.Fatal(err)
	}
	// A deleted host the preset already named does not block saving.
	renamed := v(`[{"id":"p1","name":"Renamed","layout":2,"profile_ids":["c11ae780-b6eb-4dac-a794-d27d0b23f255","syn-free"]}]`)
	if _, err := s.SaveWorkspacePresets(ctx, oracleUser, renamed); err != nil {
		t.Fatalf("keeping a deleted host: %v", err)
	}
	foreign := v(`[{"id":"p2","name":"Other","layout":1,"profile_ids":["syn-free"]}]`)
	if _, err := s.SaveWorkspacePresets(ctx, oracleUser, foreign); err == nil || !strings.Contains(err.Error(), "Choose existing hosts") {
		t.Fatalf("a host the user does not have: %v", err)
	}
	if _, err := s.SaveWorkspacePresets(ctx, 4, presets); err == nil {
		t.Fatal("another user's hosts accepted")
	}
	if _, err := s.SaveWorkspacePresets(ctx, oracleUser, v(`{"presets":[]}`)); code(err) != fault.InvalidValue {
		t.Fatalf("invalid presets: %v", err)
	}
}

func FuzzRecordRoundTrip(f *testing.F) {
	f.Add([]byte(`{"a":"Ü\/","n":1.50e3,"l":[1,{"z":null}],"big":123456789012345678901234567890}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := parseRecord(jsontext.Value(data))
		if err != nil {
			return
		}
		again, err := parseRecord(r.encode())
		if err != nil {
			t.Fatalf("encoded record does not parse: %v", err)
		}
		if string(again.encode()) != string(r.encode()) {
			t.Fatalf("not stable: %s vs %s", again.encode(), r.encode())
		}
		var a, b any
		if json.Unmarshal(data, &a) == nil && json.Unmarshal(r.encode(), &b) == nil && !jsonEqual(a, b) {
			t.Fatalf("value changed: %s -> %s", data, r.encode())
		}
	})
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a, json.Deterministic(true))
	y, _ := json.Marshal(b, json.Deterministic(true))
	return string(x) == string(y)
}

func FuzzProfilePayload(f *testing.F) {
	f.Add(`{"name":"n","host":"h.example","port":"22","username":"u","auth_type":"password","group":" G "}`)
	f.Add(`{"name":"n","host":"::1","port":1e3,"username":"u","auth_type":"key","key_id":null}`)
	f.Fuzz(func(t *testing.T, body string) {
		var req protocol.HostsProfileSave
		if protocol.DecodePayload(jsontext.Value(body), &req) != nil {
			return
		}
		d, err := validateProfile(profilePayload(req), nil)
		if err != nil {
			if _, ok := fault.From(err); !ok {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		host, _ := d.rec.str("host")
		port, _ := d.rec.get("port")
		n, ok := asInt(port)
		if !validHost(host) || !ok || n < 1 || n > 65535 {
			t.Fatalf("accepted %s as %s", body, d.rec.encode())
		}
	})
}
