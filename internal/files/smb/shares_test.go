package smb

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func TestShareStore(t *testing.T) {
	db := storetest.Open(t, Schema())
	now := time.Date(2026, 11, 27, 10, 0, 0, 5000, time.UTC)
	s := &Shares{DB: db, Max: 2, Now: func() time.Time { return now }}
	ctx := t.Context()
	v := func(s string) jsontext.Value { return jsontext.Value(s) }
	rec, err := s.Save(ctx, 1, SaveRequest{Name: v(`" NAS "`), Host: v(`"NAS.Example."`), Share: v(`"Data"`), Username: v(`"alice"`)})
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(rec)
	want := `{"name":"NAS","host":"nas.example","share":"Data","domain":"","username":"alice","id":"` + id +
		`","created_at":"2026-11-27T10:00:00.000005+00:00","updated_at":"2026-11-27T10:00:00.000005+00:00"}`
	if string(rec) != want || len(id) != 32 {
		t.Fatalf("record %s", rec)
	}
	_, err = s.Save(ctx, 1, SaveRequest{Name: v(`"nas"`), Host: v(`"h"`), Share: v(`"S"`), Username: v(`"u"`)})
	if fe, _ := fault.From(err); fe == nil || fe.Message != "An SMB share with this name already exists" {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := s.Save(ctx, 2, SaveRequest{Name: v(`"nas"`), Host: v(`"h"`), Share: v(`"S"`), Username: v(`"u"`)}); err != nil {
		t.Fatalf("other user: %v", err)
	}
	if _, err := s.Save(ctx, 1, SaveRequest{Name: v(`"B"`), Host: v(`"h"`), Share: v(`"S"`), Username: v(`"u"`)}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Save(ctx, 1, SaveRequest{Name: v(`"C"`), Host: v(`"h"`), Share: v(`"S"`), Username: v(`"u"`)})
	if fe, _ := fault.From(err); fe == nil || fe.Message != "Saved SMB share limit reached" {
		t.Fatalf("limit: %v", err)
	}
	// An imported record with an unknown member keeps it on update.
	if err := db.Write(ctx, func(tx *storeTx) error {
		recs, _ := SharesTx(ctx, tx, 1)
		recs[0] = jsontext.Value(`{"legacy":1,` + string(recs[0][1:]))
		return ImportTx(ctx, tx, 1, recs)
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour).Truncate(time.Second)
	upd, err := s.Save(ctx, 1, SaveRequest{ID: v(`"` + id + `"`), Name: v(`"NAS"`), Host: v(`"10.0.0.5"`), Share: v(`"Data"`),
		Domain: v(`"LAB"`), Username: v(`"alice"`)})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"legacy":1,"name":"NAS","host":"10.0.0.5","share":"Data","domain":"LAB","username":"alice","id":"` + id +
		`","created_at":"2026-11-27T10:00:00.000005+00:00","updated_at":"2026-11-27T11:00:00+00:00"}`
	if string(upd) != want {
		t.Fatalf("update\n got %s\nwant %s", upd, want)
	}
	if _, err := s.Save(ctx, 1, SaveRequest{ID: v(`"missing"`), Name: v(`"X"`), Host: v(`"h"`), Share: v(`"S"`), Username: v(`"u"`)}); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("unknown id: %v", err)
	}
	if err := s.Delete(ctx, 1, id); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.Delete(ctx, 1, id), fault.NotFound)
	recs, _ := s.List(ctx, 1)
	if len(recs) != 1 || !strings.Contains(string(recs[0]), `"name":"B"`) {
		t.Fatalf("after delete %s", recs)
	}
	if err := db.Write(ctx, func(tx *storeTx) error {
		return ImportTx(ctx, tx, 1, []jsontext.Value{jsontext.Value(`{"id":"x","name":"n","host":"h","share":"s","username":"u","created_at":"t","updated_at":"t","password":"p"}`)})
	}); !errors.Is(err, ErrInvalidLegacy) {
		t.Fatalf("secret member imported: %v", err)
	}
}

func TestRealtimeShares(t *testing.T) {
	db := storetest.Open(t, Schema())
	svc := &Service{Shares: &Shares{DB: db}, Config: unitConfig(&countingNetwork{}, nil)}
	peer := protocoltest.NewPeer(t, principal.Principal{UserID: 7, SessionID: "s"})
	routes := map[string]protocol.Route{}
	for _, r := range svc.Routes() {
		routes[r.Type] = r
	}
	call := func(typ, payload string) (any, error) {
		ctx := principal.With(t.Context(), peer.Principal())
		return routes[typ].Run(ctx, peer, jsontext.Value(payload))
	}
	if _, err := call(protocol.TypeSMBShareSave, `{"name":"N","host":"h","share":"S","username":"u"}`); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("missing request id: %v", err)
	}
	if _, err := call(protocol.TypeSMBShareSave, `{"request_id":"r1","name":"N","host":"h","share":"S","username":"u","password":"p"}`); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("password member: %v", err)
	}
	res, err := call(protocol.TypeSMBShareSave, `{"request_id":"r1","name":"N","host":"h","share":"S","username":"u"}`)
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(res.(protocol.SMBShareSaved).Share)
	list, err := call(protocol.TypeSMBShareList, `{}`)
	if err != nil || len(list.(protocol.SMBShares).SMBShares) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	if _, err := call(protocol.TypeSMBShareDelete, `{"request_id":"r2","share_id":""}`); fault.CodeOf(err) != fault.ValidationError {
		t.Fatalf("empty id: %v", err)
	}
	if res, err := call(protocol.TypeSMBShareDelete, `{"request_id":"r2","share_id":"`+id+`"}`); err != nil || res.(protocol.SMBShareDeleted).ShareID != id {
		t.Fatalf("delete %v %v", res, err)
	}
	for _, r := range svc.Routes() {
		mutates := r.Type == protocol.TypeSMBShareSave || r.Type == protocol.TypeSMBShareDelete || r.Type == protocol.TypeSMBConnect
		if r.Spec.Mutates != mutates {
			t.Errorf("%s: Mutates %v", r.Type, r.Spec.Mutates)
		}
	}
	if !routes[protocol.TypeSMBConnect].Spec.Async || routes[protocol.TypeSMBConnect].Spec.RateKey != RateConnect {
		t.Error("connect spec")
	}
}

func TestRealtimeConnectFailures(t *testing.T) {
	svc := &Service{Config: unitConfig(&countingNetwork{}, nil)}
	peer := protocoltest.NewPeer(t, principal.Principal{UserID: 7, SessionID: "s"})
	route := svc.Routes()[3]
	run := func(payload string) error {
		_, err := route.Run(principal.With(t.Context(), peer.Principal()), peer, jsontext.Value(payload))
		return err
	}
	wantCode(t, run(`{"host":"nas.example","share":"Data","username":"u","password":"p"}`), fault.InvalidRequest)
	wantCode(t, run(`{"request_id":"r","host":"nas.example","share":"Data","username":"u","password":"p","credential_id":"c"}`), fault.InvalidRequest)
	wantCode(t, run(`{"request_id":"r","host":"nas.example","share":"Data","username":"u"}`), fault.InvalidRequest)
	// Without the file source registry nothing is dialled.
	err := run(`{"request_id":"r","host":"nas.example","share":"Data","username":"u","password":"p"}`)
	wantCode(t, err, fault.SMBConnectionFailed)
	fe, _ := fault.From(err)
	if id, _ := fe.Details["diagnostic_id"].(string); len(id) != 16 || !strings.HasPrefix(id, "SMB-") || strings.ToUpper(id) != id {
		t.Errorf("diagnostic id %v", fe.Details)
	}
	svc.Sources = rejectSources{}
	err = run(`{"request_id":"r","host":"nas.example","share":"Data","username":"u","credential_id":"c"}`)
	wantCode(t, err, fault.CredentialUnavailable)
	// The quota is taken before the target is resolved, as in the Python pool.
	err = run(`{"request_id":"r","host":"evil.example","share":"Data","username":"u","password":"p"}`)
	wantCode(t, err, fault.SMBQuotaExceeded)
	svc.Sources = files.NewRegistry(files.RegistryOptions{})
	err = run(`{"request_id":"r","host":"evil.example","share":"Data","username":"u","password":"p"}`)
	wantCode(t, err, fault.SMBTargetNotAllowed)
}

func TestConnectAttemptsAreExclusiveAndCancellable(t *testing.T) {
	svc := &Service{}
	key := attemptKey{1, 2, "r"}
	ctx, done, err := svc.begin(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.begin(t.Context(), key); fault.CodeOf(err) != fault.Busy {
		t.Fatalf("second attempt: %v", err)
	}
	svc.Cancel(1, 3, "r") // another connection: no effect
	if ctx.Err() != nil {
		t.Fatal("cancelled by another connection")
	}
	svc.Cancel(1, 2, "r")
	if ctx.Err() == nil {
		t.Fatal("not cancelled")
	}
	done()
	if _, done2, err := svc.begin(t.Context(), key); err != nil {
		t.Fatal(err)
	} else {
		done2()
	}
}

type rejectSources struct{}

func (rejectSources) Reserve(context.Context, principal.Principal, files.SourceKind) (*files.Slot, error) {
	return nil, fault.New(fault.Busy, "quick_connection quota exceeded (per_user limit 3)")
}
