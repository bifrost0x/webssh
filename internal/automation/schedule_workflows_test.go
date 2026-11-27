package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// The run side of the schedules: a review freezes the targets in the
// form of the Python grant, an approval holds while nothing changed, and
// every change of the runbook, a target, its jump host or a key ends it
// (preview_changed), as _validate_snapshot of the Python release.
func TestWorkflowsReviewAndCurrent(t *testing.T) {
	w := newWorld()
	svc, _ := newService(t, w)
	ctx := t.Context()
	b, err := svc.SaveRunbook(ctx, owner, jsontext.Value(`{"name":"Check","steps":[{"name":"one","command":"first"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	wf := svc.Workflows()
	p := principal.Principal{UserID: owner, SessionID: "s"}
	snap, err := wf.Review(ctx, p, jsontext.Value(`{"runbook_id":"`+b.ID+`","profile_ids":["p1","p2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Targets) != 2 || jsonMember(snap.Targets[1], "id") != "p2" || routeOf(snap.Targets[1]) == nil ||
		jsonMember(routeOf(snap.Targets[1]), "kind") != "jump" || snap.KeyDigests["p1"] == "" || snap.KeyDigests["jump:j1"] == "" {
		t.Fatalf("snapshot %+v", snap)
	}
	if _, ok := pyjson.Get(snap.Targets[1], "route_fingerprint"); !ok {
		t.Fatal("the target behind the jump host has no route_fingerprint")
	}
	if err := wf.Current(ctx, owner, snap); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	for name, change := range map[string]func(){
		"jump host": func() {
			w.jumps = []string{`{"id":"j1","name":"Bastion","host":"other.test","port":22,"username":"jump","auth_type":"key","key_id":"k1"}`}
		},
		"key":    func() { w.keys = map[string][]byte{"k1": []byte("public-key-2")} },
		"target": func() { w.profiles = w.profiles[1:] },
	} {
		profiles, jumps, keys := w.profiles, w.jumps, w.keys
		w.set(func(*world) { change() })
		if err := wf.Current(ctx, owner, snap); fault.CodeOf(err) != fault.PreviewChanged {
			t.Errorf("%s changed: %v", name, err)
		}
		w.set(func(w *world) { w.profiles, w.jumps, w.keys = profiles, jumps, keys })
	}
	if _, err := svc.SaveRunbook(ctx, owner, jsontext.Value(`{"id":"`+b.ID+`","name":"Check","steps":[{"name":"one","command":"other"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := wf.Current(ctx, owner, snap); fault.CodeOf(err) != fault.PreviewChanged {
		t.Errorf("runbook changed: %v", err)
	}
	// A review failure keeps its code and names the hosts.
	w.set(func(w *world) { w.trusted = map[string]bool{} })
	_, err = wf.Review(ctx, p, jsontext.Value(`{"runbook_id":"`+b.ID+`","profile_ids":["p1"]}`))
	var he hostKeyFault
	if fault.CodeOf(err) != fault.HostKeyRequired || !errors.As(err, &he) || len(he.Hosts()) != 1 {
		t.Fatalf("untrusted host: %v", err)
	}
}

// A due run starts through StartScheduled with the schedule's check and
// reports its end; a changed approval is not dispatched.
func TestWorkflowsStartScheduled(t *testing.T) {
	w := newWorld()
	svc, _ := newService(t, w)
	ctx := t.Context()
	b, err := svc.SaveRunbook(ctx, owner, jsontext.Value(`{"name":"Check","steps":[{"name":"one","command":"first"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	wf := svc.Workflows()
	snap, err := wf.Review(ctx, principal.Principal{UserID: owner, SessionID: "s"}, jsontext.Value(`{"runbook_id":"`+b.ID+`","profile_ids":["p2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan string, 1)
	run := ScheduledRun{UserID: owner, ScheduleID: "sch", ClaimID: "claim-1", Snapshot: snap,
		Check:  func(context.Context) error { return nil },
		Finish: func(_ context.Context, status string) { finished <- status }}
	if err := wf.StartScheduled(ctx, run); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-finished:
		if s != StatusSucceeded {
			t.Fatalf("status %s", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the scheduled run did not finish")
	}
	waitQuota(t, w)
	w.set(func(w *world) { w.keys = map[string][]byte{"k1": []byte("public-key-2")} })
	run.ClaimID = "claim-2"
	err = wf.StartScheduled(ctx, run)
	var nd *NotDispatchedError
	if !errors.As(err, &nd) || nd.Code != fault.PreviewChanged {
		t.Fatalf("changed key: %v", err)
	}
}
