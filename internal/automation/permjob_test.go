package automation

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

func (e *permEnv) prepare(t *testing.T, recursive bool, paths ...string) string {
	t.Helper()
	st, err := e.j.Prepare(t.Context(), e.c, PermRequest{SourceID: src, Paths: paths, Recursive: recursive, FileMode: "640", DirMode: "750"})
	if err != nil {
		t.Fatal(err)
	}
	return jsonMember(st, "job_id")
}

func TestPermissionJobRecursivePlanKeepsModesSeparate(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	delete(e.tree.nodes, "/work/setuid")
	id := e.prepare(t, true, "/work", "/work/sub")
	st := e.wait(t, id, permReady, permFailed)
	if jsonMember(st, "state") != permReady || num(st, "files") != "3" || num(st, "directories") != "2" || num(st, "skipped") != "1" || num(st, "total") != "5" {
		t.Fatalf("preview %s", st)
	}
	if !strings.Contains(string(st), `"current_modes":{"files":{"600":2,"644":1},"directories":{"700":1,"755":1}}`) {
		t.Fatalf("current modes %s", st)
	}
	if num(st, "expires_in") != "120" || len(e.tree.chmods) != 0 {
		t.Fatalf("a preview changed something: %s %v", st, e.tree.chmods)
	}
	if _, err := e.j.Apply(t.Context(), e.c, src, id); err != nil {
		t.Fatal(err)
	}
	st = e.wait(t, id, permCompleted, permFailed)
	if jsonMember(st, "state") != permCompleted || num(st, "changed") != "5" || num(st, "processed") != "5" {
		t.Fatalf("apply %s", st)
	}
	for p, want := range map[string]uint32{"/work/a.txt": 0o640, "/work/b.txt": 0o640, "/work/sub/c.txt": 0o640,
		"/work/sub": 0o750, "/work": 0o750, "/work/link": 0o777} {
		if got := e.tree.mode(p); got != want {
			t.Errorf("%s: %o, want %o", p, got, want)
		}
	}
	// Files first, then directories from the deepest up.
	if want := []string{"/work/a.txt", "/work/b.txt", "/work/sub/c.txt", "/work/sub", "/work"}; !slices.Equal(e.tree.chmods, want) {
		t.Fatalf("order %v", e.tree.chmods)
	}
	// Applying twice is refused.
	_, err := e.j.Apply(t.Context(), e.c, src, id)
	wantCode(t, err, fault.FileConflict)
	if !slices.Contains(e.audit.events, "chmod COMPLETED /work/sub 700>750") || !slices.Contains(e.audit.events, "chmod_job completed / >") {
		t.Fatalf("audit %v", e.audit.events)
	}
}

func TestPermissionJobRefusals(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	for _, rq := range []PermRequest{
		{SourceID: src, Paths: []string{"/work"}, FileMode: "0640", DirMode: "750"},
		{SourceID: src, Paths: []string{"/work"}, FileMode: "64x", DirMode: "750"},
		{SourceID: src, Paths: []string{"/work/../etc"}, FileMode: "640", DirMode: "750"},
		{SourceID: src, Paths: []string{"/"}, FileMode: "640", DirMode: "750"},
		{SourceID: src, Paths: nil, FileMode: "640", DirMode: "750"},
		{SourceID: src, Paths: []string{"/" + strings.Repeat("d/", PermMaxDepth+1)}, FileMode: "640", DirMode: "750"},
	} {
		_, err := e.j.Prepare(t.Context(), e.c, rq)
		wantCode(t, err, fault.InvalidRequest)
	}
	// Another user, or the switch off: no job.
	other := PermCaller{P: principal.Principal{UserID: 6, SessionID: "x"}, Peer: 9}
	_, err := e.j.Prepare(t.Context(), other, PermRequest{SourceID: src, Paths: []string{"/work"}, FileMode: "640", DirMode: "750"})
	wantCode(t, err, fault.SourceUnavailable)
	e.tree.enabled = false
	_, err = e.j.Prepare(t.Context(), e.c, PermRequest{SourceID: src, Paths: []string{"/work"}, FileMode: "640", DirMode: "750"})
	wantCode(t, err, fault.UnsupportedOperation)
}

func TestPermissionJobRefusesSpecialBitsAndChangedState(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	id := e.prepare(t, true, "/work")
	st := e.wait(t, id, permReady, permFailed)
	if jsonMember(st, "state") != permFailed || jsonMember(st, "code") != string(fault.UnsupportedOperation) {
		t.Fatalf("set-id file: %s", st)
	}
	delete(e.tree.nodes, "/work/setuid")
	id = e.prepare(t, true, "/work")
	e.wait(t, id, permReady)
	e.tree.set("/work/sub/c.txt", 0o100604) // changed after the preview
	if _, err := e.j.Apply(t.Context(), e.c, src, id); err != nil {
		t.Fatal(err)
	}
	st = e.wait(t, id, permCompleted, permFailed)
	if jsonMember(st, "code") != string(fault.MetadataChanged) || len(e.tree.chmods) != 0 {
		t.Fatalf("changed object: %s %v", st, e.tree.chmods)
	}
}

func TestPermissionJobStopsAtFirstChangeDuringApply(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	delete(e.tree.nodes, "/work/setuid")
	e.tree.onChmod = func(p string) {
		if p == "/work/a.txt" {
			e.tree.set("/work/sub", 0o040777) // a parent of a later object
		}
	}
	id := e.prepare(t, true, "/work")
	e.wait(t, id, permReady)
	if _, err := e.j.Apply(t.Context(), e.c, src, id); err != nil {
		t.Fatal(err)
	}
	st := e.wait(t, id, permCompleted, permFailed)
	if jsonMember(st, "state") != permFailed || jsonMember(st, "code") != string(fault.MetadataChanged) || num(st, "changed") != "2" {
		t.Fatalf("%s", st)
	}
	// Completed changes remain; nothing is retried.
	if !slices.Equal(e.tree.chmods, []string{"/work/a.txt", "/work/b.txt"}) || e.tree.mode("/work/a.txt") != 0o640 {
		t.Fatalf("chmods %v", e.tree.chmods)
	}
}

func TestPermissionJobUnknownOutcome(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	e.tree.failAt = "/other/f"
	id := e.prepare(t, false, "/other/f")
	e.wait(t, id, permReady)
	if _, err := e.j.Apply(t.Context(), e.c, src, id); err != nil {
		t.Fatal(err)
	}
	if st := e.wait(t, id, permCompleted, permFailed); jsonMember(st, "code") != string(fault.OutcomeUnknown) {
		t.Fatalf("%s", st)
	}
}

func TestPermissionJobOwnershipConflictAndExpiry(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	id := e.prepare(t, false, "/other/f")
	e.wait(t, id, permReady)
	_, err := e.j.Prepare(t.Context(), e.c, PermRequest{SourceID: src, Paths: []string{"/work/a.txt"}, FileMode: "640", DirMode: "750"})
	wantCode(t, err, fault.FileConflict)
	otherPeer := e.c
	otherPeer.Peer = 2
	_, err = e.j.Get(t.Context(), otherPeer, src, id)
	wantCode(t, err, fault.FileNotFound)
	_, err = e.j.Apply(t.Context(), otherPeer, src, id)
	wantCode(t, err, fault.FileNotFound)
	e.clock.set(e.clock.now().Add(PermPreviewTTL + time.Second))
	st, err := e.j.Get(t.Context(), e.c, src, id)
	if err != nil || jsonMember(st, "state") != permCancelled || jsonMember(st, "code") != string(fault.FileExpired) {
		t.Fatalf("expiry %s %v", st, err)
	}
	_, err = e.j.Apply(t.Context(), e.c, src, id)
	wantCode(t, err, fault.FileConflict)
	if len(e.tree.chmods) != 0 {
		t.Fatal("an expired plan changed something")
	}
}

func TestPermissionJobReopenedSourceAndCancel(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	id := e.prepare(t, false, "/other/f")
	e.wait(t, id, permReady)
	e.tree.mu.Lock()
	e.tree.ident++
	e.tree.mu.Unlock()
	_, err := e.j.Apply(t.Context(), e.c, src, id)
	wantCode(t, err, fault.MetadataChanged)
	st, err := e.j.Cancel(t.Context(), e.c, src, id)
	if err != nil || jsonMember(st, "state") != permCancelled {
		t.Fatalf("cancel %s %v", st, err)
	}
	_, err = e.j.Apply(t.Context(), e.c, src, id)
	wantCode(t, err, fault.FileConflict)
}

func TestPermissionJobStopsWithItsConnectionAndSession(t *testing.T) {
	t.Parallel()
	for name, stop := range map[string]func(e *permEnv){
		"connection": func(e *permEnv) { e.j.PeerClosed(5, 1) },
		"session":    func(e *permEnv) { e.j.Revoke(principal.Revocation{UserID: 5, SessionID: e.c.P.SessionID}) },
		"account":    func(e *permEnv) { e.j.Revoke(principal.Revocation{UserID: 5}) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newPermEnv(t)
			block := make(chan struct{})
			e.tree.block = block
			st, err := e.j.Prepare(t.Context(), e.c, PermRequest{SourceID: src, Paths: []string{"/other"}, Recursive: true, FileMode: "640", DirMode: "750"})
			if err != nil {
				t.Fatal(err)
			}
			stop(e)
			e.tree.mu.Lock()
			e.tree.block = nil
			e.tree.mu.Unlock()
			close(block)
			if st := e.wait(t, jsonMember(st, "job_id"), permCancelled, permFailed, permReady); jsonMember(st, "state") != permCancelled {
				t.Fatalf("%s", st)
			}
		})
	}
}

func TestPermissionSingleChangeNeedsTheInspectedState(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	ctx := context.Background()
	got, err := e.j.Inspect(ctx, e.c, src, "/work/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if jsonMember(got, "mode") != "600" || jsonMember(got, "object_type") != "file" || num(got, "uid") != "1000" || jsonMember(got, "path") != "/work/a.txt" {
		t.Fatalf("inspect %s", got)
	}
	token := jsonMember(got, "metadata_token")
	// Forged and foreign tokens are refused.
	_, err = e.j.Change(ctx, e.c, src, "/work/a.txt", "640", strings.Repeat("1", 10)+"."+strings.Repeat("a", 64)+"."+strings.Repeat("b", 64))
	wantCode(t, err, fault.MetadataChanged)
	_, err = e.j.Change(ctx, e.c, src, "/work/b.txt", "640", token)
	wantCode(t, err, fault.MetadataChanged)
	_, err = e.j.Change(ctx, e.c, src, "/work/a.txt", "6400", token)
	wantCode(t, err, fault.InvalidRequest)
	out, err := e.j.Change(ctx, e.c, src, "/work/a.txt", "640", token)
	if err != nil || jsonMember(out, "mode") != "640" || jsonMember(out, "old_mode") != "600" || e.tree.mode("/work/a.txt") != 0o640 {
		t.Fatalf("change %s %v", out, err)
	}
	// The state changed with the change: the old token is spent.
	_, err = e.j.Change(ctx, e.c, src, "/work/a.txt", "600", token)
	wantCode(t, err, fault.MetadataChanged)
	// Tokens expire after a minute.
	got, _ = e.j.Inspect(ctx, e.c, src, "/work/b.txt")
	e.clock.set(e.clock.now().Add(permMetadataTTL + time.Second))
	_, err = e.j.Change(ctx, e.c, src, "/work/b.txt", "640", jsonMember(got, "metadata_token"))
	wantCode(t, err, fault.MetadataChanged)
	// Set-id bits are refused; links and other objects are not inspected.
	got, _ = e.j.Inspect(ctx, e.c, src, "/work/setuid")
	_, err = e.j.Change(ctx, e.c, src, "/work/setuid", "755", jsonMember(got, "metadata_token"))
	wantCode(t, err, fault.UnsupportedOperation)
	_, err = e.j.Inspect(ctx, e.c, src, "/work/link")
	wantCode(t, err, fault.UnsupportedOperation)
	if !slices.Contains(e.audit.events, "chmod COMPLETED /work/a.txt 600>640") {
		t.Fatalf("audit %v", e.audit.events)
	}
}
