package files_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func TestEditOpenAndSaveKeepsEncodingAndEndings(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	raw := []byte("eins\r\nzwei\nGr\xfc\xdfe\r\n")
	f.b.PutFile("/etc/conf", raw)
	ctx := context.Background()
	c := caller(alice)
	doc, err := f.svc.OpenEdit(ctx, c, f.id, "/etc/conf")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Encoding != files.EncodingLatin1 || doc.Newline != files.NewlineMixed || doc.Text != "eins\nzwei\nGrüße\n" ||
		doc.Revision != files.Revision(raw) || string(doc.Original) != string(raw) || doc.Endpoint != "h:22" {
		t.Fatalf("open: %+v", doc)
	}
	saved, err := f.svc.Save(ctx, c, files.SaveRequest{
		SourceID: f.id, Path: "/etc/conf", Content: "eins\nneu\nzwei\nGrüße\n",
		Encoding: string(doc.Encoding), Newline: string(doc.Newline), ExpectedRevision: doc.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.b.File("/etc/conf")
	if want := "eins\r\nneu\r\nzwei\nGr\xfc\xdfe\r\n"; string(got) != want {
		t.Fatalf("saved %q, want %q", got, want)
	}
	if saved.Revision != files.Revision(got) {
		t.Fatal("revision of the saved bytes")
	}
	if a := f.audit.last(); a["operation"] != "edit_save" || a["result"] != "COMPLETED" || a["filename"] != "conf" {
		t.Fatalf("audit %v", a)
	}
	// The old revision is stale now.
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/etc/conf", Content: "x", Encoding: "latin-1", ExpectedRevision: doc.Revision})
	wantCode(t, err, fault.EditConflict)
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/etc/conf", Content: "x"})
	wantCode(t, err, fault.EditConflict)
	if got2, _ := f.b.File("/etc/conf"); string(got2) != string(got) {
		t.Fatal("stale save changed the file")
	}
	// A character Latin-1 cannot store.
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/etc/conf", Content: "ok\n€", Encoding: "latin-1", ExpectedRevision: saved.Revision})
	wantCode(t, err, fault.EditEncodingUnsupported)
	if d := fault.DetailsOf(err); d["character"] != "€" || d["line"] != 2 {
		t.Fatalf("details %v", d)
	}
}

func TestEditRefusesBinaryLargeAndBadInput(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{MaxEditorBytes: 1 << 20})
	f.b.PutFile("/bin", []byte("\x00\x01"))
	f.b.PutFile("/big", make([]byte, 1<<20+1))
	f.b.PutFile("/ok", []byte("a"))
	ctx := context.Background()
	c := caller(alice)
	_, err := f.svc.OpenEdit(ctx, c, f.id, "/bin")
	wantCode(t, err, fault.FileBinary)
	_, err = f.svc.OpenEdit(ctx, c, f.id, "/big")
	wantCode(t, err, fault.FileTooLarge)
	rev := files.Revision([]byte("a"))
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/ok", Content: strings.Repeat("x", 1<<20+1), ExpectedRevision: rev})
	wantCode(t, err, fault.FileTooLarge)
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/ok", Content: "b", ExpectedRevision: rev, Strategy: "truncate"})
	wantCode(t, err, fault.InvalidRequest)
	for _, p := range []string{"/", "rel", "/a/../ok", `/a\b`} {
		_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: p, Content: "b", ExpectedRevision: rev})
		wantCode(t, err, fault.InvalidRequest)
	}
}

func TestSaveThroughLinkKeepsLink(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	f.b.PutFile("/sites/available", []byte("old\n"))
	f.b.PutLink("/sites/enabled", "/sites/available")
	ctx := context.Background()
	doc, err := f.svc.OpenEdit(ctx, caller(alice), f.id, "/sites/enabled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Save(ctx, caller(alice), files.SaveRequest{SourceID: f.id, Path: "/sites/enabled", Content: "new\n", ExpectedRevision: doc.Revision}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.b.File("/sites/available"); string(got) != "new\n" {
		t.Fatalf("target %q", got)
	}
	if e, _ := f.b.Stat(ctx, "/sites/enabled", false); !e.IsSymlink {
		t.Fatal("link replaced")
	}
}

func TestSaveOutcomeUnknownAndChallenge(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{MaxEditorBytes: 1000, EditorBytesPerMinute: 1000})
	f.b.PutFile("/f", []byte("a"))
	rev := files.Revision([]byte("a"))
	ctx := context.Background()
	c := caller(alice)
	f.b.Fail = func(op, _ string) error {
		if op == "write" {
			return fault.New(fault.OutcomeUnknown, "")
		}
		return nil
	}
	_, err := f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/f", Content: "b", ExpectedRevision: rev})
	wantCode(t, err, fault.SaveOutcomeUnknown)

	// SMB without a safe replace: the refusal carries a challenge, and the
	// same save with recoverable_swap is not charged again.
	f.b.Fail = func(op, _ string) error {
		if op == "write" {
			return fault.New(fault.SMBRecoverableReplaceNeed, "")
		}
		return nil
	}
	body := strings.Repeat("y", 600)
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/f", Content: body, ExpectedRevision: rev})
	wantCode(t, err, fault.SMBRecoverableReplaceNeed)
	token, _ := fault.DetailsOf(err)["save_challenge"].(string)
	if len(token) < 32 {
		t.Fatalf("no challenge: %v", fault.DetailsOf(err))
	}
	f.b.Fail = nil
	f.b.SetCapabilities(files.Capabilities{Ops: files.CapAll, Replace: []files.Strategy{files.StrategyRecoverableSwap}})
	other := files.SaveRequest{SourceID: f.id, Path: "/f", Content: body + "z", ExpectedRevision: rev, Strategy: "recoverable_swap", Challenge: token}
	if _, err := f.svc.Save(ctx, c, other); !fault.Is(err, fault.RateLimited) {
		t.Fatalf("challenge for another body exempted the budget: %v", err)
	}
	// The token was spent by the wrong body; a fresh one is needed.
	f.b.SetCapabilities(files.Capabilities{Ops: files.CapAll, Replace: []files.Strategy{files.StrategyAtomic}})
	*f.now = f.now.Add(2 * 60e9)
	f.b.Fail = func(op, _ string) error {
		if op == "write" {
			return fault.New(fault.SMBRecoverableReplaceNeed, "")
		}
		return nil
	}
	_, err = f.svc.Save(ctx, c, files.SaveRequest{SourceID: f.id, Path: "/f", Content: body, ExpectedRevision: rev})
	token, _ = fault.DetailsOf(err)["save_challenge"].(string)
	f.b.Fail = nil
	f.b.SetCapabilities(files.Capabilities{Ops: files.CapAll, Replace: []files.Strategy{files.StrategyRecoverableSwap}})
	retry := files.SaveRequest{SourceID: f.id, Path: "/f", Content: body, ExpectedRevision: rev, Strategy: "recoverable_swap", Challenge: token}
	if _, err := f.svc.Save(ctx, c, retry); err != nil {
		t.Fatalf("challenged retry: %v", err)
	}
	if a := f.audit.last(); a["result"] != "RECOVERABLE_REPLACE_COMPLETED" {
		t.Fatalf("audit %v", a)
	}
	// Spent once.
	f.b.PutFile("/f", []byte("a"))
	if _, err := f.svc.Save(ctx, c, retry); !fault.Is(err, fault.RateLimited) {
		t.Fatalf("challenge reused: %v", err)
	}
}

func TestMutations(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	f.b.PutFile("/home/a.txt", []byte("a"))
	f.b.PutFile("/home/b.txt", []byte("b"))
	f.b.PutFile("/home/dir/x", []byte("x"))
	ctx := context.Background()
	c := caller(alice)
	if _, err := f.svc.Mkdir(ctx, c, f.id, "/home/new"); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Mkdir(ctx, c, f.id, "/home/new")
	wantCode(t, err, fault.FileConflict)
	if p, err := f.svc.CreateFile(ctx, c, f.id, "/home", "c.txt"); err != nil || p != "/home/c.txt" {
		t.Fatalf("create: %q %v", p, err)
	}
	_, err = f.svc.CreateFile(ctx, c, f.id, "/home", "a.txt")
	wantCode(t, err, fault.FileConflict)
	if got, _ := f.b.File("/home/a.txt"); string(got) != "a" {
		t.Fatal("create replaced a file")
	}
	for _, name := range []string{"", "..", "a/b", "  ", "x\x01"} {
		_, err := f.svc.CreateFile(ctx, c, f.id, "/home", name)
		wantCode(t, err, fault.InvalidRequest)
	}
	// Rename never replaces and never moves into itself.
	wantCode(t, f.svc.Rename(ctx, c, f.id, "/home/a.txt", "/home/b.txt"), fault.FileConflict)
	wantCode(t, f.svc.Rename(ctx, c, f.id, "/home/dir", "/home/dir/sub"), fault.InvalidRequest)
	wantCode(t, f.svc.Rename(ctx, c, f.id, "/home/dir", "/home/dir"), fault.InvalidRequest)
	wantCode(t, f.svc.Rename(ctx, c, f.id, "/", "/x"), fault.InvalidRequest)
	wantCode(t, f.svc.Rename(ctx, c, f.id, "/home/a.txt", "/home/ "), fault.InvalidRequest)
	if err := f.svc.Rename(ctx, c, f.id, "/home/a.txt", "/home/dir/a.txt"); err != nil {
		t.Fatal(err)
	}
	if a := f.audit.last(); a["operation"] != "rename" || a["destination_filename"] != "a.txt" {
		t.Fatalf("audit %v", a)
	}
	if err := f.svc.Delete(ctx, c, f.id, "/home/dir"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.b.File("/home/dir/x"); ok {
		t.Fatal("recursive delete left a file")
	}
	wantCode(t, f.svc.Delete(ctx, c, f.id, "/"), fault.InvalidRequest)
	wantCode(t, f.svc.Delete(ctx, c, f.id, "//home"), fault.InvalidRequest)
}

func TestRenameCaseInsensitive(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{})
	f.b.SetCapabilities(files.Capabilities{Ops: files.CapAll, CaseInsensitive: true})
	f.b.PutFile("/Dir/a", nil)
	wantCode(t, f.svc.Rename(context.Background(), caller(alice), f.id, "/Dir", "/dir/sub"), fault.InvalidRequest)
}

func TestControlBudget(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{ControlBytesPerMin: 64 << 10})
	c := caller(alice)
	n := 0
	for f.svc.ChargeRequest(c, 1000) == nil {
		n++
	}
	if n != 65 {
		t.Fatalf("%d requests of 1000 bytes", n)
	}
	err := f.svc.ChargeRequest(c, 1)
	wantCode(t, err, fault.RateLimited)
	if f.svc.ChargeRequest(caller(bob), 1000) != nil {
		t.Fatal("budget shared between users")
	}
	*f.now = f.now.Add(60e9)
	if err := f.svc.ChargeRequest(c, 1000); err != nil {
		t.Fatalf("budget not refilled: %v", err)
	}
}

func TestRealtimeRoutes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{PageSize: 50})
	fill(f.b, "/d", 60)
	f.b.PutFile("/e.txt", []byte("a\r\nb\r\n"))
	routes := map[string]protocol.Route{}
	for _, r := range f.svc.Routes() {
		if _, ok := protocol.Lookup(r.Type); !ok {
			t.Fatalf("%s is not in the catalog", r.Type)
		}
		if !r.Spec.Async {
			t.Errorf("%s is not async", r.Type)
		}
		routes[r.Type] = r
	}
	if len(routes) != 12 || !routes[protocol.TypeFilesEditSave].Spec.Mutates || routes[protocol.TypeFilesList].Spec.Mutates {
		t.Fatalf("routes %v", routes)
	}
	peer := protocoltest.NewPeer(t, alice)
	ctx := context.Background()
	call := func(typ string, payload any) map[string]any {
		t.Helper()
		raw, perr := protocoltest.Call(ctx, routes[typ], peer, payload)
		if perr != nil {
			t.Fatalf("%s: %+v", typ, perr)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ref := map[string]any{"source_id": f.id, "request_id": "r1"}
	with := func(kv ...any) map[string]any {
		m := map[string]any{"source_id": f.id, "request_id": "r1"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	page := call(protocol.TypeFilesList, with("remote_path", "/d"))
	if page["path"] != "/d" || len(page["files"].([]any)) != 50 || page["next_cursor"] == nil || page["request_id"] != "r1" {
		t.Fatalf("listing %v", page)
	}
	entry := page["files"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "size", "mode", "is_dir", "is_symlink", "modified"} {
		if _, ok := entry[k]; !ok {
			t.Fatalf("entry without %s: %v", k, entry)
		}
	}
	last := call(protocol.TypeFilesList, with("remote_path", "/d", "cursor", page["next_cursor"]))
	if last["next_cursor"] != nil || len(last["files"].([]any)) != 10 {
		t.Fatalf("last page %v", last)
	}
	if home := call(protocol.TypeFilesHome, ref); home["path"] != "/" {
		t.Fatalf("home %v", home)
	}
	ed := call(protocol.TypeFilesEditOpen, with("path", "/e.txt"))
	if ed["content"] != "a\nb\n" || ed["newline"] != "crlf" || ed["original_bytes"] != "YQ0KYg0K" || ed["filename"] != "e.txt" {
		t.Fatalf("edit %v", ed)
	}
	saved := call(protocol.TypeFilesEditSave, with("path", "/e.txt", "content", "c\n", "newline", "crlf", "expected_revision", ed["revision"]))
	if got, _ := f.b.File("/e.txt"); string(got) != "c\r\n" || saved["revision"] != files.Revision(got) {
		t.Fatalf("saved %q %v", got, saved)
	}
	pv := call(protocol.TypeFilesPreview, with("path", "/e.txt"))
	if pv["content"] != "c\r\n" || pv["is_binary"] != false || pv["read_size"] != float64(3) {
		t.Fatalf("preview %v", pv)
	}
	call(protocol.TypeFilesMkdir, with("remote_path", "/n"))
	if cr := call(protocol.TypeFilesCreate, with("parent_path", "/n", "name", "f")); cr["path"] != "/n/f" {
		t.Fatalf("create %v", cr)
	}
	call(protocol.TypeFilesRename, with("old_path", "/n/f", "new_path", "/n/g"))
	call(protocol.TypeFilesDelete, with("path", "/n"))
	if _, perr := protocoltest.Call(ctx, routes[protocol.TypeFilesHome], peer, map[string]any{"source_id": f.id}); perr == nil || perr.Code != fault.InvalidRequest {
		t.Fatalf("missing request id: %+v", perr)
	}
	if _, perr := protocoltest.Call(ctx, routes[protocol.TypeFilesHome], peer, with("extra", 1)); perr == nil {
		t.Fatal("unknown member accepted")
	}
	call(protocol.TypeFilesListCancel, with("cursor", "v1.nope"))
	call(protocol.TypeFilesSourceClose, map[string]any{"source_id": f.id})
	if _, perr := protocoltest.Call(ctx, routes[protocol.TypeFilesHome], peer, ref); perr == nil || perr.Code != fault.SourceUnavailable {
		t.Fatalf("closed source: %+v", perr)
	}
}

func TestPublicSource(t *testing.T) {
	t.Parallel()
	d := files.Descriptor{SourceID: "smb-quick:h1", Kind: files.KindSMB, Label: "s on h", Endpoint: "h/s", Protocol: "SMB 3.1.1",
		Ephemeral: true, Security: files.Security{Encrypted: true, Signed: true, SecureNegotiate: true}}
	got := files.PublicSource(d, files.Capabilities{Ops: files.CapList | files.CapRead}, &files.Access{List: "granted", CreateFile: "denied", CreateDirectory: "unknown", DeleteChildren: "granted"})
	raw, _ := json.Marshal(got)
	want := `{"source_id":"smb-quick:h1","kind":"smb","label":"s on h","endpoint":"h/s","protocol":"SMB 3.1.1","capabilities":["list","read"],"ephemeral":true,"security":{"encrypted":true,"secure_negotiate":true,"signed":true},"access":{"create_directory":"unknown","create_file":"denied","delete_children":"granted","list":"granted"}}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
}
