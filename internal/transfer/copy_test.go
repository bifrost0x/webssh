package transfer_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

func TestCopyEveryKindCombination(t *testing.T) {
	t.Parallel()
	// The fake has the SFTP capabilities; the source ids carry the kinds
	// the manager never looks at, so this checks that nothing depends on
	// them. The lab tests run the real SFTP and SMB backends.
	for _, ids := range [][2]string{
		{"sftp-session:a", "smb-quick:b"}, {"smb-quick:b", "sftp-session:a"},
		{"sftp-session:a", "sftp-session:a"}, {"smb-quick:b", "smb-quick:b"},
	} {
		e := newEnv(t)
		e.a.PutFile("/data/r.txt", []byte("report"))
		e.a.PutFile("/data/d/x", []byte("xx"))
		e.b.PutFile("/data/r.txt", []byte("report"))
		e.b.PutFile("/data/d/x", []byte("xx"))
		id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{
			SourceID: ids[0], SourcePath: "/data", DestID: ids[1], DestPath: "/copy", RequestID: "req-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		ev := e.ev.wait(t, id)
		if ev.State != transfer.Completed || ev.Copy == nil || *ev.Copy != (transfer.CopyRef{SourceID: ids[0], RequestID: "req-1", DestinationSourceID: ids[1]}) ||
			ev.Filename != "data" || ev.SourcePath != "/data" || ev.DestPath != "/copy" {
			t.Fatalf("%v: %+v", ids, ev)
		}
		dst := e.a
		if ids[1] == "smb-quick:b" {
			dst = e.b
		}
		if got, _ := dst.File("/copy/d/x"); string(got) != "xx" {
			t.Fatalf("%v: copied %q", ids, got)
		}
		e.idle()
	}
}

func TestCopyProgressAndAudit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/big.bin", make([]byte, 300<<10))
	id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/big.bin", DestID: "smb-quick:b", DestPath: "/big.bin", RequestID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	e.ev.wait(t, id)
	e.idle()
	e.ev.mu.Lock()
	last := e.ev.progress[len(e.ev.progress)-1]
	e.ev.mu.Unlock()
	if last.Transferred != 300<<10 || last.Total != 300<<10 || last.Filename != "big.bin" || last.Copy == nil {
		t.Fatalf("last progress %+v", last)
	}
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	if len(e.audit.events) != 1 {
		t.Fatalf("audit %v", e.audit.events)
	}
	got := e.audit.events[0]
	line := fmt.Sprint(got...)
	for _, want := range []string{"FILE_SOURCE_OPERATION", "server_to_server_copy", "COMPLETED", "big.bin", "destination_filename"} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit %q lacks %s", line, want)
		}
	}
	if strings.Contains(line, "/big.bin") {
		t.Fatalf("audit carries a path: %q", line)
	}
}

func TestCopyIsCancelledByUserRevocationAndConnection(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"cancel", "revoke", "connection"} {
		e, s := streamEnv(t, 10<<20, true)
		e.m.PeerOpened(e.owner.UserID, 1)
		e.m.PeerOpened(e.owner.UserID, 2)
		id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: "sftp-quick:s", SourcePath: "/gen", DestID: "smb-quick:b", DestPath: "/gen", RequestID: "r"})
		if err != nil {
			t.Fatal(err)
		}
		s.gate <- struct{}{}
		switch how {
		case "cancel":
			if st := e.m.CancelFor(e.owner.UserID, id); st != transfer.Cancelling {
				t.Fatalf("cancel %s", st)
			}
		case "revoke":
			e.m.Revoke(principal.Revocation{UserID: e.owner.UserID})
		case "connection":
			e.m.PeerClosed(e.owner.UserID, 1) // the connection that started it
		}
		ev := e.ev.wait(t, id)
		want := map[string]fault.Code{"cancel": fault.FileCancelled, "revoke": fault.SourceUnavailable, "connection": fault.FileCancelled}[how]
		if ev.Failure == nil || ev.Failure.Code != want {
			t.Fatalf("%s: %+v", how, ev)
		}
		if _, ok := e.b.File("/gen"); ok {
			t.Fatalf("%s: a cancelled copy left a file", how)
		}
		e.idle()
	}
}

func TestCopyRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	other := principal.Principal{UserID: 7, SessionID: "other"}
	e.src.add("sftp-quick:foreign", other, e.a)
	for _, c := range []struct {
		rq   transfer.CopyRequest
		code fault.Code
	}{
		{transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/f", DestID: "smb-quick:b"}, fault.InvalidRequest},
		{transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/f", DestID: "smb-quick:b", DestPath: "/x", Policy: "merge"}, fault.InvalidRequest},
		{transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "f", DestID: "smb-quick:b", DestPath: "/x"}, fault.InvalidRequest},
		{transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/f", DestID: "smb-quick:b", DestPath: "/"}, fault.InvalidRequest},
		{transfer.CopyRequest{SourceID: "sftp-quick:foreign", SourcePath: "/f", DestID: "smb-quick:b", DestPath: "/x"}, fault.SourceUnavailable},
		{transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/f", DestID: "sftp-quick:foreign", DestPath: "/x"}, fault.SourceUnavailable},
	} {
		if _, err := e.m.Copy(t.Context(), e.caller(), c.rq); fault.CodeOf(err) != c.code {
			t.Errorf("%+v: %v", c.rq, err)
		}
	}
	// One background copy per user (QUOTA_BACKGROUND_JOB_PER_USER 1).
	s := newStream(1 << 20)
	s.gate = make(chan struct{})
	e.src.add("sftp-quick:s", e.owner, s)
	id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: "sftp-quick:s", SourcePath: "/gen", DestID: "smb-quick:b", DestPath: "/g", RequestID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: "sftp-session:a", SourcePath: "/f", DestID: "smb-quick:b", DestPath: "/x", RequestID: "r"})
	if fe, _ := fault.From(err); fe == nil || fe.Code != fault.TransferUnavailable || fe.Details["retryable"] != false {
		t.Fatalf("second copy: %v", err)
	}
	close(s.gate)
	e.ev.wait(t, id)
	e.idle()
}

func TestRealtimeRoutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	routes := map[string]protocol.Route{}
	for _, r := range e.m.Routes() {
		if !r.Spec.Mutates || !r.Spec.Async {
			t.Errorf("%s: spec %+v", r.Type, r.Spec)
		}
		routes[r.Type] = r
	}
	peer := protocoltest.NewPeer(t, e.owner)
	run := func(typ, payload string) (any, error) {
		return routes[typ].Run(t.Context(), peer, jsontext.Value(payload))
	}
	out, err := run(protocol.TypeTransferPrepare, `{"source_id":"sftp-session:a","request_id":"r1","direction":"download","remote_path":"/f"}`)
	if err != nil {
		t.Fatal(err)
	}
	pr := out.(*protocol.TransferPrepared)
	if pr.RequestID != "r1" || pr.SourceID != "sftp-session:a" || pr.Direction != "download" || !strings.HasPrefix(pr.URL, "/root/api/transfers/") || pr.ExpiresAt == 0 {
		t.Fatalf("prepared %+v", pr)
	}
	if _, err := run(protocol.TypeTransferPrepare, `{"source_id":"sftp-session:a","request_id":"r1","direction":"download","remote_path":"/f","extra":1}`); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := run(protocol.TypeTransferPrepare, `{"source_id":"sftp-session:a","request_id":"bad id!","direction":"download","remote_path":"/f"}`); fault.CodeOf(err) != fault.TransferUnavailable {
		t.Fatalf("bad request id: %v", err)
	}
	out, _ = run(protocol.TypeTransferCancel, `{"transfer_id":"`+pr.TransferID+`"}`)
	if out.(*protocol.TransferCancelState).State != "cancelled" {
		t.Fatalf("cancel %+v", out)
	}
	out, _ = run(protocol.TypeTransferCancel, `{"transfer_id":"`+strings.Repeat("x", 100)+`"}`)
	if out.(*protocol.TransferCancelState).State != "unavailable" {
		t.Fatalf("long id %+v", out)
	}
	out, err = run(protocol.TypeTransferCopy, `{"source_id":"sftp-session:a","request_id":"r2","source_path":"/f","destination_source_id":"smb-quick:b","dest_path":"/f","conflict_policy":"error"}`)
	if err != nil {
		t.Fatal(err)
	}
	started := out.(*protocol.TransferCopyStarted)
	if started.DestinationSourceID != "smb-quick:b" || started.RequestID != "r2" {
		t.Fatalf("started %+v", started)
	}
	e.ev.wait(t, started.TransferID)
	e.idle()
}

func TestChargedBeforeDecoding(t *testing.T) {
	t.Parallel()
	var charged []int
	e := newEnv(t, func(o *transfer.Options) {
		o.Charge = func(_ int64, n int) error {
			charged = append(charged, n)
			if n > 1000 {
				return fault.New(fault.RateLimited, "")
			}
			return nil
		}
	})
	peer := protocoltest.NewPeer(t, e.owner)
	for _, r := range e.m.Routes() {
		if r.Type != protocol.TypeTransferCancel {
			continue
		}
		if _, err := r.Run(t.Context(), peer, jsontext.Value(`{"transfer_id":"`+strings.Repeat("y", 2000)+`"}`)); fault.CodeOf(err) != fault.RateLimited {
			t.Fatalf("over budget: %v", err)
		}
		_, _ = r.Run(t.Context(), peer, jsontext.Value(`{"transfer_id":"t"}`))
	}
	if len(charged) != 2 || charged[1] != 256 {
		t.Fatalf("charged %v", charged)
	}
}

func TestNotifyEventsPayloads(t *testing.T) {
	t.Parallel()
	var got []string
	ev := transfer.NotifyEvents(func(_ int64, typ string, payload any) int {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, typ+" "+string(raw))
		return 1
	})
	ev.Progress(1, transfer.Progress{TransferID: "t", Direction: transfer.Upload, Transferred: 1, Total: 2})
	f := transfer.Failure{Code: fault.LimitExceeded, LimitKind: transfer.LimitUpload, LimitBytes: 5, ActualBytes: -1}
	ev.Finished(1, transfer.Finished{TransferID: "t", Direction: transfer.Upload, State: transfer.Failed, Failure: &f})
	ref := &transfer.CopyRef{SourceID: "a", RequestID: "r", DestinationSourceID: "b"}
	ev.Finished(1, transfer.Finished{TransferID: "c", Direction: transfer.ServerToServer, State: transfer.Completed, Copy: ref, Filename: "f", SourcePath: "/f", DestPath: "/g"})
	want := []string{
		`transfer.progress {"transfer_id":"t","direction":"upload","transferred":1,"total":2}`,
		`transfer.finished {"transfer_id":"t","direction":"upload","status":"failed","error_code":"LIMIT_EXCEEDED","error":"The transfer exceeds the configured limit.","retryable":false,"limit_kind":"upload","limit_bytes":5}`,
		`transfer.finished {"transfer_id":"c","direction":"server_to_server","status":"completed","copy":{"source_id":"a","request_id":"r","destination_source_id":"b"},"filename":"f","source_path":"/f","dest_path":"/g"}`,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d:\n%s\nwant\n%s", i, got[i], want[i])
		}
	}
}
