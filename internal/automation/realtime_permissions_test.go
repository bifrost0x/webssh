package automation

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func permissionRoute(t *testing.T, j *PermissionJobs, typ string) protocol.Route {
	t.Helper()
	for _, r := range j.Routes() {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no route %s", typ)
	return protocol.Route{}
}

func TestPermissionRoutesAnswerWithThePythonTexts(t *testing.T) {
	t.Parallel()
	e := newPermEnv(t)
	peer := protocoltest.NewPeer(t, e.c.P)
	// The jobs belong to the connection that prepared them; peer ids
	// come from a counter shared by every test.
	e.c.Peer = peer.ID()
	run := func(typ, payload string) (any, error) {
		return permissionRoute(t, e.j, typ).Run(t.Context(), peer, jsontext.Value(payload))
	}
	out, err := run(protocol.TypePermissionsGet, `{"source_id":"sftp-session:s1","request_id":"r1","path":"/work/a.txt"}`)
	if err != nil || jsonMember(out.(jsontext.Value), "mode") != "600" {
		t.Fatalf("get: %v %v", out, err)
	}
	_, err = run(protocol.TypePermissionsSet, `{"source_id":"sftp-session:s1","request_id":"r1","path":"/work/a.txt","mode":"640","expected_metadata":"x"}`)
	if fe, ok := fault.From(err); !ok || fe.Code != fault.MetadataChanged || fe.Message != "The file metadata changed. Reopen the permissions dialog." {
		t.Fatalf("set with a forged token: %v", err)
	}
	_, err = run(protocol.TypePermissionsJobPrepare, `{"source_id":"sftp-session:s1","request_id":"","paths":["/work"],"file_mode":"640","directory_mode":"750"}`)
	wantCode(t, err, fault.InvalidRequest)
	_, err = run(protocol.TypePermissionsJobPrepare, `{"source_id":"sftp-session:s1","request_id":"r2","paths":["/work"],"recursive":"yes","file_mode":"640","directory_mode":"750"}`)
	wantCode(t, err, fault.InvalidRequest)
	_, err = run(protocol.TypePermissionsJobGet, `{"source_id":"sftp-session:other","request_id":"r3","job_id":"nope"}`)
	if fe, ok := fault.From(err); !ok || fe.Code != fault.SourceUnavailable || fe.Message != "File source unavailable" {
		t.Fatalf("foreign source: %v", err)
	}
	out, err = run(protocol.TypePermissionsJobPrepare, `{"source_id":"sftp-session:s1","request_id":"r4","paths":["/other/f"],"file_mode":"640","directory_mode":"750"}`)
	if err != nil {
		t.Fatal(err)
	}
	e.wait(t, jsonMember(out.(jsontext.Value), "job_id"), permReady)
}
