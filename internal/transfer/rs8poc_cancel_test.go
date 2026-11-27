package transfer_test

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

func TestRS8ForeignCancelIsUnavailable(t *testing.T) {
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	if st := e.m.CancelFor(principaltest.User(8).UserID, pr.TransferID); st != transfer.CancelUnavailable {
		t.Fatalf("foreign cancel = %s", st)
	}
	if got := e.do(principaltest.User(8), "GET", pr.URL, nil, 0); got.Code != 404 {
		t.Fatalf("foreign download = %d", got.Code)
	}
	if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st == transfer.CancelUnavailable {
		t.Fatal("owner cannot cancel")
	}
}
