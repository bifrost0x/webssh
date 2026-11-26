package transfer_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

func TestToken(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 100 {
		tok := transfer.NewToken()
		if !transfer.ValidToken(tok) || seen[tok] {
			t.Fatalf("token %q invalid or repeated", tok)
		}
		seen[tok] = true
	}
	for _, bad := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 44), strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "/"} {
		if transfer.ValidToken(bad) {
			t.Errorf("ValidToken(%q) accepted", bad)
		}
	}
}

func TestFailureRetryable(t *testing.T) {
	t.Parallel()
	retry := map[fault.Code]bool{
		fault.ShareUnavailable: true, fault.FileTimeout: true, fault.SourceUnavailable: true, fault.SourceChanged: true,
		fault.FilePermissionDenied: false, fault.FileConflict: false, fault.LimitExceeded: false, fault.TransferUnavailable: false,
	}
	for code, want := range retry {
		if got := (transfer.Failure{Code: code}).Retryable(); got != want {
			t.Errorf("%s: Retryable = %v", code, got)
		}
	}
	if !transfer.Completed.Terminal() || transfer.Cancelling.Terminal() {
		t.Error("Terminal is wrong")
	}
}

// sources is a fake of transfer.Sources: one backend per source id, owned
// by one user and session.
type sources struct {
	owner    principal.Principal
	backends map[string]files.Backend
	held     int
}

func (s *sources) Resolve(_ context.Context, p principal.Principal, id string, need files.Capability) (files.Backend, func(), error) {
	b, ok := s.backends[id]
	if !ok || p.UserID != s.owner.UserID || p.SessionID != s.owner.SessionID || !b.Capabilities().Ops.Has(need) {
		return nil, nil, fault.New(fault.SourceUnavailable, "")
	}
	s.held++
	return b, func() { s.held-- }, nil
}

var _ transfer.Sources = (*sources)(nil)

// copyFile is a host-to-host copy of one file as TR1 builds it on the
// contract.
func copyFile(ctx context.Context, src transfer.Sources, p principal.Principal, from, fromPath, to, toPath string, policy transfer.ConflictPolicy) error {
	a, releaseA, err := src.Resolve(ctx, p, from, files.CapRead|files.CapRemoteTransfer)
	if err != nil {
		return err
	}
	defer releaseA()
	b, releaseB, err := src.Resolve(ctx, p, to, files.CapWrite|files.CapRemoteTransfer)
	if err != nil {
		return err
	}
	defer releaseB()
	r, err := a.Open(ctx, fromPath, files.Range{Length: -1})
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = b.Write(ctx, toPath, io.LimitReader(r, transfer.DefaultLimits.MaxArchive+1), files.WriteOptions{
		Exclusive: policy == transfer.ConflictError, Size: r.Entry().Size, MaxBytes: transfer.DefaultLimits.MaxArchive,
	})
	return err
}

func TestServerToServerOnTheContract(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	owner := principaltest.User(7)
	a, b := filestest.New(), filestest.New()
	a.PutFile("/src.txt", []byte("payload"))
	b.PutFile("/dst.txt", []byte("old"))
	src := &sources{owner: owner, backends: map[string]files.Backend{"sftp-session:a": a, "smb-quick:b": b}}

	if err := copyFile(ctx, src, owner, "sftp-session:a", "/src.txt", "smb-quick:b", "/dst.txt", transfer.ConflictError); !fault.Is(err, fault.FileConflict) {
		t.Fatalf("conflict policy error = %v", err)
	}
	if err := copyFile(ctx, src, owner, "sftp-session:a", "/src.txt", "smb-quick:b", "/dst.txt", transfer.ConflictReplace); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.File("/dst.txt"); string(got) != "payload" {
		t.Fatalf("destination = %q", got)
	}
	other := principaltest.User(8)
	if err := copyFile(ctx, src, other, "sftp-session:a", "/src.txt", "smb-quick:b", "/x", transfer.ConflictError); !fault.Is(err, fault.SourceUnavailable) {
		t.Fatalf("another user's source = %v", err)
	}
	if src.held != 0 {
		t.Fatalf("%d holds not released", src.held)
	}
}
