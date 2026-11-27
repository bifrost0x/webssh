package smb

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

func unitConfig(n Network, dial func(context.Context, string, string) (net.Conn, error)) Config {
	return Config{Network: n, AllowedTargets: []string{"nas.example", "127.0.0.1"}, ConnectTimeout: 500 * time.Millisecond,
		IOIdleTimeout: 500 * time.Millisecond, Dial: dial}
}

// Every refusal of the input happens before anything is admitted or
// dialled; an empty user name or an empty password is refused on its own.
func TestConnectRefusesInputBeforeDialling(t *testing.T) {
	n := &countingNetwork{}
	dialled := false
	cfg := unitConfig(n, func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, errTest })
	good := Target{Host: "nas.example", Share: "Data", Username: "alice", Password: []byte("pw")}
	for name, c := range map[string]struct {
		edit func(*Target)
		code fault.Code
	}{
		"empty user":         {func(t *Target) { t.Username = "" }, fault.InvalidRequest},
		"empty password":     {func(t *Target) { t.Password = nil }, fault.InvalidRequest},
		"empty both":         {func(t *Target) { t.Username, t.Password = "", nil }, fault.InvalidRequest},
		"user with domain":   {func(t *Target) { t.Username = `LAB\alice` }, fault.InvalidRequest},
		"control in user":    {func(t *Target) { t.Username = "a\tb" }, fault.InvalidRequest},
		"domain with at":     {func(t *Target) { t.Domain = "a@b" }, fault.InvalidRequest},
		"password too long":  {func(t *Target) { t.Password = []byte(strings.Repeat("p", MaxPassword+1)) }, fault.InvalidRequest},
		"password newline":   {func(t *Target) { t.Password = []byte("a\nb") }, fault.InvalidRequest},
		"admin share":        {func(t *Target) { t.Share = "ADMIN$" }, fault.InvalidRequest},
		"reserved share":     {func(t *Target) { t.Share = "con" }, fault.InvalidRequest},
		"host not allowed":   {func(t *Target) { t.Host = "evil.example" }, fault.SMBTargetNotAllowed},
		"host invalid":       {func(t *Target) { t.Host = "bad host" }, fault.SMBTargetNotAllowed},
		"host case and dots": {func(t *Target) { t.Host = "NAS.Example." }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			n.calls, dialled = 0, false
			tg := good
			tg.Password = []byte("pw")
			c.edit(&tg)
			_, err := Connect(t.Context(), cfg, tg)
			if c.code == "" {
				if n.calls != 1 || n.host != "nas.example" || n.port != DefaultPort || n.role != netpolicy.RoleSMB || !dialled {
					t.Fatalf("canonical host not admitted: %v %q %v", n.calls, n.host, err)
				}
				return
			}
			wantCode(t, err, c.code)
			if n.calls != 0 || dialled {
				t.Fatalf("refused input reached the network (admit %d, dial %v)", n.calls, dialled)
			}
		})
	}
}

func TestConnectClearsThePassword(t *testing.T) {
	pw := []byte("secret")
	_, _ = Connect(t.Context(), unitConfig(&countingNetwork{}, func(context.Context, string, string) (net.Conn, error) { return nil, errTest }),
		Target{Host: "nas.example", Share: "Data", Username: "alice", Password: pw})
	if string(pw) == "secret" {
		t.Fatal("password still in memory")
	}
}

type refusingNetwork struct{}

func (refusingNetwork) Admit(context.Context, netpolicy.Role, string, int) (netpolicy.Admitted, error) {
	return netpolicy.Admitted{}, fault.New(fault.TargetBlocked, "")
}

func TestConnectNetworkPolicyAndTimeouts(t *testing.T) {
	tg := Target{Host: "nas.example", Share: "Data", Username: "alice", Password: []byte("pw")}
	_, err := Connect(t.Context(), unitConfig(refusingNetwork{}, nil), tg)
	wantCode(t, err, fault.SMBTargetNotAllowed)
	if d := DiagnosticOf(err); d.Phase != PhaseTargetResolution {
		t.Errorf("diagnostic %+v", d)
	}

	// A server that accepts and never answers: the connect deadline ends
	// the negotiate.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	}()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	start := time.Now()
	tg.Password = []byte("pw")
	_, err = Connect(t.Context(), unitConfig(&countingNetwork{}, dial), tg)
	wantCode(t, err, fault.FileTimeout)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("timeout after %v", took)
	}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	tg.Password = []byte("pw")
	cfg := unitConfig(&countingNetwork{}, dial)
	cfg.ConnectTimeout = 5 * time.Second
	_, err = Connect(ctx, cfg, tg)
	wantCode(t, err, fault.SMBConnectCancelled)
	_, err = Connect(t.Context(), Config{}, tg)
	wantCode(t, err, fault.SMBConnectionFailed)
}

func TestErrorTextHasNoCause(t *testing.T) {
	err := classify(errors.New(`\\10.0.0.5\share\secret-name password=hunter2`), PhaseFileOperation)
	if s := err.Error(); strings.Contains(s, "hunter2") || strings.Contains(s, "secret-name") {
		t.Fatalf("cause in error text: %s", s)
	}
	fe, _ := fault.From(err)
	if fe.Message != "" || fe.Code != fault.OperationFailed {
		t.Fatalf("%+v", fe)
	}
}

func TestUnansweredDecidesOutcome(t *testing.T) {
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"deadline":       {classifyCtx(deadline, errors.New("x"), PhaseFileOperation), true},
		"transport":      {fail(fault.SourceUnavailable, PhaseFileOperation, "TransportError", nil), true},
		"status":         {classify(&responseError, PhaseFileOperation), false},
		"status timeout": {func() error { e := classify(&ioTimeout, PhaseFileOperation); return e }(), false},
		"not applied":    {fail(fault.FileTimeout, PhaseFileOperation, causeNotApplied, nil), false},
		"invalid":        {fault.New(fault.InvalidRequest, ""), false},
	} {
		if got := unanswered(c.err); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	b := &Backend{}
	b.dead.Store(true) // taint must not reach a nil session in this unit test
	err := b.reconcile(classifyCtx(deadline, errors.New("x"), PhaseFileOperation), func() (bool, bool) { return true, true })
	if err != nil {
		t.Errorf("applied: %v", err)
	}
	err = b.reconcile(classifyCtx(deadline, errors.New("x"), PhaseFileOperation), func() (bool, bool) { return false, true })
	if fault.CodeOf(err) != fault.FileTimeout || unanswered(err) {
		t.Errorf("not applied: %v", err)
	}
	err = b.reconcile(classifyCtx(deadline, errors.New("x"), PhaseFileOperation), func() (bool, bool) { return false, false })
	wantCode(t, err, fault.OutcomeUnknown)
	if err := b.reconcile(classify(&responseError, PhaseFileOperation), func() (bool, bool) { t.Fatal("asked"); return false, false }); fault.CodeOf(err) != fault.FileConflict {
		t.Errorf("status passes: %v", err)
	}
}

func TestBackendRefusesAfterClose(t *testing.T) {
	b := &Backend{}
	b.dead.Store(true)
	ctx := t.Context()
	_, err := b.Stat(ctx, "/a", false)
	wantCode(t, err, fault.SourceUnavailable)
	_, err = b.Write(ctx, "/a", strings.NewReader(""), files.WriteOptions{})
	wantCode(t, err, fault.SourceUnavailable)
	wantCode(t, b.Mkdir(ctx, "/a"), fault.SourceUnavailable)
	wantCode(t, b.Rename(ctx, "/a", "/b"), fault.SourceUnavailable)
	wantCode(t, b.Remove(ctx, "/a", true, files.Budget{}), fault.SourceUnavailable)
	_, err = b.Home(ctx)
	wantCode(t, err, fault.SourceUnavailable)
	if c := b.Capabilities(); c.Ops.Has(files.CapChmod) || c.RootWritable || !c.CaseInsensitive {
		t.Errorf("capabilities %+v", c)
	}
}
