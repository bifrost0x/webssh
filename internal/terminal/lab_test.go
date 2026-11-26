//go:build lab

// The lab tests run the terminal with the real dialer, network policy and
// host-key store against the shared test lab (tests/lab):
//
//	go test -tags lab -run Lab ./internal/terminal
//
// They fail, not skip, when the lab is not reachable.
package terminal

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type labService struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	InternalHost string            `json:"internal_host"`
	InternalPort int               `json:"internal_port"`
	Fingerprints map[string]string `json:"host_key_fingerprints"`
	FPFile       string            `json:"host_key_fingerprints_file"`
}

type labFile struct {
	RuntimeDir string                `json:"runtime_dir"`
	Services   map[string]labService `json:"services"`
}

var loadLab = sync.OnceValues(func() (labFile, error) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "lab", "runtime", "lab.json")
	}
	var l labFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(raw, &l)
})

func lab(t *testing.T) labFile {
	t.Helper()
	l, err := loadLab()
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	return l
}

func labSecret(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func labHop(t *testing.T, name string, internal bool, auth client.Auth) client.Hop {
	t.Helper()
	s, ok := lab(t).Services[name]
	if !ok {
		t.Fatalf("lab has no %s", name)
	}
	if internal {
		return client.Hop{Host: s.InternalHost, Port: s.InternalPort, User: "pwuser", Auth: auth}
	}
	return client.Hop{Host: s.Host, Port: s.Port, User: "pwuser", Auth: auth}
}

// labFingerprints lists every published fingerprint of the lab.
func labFingerprints(t *testing.T) []string {
	t.Helper()
	l := lab(t)
	var out []string
	for _, s := range l.Services {
		fps := s.Fingerprints
		if s.FPFile != "" {
			if raw, err := os.ReadFile(filepath.Join(l.RuntimeDir, s.FPFile)); err == nil {
				_ = json.Unmarshal(raw, &fps)
			}
		}
		for _, fp := range fps {
			out = append(out, fp)
		}
	}
	return out
}

func newLabManager(t *testing.T, profiles fakeProfiles) *Manager {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema())
	dialer := &client.Dialer{Net: policy, HostKeys: hostkey.New(db, log)}
	m, err := New(Config{}, Deps{Shells: dialer, Profiles: profiles, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	return m
}

// labOpen runs terminal.open for profile and accepts every host-key prompt
// whose fingerprint the lab published. It returns the result and the
// prompt contexts seen.
func labOpen(t *testing.T, m *Manager, peer *peerT, ch uint32, profile string) (protocol.TerminalOpened, []string, *protocol.Error) {
	t.Helper()
	return labOpenTarget(t, m, peer, protocol.TerminalOpen{Ch: ch, RequestID: "lab-" + strconv.Itoa(int(ch)), Rows: 24, Cols: 80,
		Target: protocol.OpenTarget{ProfileID: profile, AuthType: "password"}})
}

// labOpenTarget is labOpen for any request.
func labOpenTarget(t *testing.T, m *Manager, peer *peerT, req protocol.TerminalOpen) (protocol.TerminalOpened, []string, *protocol.Error) {
	t.Helper()
	type outcome struct {
		res  protocol.TerminalOpened
		werr *protocol.Error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		o.werr = call(t, m, peer, protocol.TypeTerminalOpen, req, &o.res)
		done <- o
	}()
	known := labFingerprints(t)
	answered := map[string]bool{}
	var contexts []string
	for {
		select {
		case o := <-done:
			return o.res, contexts, o.werr
		case <-time.After(20 * time.Millisecond):
		}
		for _, ev := range peer.Events(protocol.TypePromptHostKey) {
			q := decode[protocol.PromptHostKey](t, ev)
			if answered[q.PromptID] {
				continue
			}
			answered[q.PromptID] = true
			contexts = append(contexts, q.Context)
			ok := slices.Contains(known, q.Fingerprint)
			if !ok {
				t.Errorf("unpublished host key %s %s", q.KeyType, q.Fingerprint)
			}
			if werr := call(t, m, peer, protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: q.PromptID, Kind: "host_key", Accepted: ok}, nil); werr != nil {
				t.Errorf("answer: %+v", werr)
			}
		}
	}
}

// labRun types a command and waits for want in the output, acknowledging
// what arrived, as the browser does.
func labRun(t *testing.T, m *Manager, peer *peerT, ch uint32, iseq uint64, cmd, want string) {
	t.Helper()
	if err := m.HandleBinary(peer, input(ch, iseq, cmd, false)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(output(t, peer, ch), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in %q", want, output(t, peer, ch))
		}
		if fs := frames(t, peer); len(fs) > 0 {
			_ = m.HandleBinary(peer, ack(ch, fs[len(fs)-1].Seq))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLabTerminal(t *testing.T) {
	pw := client.Auth{Password: labSecret(t, "secrets/ssh-pwuser")}
	socks := lab(t).Services["socks-open"]
	profiles := fakeProfiles{
		"modern": {Owner: 1, Hop: labHop(t, "ssh-modern", false, pw)},
		"jump": {Owner: 1, Hop: labHop(t, "ssh-inner", true, pw),
			Jumps:   []client.Hop{labHop(t, "ssh-bastion", false, pw)},
			Display: client.Display{JumpHostID: "j1"}},
		"socks": {Owner: 1, Hop: labHop(t, "ssh-inner", true, pw),
			Proxy:   &client.SOCKS{Host: socks.Host, Port: socks.Port, RemoteDNS: true},
			Display: client.Display{SOCKSProxyID: "s1"}},
	}
	m := newLabManager(t, profiles)
	cases := []struct {
		profile string
		prompts []string
	}{
		{"modern", []string{"target"}},
		{"jump", []string{"jump_host", "target"}},
		{"socks", nil}, // ssh-inner was trusted through the jump host
	}
	for i, tc := range cases {
		t.Run(tc.profile, func(t *testing.T) {
			peer := user(t, 1)
			ch := uint32(i + 1)
			res, contexts, werr := labOpen(t, m, peer, ch, tc.profile)
			if werr != nil {
				t.Fatalf("open: %+v", werr)
			}
			if !slices.Equal(contexts, tc.prompts) {
				t.Fatalf("prompts %v, want %v", contexts, tc.prompts)
			}
			if tc.profile == "jump" && res.Info.ViaJump == "" || tc.profile == "socks" && !res.Info.ViaSOCKS {
				t.Fatalf("info %+v", res.Info)
			}
			labRun(t, m, peer, ch, 1, "echo C8=$((6*7)); id -un\r", "C8=42")
			labRun(t, m, peer, ch, 2, "printf '\\033[c'; echo DA-DONE\r", "DA-DONE")
			if strings.Contains(output(t, peer, ch), "\x1b[c") {
				t.Fatal("a device-attribute query reached the browser")
			}
			if werr := call(t, m, peer, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil); werr != nil {
				t.Fatal(werr)
			}
			if st := m.Stats(); st.Sessions != 0 || st.Reserved != 0 {
				t.Fatalf("after close %+v", st)
			}
		})
	}
	// The second contact needs no prompt.
	peer := user(t, 1)
	if _, contexts, werr := labOpen(t, m, peer, 9, "modern"); werr != nil || len(contexts) != 0 {
		t.Fatalf("second contact: %+v, prompts %v", werr, contexts)
	}
	// A declined first contact refuses the connection.
	other := newLabManager(t, profiles)
	peer = user(t, 1)
	done := make(chan *protocol.Error, 1)
	go func() {
		done <- call(t, other, peer, protocol.TypeTerminalOpen, protocol.TerminalOpen{Ch: 1, RequestID: "d", Target: protocol.OpenTarget{ProfileID: "modern", AuthType: "password"}}, nil)
	}()
	q := decode[protocol.PromptHostKey](t, waitPrompt(t, peer, protocol.TypePromptHostKey))
	if werr := call(t, other, peer, protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: q.PromptID, Kind: "host_key"}, nil); werr != nil {
		t.Fatal(werr)
	}
	if werr := <-done; werr == nil || werr.Code != fault.HostKeyNotAccepted {
		t.Fatalf("declined host key: %+v", werr)
	}
}
