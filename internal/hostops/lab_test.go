//go:build lab

// The lab tests run the collectors and server operations with the real
// dialer against ssh-modern of the shared test lab (tests/lab):
//
//	go test -tags lab -run Lab ./internal/hostops
//
// They fail, not skip, when the lab is not reachable.
package hostops

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type labFile struct {
	RuntimeDir string `json:"runtime_dir"`
	Services   map[string]struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"services"`
}

func labConn(t *testing.T) *client.Conn {
	t.Helper()
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var l labFile
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	pw, err := os.ReadFile(filepath.Join(l.RuntimeDir, "secrets/ssh-pwuser"))
	if err != nil {
		t.Fatal(err)
	}
	s := l.Services["ssh-modern"]
	log := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema())
	d := &client.Dialer{Net: policy, HostKeys: hostkey.New(db, log)}
	tg := client.Target{Owner: 1, Hop: client.Hop{Host: s.Host, Port: s.Port, User: "pwuser", Auth: client.Auth{Password: strings.TrimSpace(string(pw))}}}
	conn, err := d.Dial(t.Context(), tg, acceptKeys{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// acceptKeys trusts the lab's host key on first use.
type acceptKeys struct{}

func (acceptKeys) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return true, nil }

func (acceptKeys) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }

func TestLabInsightsAndInventory(t *testing.T) {
	conn := labConn(t)
	s := newSessions()
	s.add(1, "lab", Live{Exec: conn, Host: "ssh-modern", ProfileID: "p", Herdr: true})
	d := &Diagnostics{Sessions: s, Switches: fakeSwitches{herdr: true}, Profiles: fakeProfiles{"p": {true, false}}}
	d.Routes()
	for _, diag := range []bool{false, true} {
		res, err := d.handleInsights(asAlice(), nil, protocol.InsightsSample{SessionID: "lab", RequestID: "r", IncludeDiagnostics: diag})
		if err != nil || !res.Success {
			t.Fatalf("insights (diagnostics %v): %+v %v", diag, res, err)
		}
		var st Stats
		if err := json.Unmarshal(res.Stats, &st); err != nil || st.Memory == nil || len(st.CPU) < 4 || st.OSName == "" {
			t.Fatalf("stats %s", res.Stats)
		}
		if diag && (st.Load == nil || st.Network == nil) {
			t.Fatalf("diagnostics %s", res.Stats)
		}
		t.Logf("insights %s", res.Stats)
	}
	inv, err := d.handleInventory(asAlice(), nil, protocol.InventorySample{SessionID: "lab", RequestID: "r"})
	if err != nil || !inv.Success {
		t.Fatalf("inventory %+v %v", inv, err)
	}
	raw, _ := json.Marshal(inv)
	t.Logf("inventory %s", raw)
	h, _ := d.handleHerdr(asAlice(), nil, protocol.HerdrSnapshot{SessionID: "lab"})
	if h.Success || h.Reason == nil || *h.Reason != "not_installed" {
		t.Fatalf("herdr on a host without it: %+v", h)
	}
}

func TestLabServerOperations(t *testing.T) {
	conn := labConn(t)
	f := newOps(t, true)
	f.sessions.add(1, "lab", Live{Exec: conn, Host: "ssh-modern", Username: "pwuser"})
	status, body := f.call(t, alice, http.MethodPost, "/api/server-operations/read", `{"session_id":"lab","action":"system.inspect"}`)
	if status != 200 || body["status"] != "completed" || !strings.Contains(body["output"].(string), "Linux") {
		t.Fatalf("system.inspect: %d %v", status, body)
	}
	status, body = f.call(t, alice, http.MethodPost, "/api/server-operations/read", `{"session_id":"lab","action":"process.list"}`)
	t.Logf("process.list: %d status=%v code=%v processes=%d", status, body["status"], body["code"], len(anySlice(body["processes"])))
	if status != 200 || (body["status"] == "completed" && len(anySlice(body["processes"])) == 0) {
		t.Fatalf("process.list: %d %v", status, body)
	}
	// A write that needs root fails with sudo -n instead of waiting for a
	// password; the outcome is known: failed.
	in := prepare(t, f, alice, `{"session_id":"lab","action":"service.restart","target":{"unit":"webssh-lab-none.service"},"use_sudo":true}`)
	status, body = f.call(t, alice, http.MethodPost, "/api/server-operations/execute", `{"intent":"`+in["intent"].(string)+`"}`, StepUpHeader, "ok")
	if status != 200 || body["status"] != "failed" {
		t.Fatalf("restart without sudo rights: %d %v", status, body)
	}
	t.Logf("restart: exit %v, stderr %q", body["exit_status"], body["error_output"])
	// The process programs run from stdin.
	status, body = f.call(t, alice, http.MethodPost, "/api/server-operations/read", `{"session_id":"lab","action":"process.inspect","target":{"pid":2}}`)
	t.Logf("process.inspect: %d status=%v exit=%v out=%q err=%q", status, body["status"], body["exit_status"], body["output"], body["error_output"])
	if status != 200 {
		t.Fatalf("process.inspect: %d %v", status, body)
	}
}

func anySlice(v any) []any {
	s, _ := v.([]any)
	return s
}
