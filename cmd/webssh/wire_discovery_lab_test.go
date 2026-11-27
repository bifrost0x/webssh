//go:build lab

package main

import (
	"context"
	json "encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Discovery in the lab network: a scan of the loopback address over the
// published ports of ssh-modern, ssh-legacy and ldap1 finds the two SSH
// servers and leaves the directory, which sends no SSH greeting, out.
func TestLabDiscoveryFindsOnlySSHServers(t *testing.T) {
	if os.Getenv("WEBSSH_LAB_JSON") == "" {
		t.Fatal("set WEBSSH_LAB_JSON to the lab inventory")
	}
	_, ts := openTestSystem(t, nil)
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/api/discovery/scans",
		map[string]any{"network": "127.0.0.1", "ports": []int{12201, 12203, 13389}}, "")
	if status != http.StatusAccepted {
		t.Fatalf("scan: %d %s", status, body)
	}
	var started map[string]any
	if err := json.Unmarshal([]byte(body), &started); err != nil {
		t.Fatal(err)
	}
	view := pollScan(t, admin, ts.URL, started["id"].(string))
	found := view["found"].([]any)
	if view["state"] != "done" || view["checked"] != 3.0 || len(found) != 2 {
		t.Fatalf("scan: %v", view)
	}
	for i, port := range []float64{12201, 12203} {
		entry := found[i].(map[string]any)
		if entry["port"] != port || !strings.HasPrefix(entry["software"].(string), "OpenSSH") {
			t.Errorf("entry %d: %v", i, entry)
		}
	}
}

// The reachability check under the real network policy: an SSH server is
// reachable, the directory's port is not (D-27).
func TestLabReachabilityNeedsAnSSHGreeting(t *testing.T) {
	policy, err := netpolicy.New(netpolicy.Config{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	r := &hostops.Reachability{Prober: probeDialer{policy}, Canonical: netpolicy.CanonicalHost,
		Inventory: func(context.Context, int64) ([]hostops.ReachHost, error) {
			return []hostops.ReachHost{{ID: "ssh", Host: "127.0.0.1", Port: 12201}, {ID: "ldap", Host: "127.0.0.1", Port: 13389}}, nil
		}}
	h := &hostops.ReachabilityHTTP{Check: r, Limiter: userLimiter{l: auth.NewLimiter()},
		Permitted: func(context.Context, principal.Principal) (bool, error) { return true, nil }}
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequestWithContext(principal.With(t.Context(), principaltest.User(1)), http.MethodPost, "/api/overview/reachability", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	res := rec.Body.String()
	if !strings.Contains(res, `"ssh":{"state":"reachable"`) || !strings.Contains(res, `"ldap":{"state":"unreachable"}`) {
		t.Fatalf("check: %s", res)
	}
}

// The identity probe on a real sshd: the script travels on stdin through
// the login shell and the answer parses as a detected Linux host.
func TestLabIdentityProbeOnARealHost(t *testing.T) {
	inv := os.Getenv("WEBSSH_LAB_JSON")
	if inv == "" {
		t.Fatal("set WEBSSH_LAB_JSON to the lab inventory")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(inv), "secrets", "ssh-pwuser"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := netpolicy.New(netpolicy.Config{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &client.Dialer{Net: policy, HostKeys: acceptAll{}}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := dialer.Dial(ctx, client.Target{Owner: 1, Hop: client.Hop{Host: "127.0.0.1", Port: 12201, User: "pwuser",
		Auth: client.Auth{Password: strings.TrimSpace(string(raw))}}}, acceptAll{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if b, ok := hostops.DescribeBanner([]byte(conn.ServerVersion())); !ok || !strings.HasPrefix(b.Software, "OpenSSH") {
		t.Fatalf("server version %q", conn.ServerVersion())
	}
	cmd, err := remotecmd.Script(hosts.IdentityScript, false)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Timeout, cmd.MaxOutput = 10*time.Second, hosts.MaxIdentityOutput
	res, err := remotecmd.Run(ctx, conn, cmd)
	if err != nil || res.ExitStatus != 0 || res.Truncated {
		t.Fatalf("probe: %+v %v", res, err)
	}
	id, err := hosts.ParseIdentity(string(res.Stdout))
	if err != nil || id.State != hosts.StateDetected || id.Platform == "" {
		t.Fatalf("identity %+v %v from %q", id, err, res.Stdout)
	}
	t.Logf("lab host: %+v", id)
}

// acceptAll trusts every host key of the lab host, for the probe test only.
type acceptAll struct{}

func (acceptAll) Known(context.Context, int64, string, int, ssh.PublicKey) (bool, error) {
	return false, nil
}
func (acceptAll) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }
func (acceptAll) Preferred(_ context.Context, _ int64, _ string, _ int, allowed []string) ([]string, error) {
	return allowed, nil
}
func (acceptAll) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return true, nil }
func (acceptAll) Banner(context.Context, client.BannerPrompt) (bool, error)   { return true, nil }
