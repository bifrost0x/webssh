package main

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
)

// routedSource is a file source on a known network path.
type routedSource struct {
	*filestest.Backend
	peer netip.Addr
}

func (b routedSource) Route() (netip.Addr, []string, bool) { return b.peer, nil, true }

// W3-3/OP3-2: an administrator who turns the tailnet block on closes the
// open connections the block now refuses at once and the audit log
// records it (TAILNET_RESTRICTED_CONNECTIONS_CLOSED); a connection on an
// allowed route stays open. Saving the setting unchanged or lifting the
// block closes nothing.
func TestTailnetBlockClosesOpenConnections(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"ADMIN_PANEL_ENABLED": "true"})
	policy, err := netpolicy.New(netpolicy.Config{Tailnet: netpolicy.Tailnet{
		Restricted: sys.tailnetRestricted, Interface: "tailscale0", InterfaceConfigured: true,
		Lookup: func(_ context.Context, addr netip.Addr) (netpolicy.Route, error) {
			if addr.String() == "100.100.100.10" {
				return netpolicy.Route{Interface: "tailscale0", Table: 52}, nil
			}
			return netpolicy.Route{Interface: "eth0", Table: 254}, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sys.policy = policy
	admin := signUp(t, ts.URL, "tailnetadmin", "tailnet-admin-password-1")
	set := func(restrict bool) {
		t.Helper()
		grant := adminGrant(t, admin, ts.URL, "settings.update", "global", "tailnet-admin-password-1")
		status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/settings",
			map[string]bool{"tailscale_ssh_restrict_tailnet_routes": restrict}, grant)
		if status != http.StatusOK {
			t.Fatalf("settings: %d %s", status, body)
		}
	}
	owner := principal.Principal{UserID: 1, SessionID: "browser-1", Username: "tailnetadmin"}
	add := func(peer string) string {
		t.Helper()
		id, err := sys.fileSources.Add(owner, files.SourceSFTPQuick, files.Descriptor{Kind: files.KindSFTP},
			routedSource{filestest.New(), netip.MustParseAddr(peer)})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	open := func(id string) bool {
		_, _, err := sys.fileSources.Describe(owner, id)
		if err != nil && !fault.Is(err, fault.SourceUnavailable) {
			t.Fatal(err)
		}
		return err == nil
	}
	audited := func() string {
		_, export := get(t, admin, ts.URL+"/admin/api/audit/export")
		return export
	}

	set(false)
	node, lan := add("100.100.100.10"), add("192.168.1.10")
	set(false)
	if !open(node) || strings.Contains(audited(), "TAILNET_RESTRICTED_CONNECTIONS_CLOSED") {
		t.Fatal("saving the lifted block closed a connection")
	}
	set(true)
	if open(node) || !open(lan) {
		t.Fatalf("after the block: node open %v, LAN open %v", open(node), open(lan))
	}
	export := audited()
	if strings.Count(export, "TAILNET_RESTRICTED_CONNECTIONS_CLOSED") != 1 ||
		!strings.Contains(export, "pool_connections=1") || !strings.Contains(export, "ssh_sessions=0") {
		t.Fatalf("audit %s", export)
	}
	node = add("100.100.100.10")
	set(true)
	if !open(node) {
		t.Fatal("saving the block again closed a connection")
	}
}
