package main

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// sshTargets adapts the saved hosts to hostkey.Targets; internal/hosts
// may not import internal/ssh/hostkey.
type sshTargets struct{ h *hosts.Service }

func (t sshTargets) SSHTargets(ctx context.Context, owner int64) ([]hostkey.Target, error) {
	eps, err := t.h.SSHTargets(ctx, owner)
	if err != nil {
		return nil, err
	}
	out := make([]hostkey.Target, 0, len(eps))
	for _, e := range eps {
		out = append(out, hostkey.Target{ID: e.ID, Name: e.Name, Kind: e.Kind, Host: e.Host, Port: e.Port})
	}
	return out, nil
}

// hostTrust adapts the host-key store to hostops.HostTrust: a host is
// trusted when an effective key exists for its canonical name and port.
// A host that is not a valid name or address is not trusted.
type hostTrust struct{ s *hostkey.Store }

func (t hostTrust) Trusted(ctx context.Context, owner int64, host string, port int) (bool, error) {
	canonical, err := netpolicy.CanonicalHost(host)
	if err != nil {
		return false, nil
	}
	reports, err := t.s.Effective(ctx, owner, []hostkey.Target{{Host: canonical, Port: port}})
	if err != nil {
		return false, err
	}
	for _, r := range reports {
		for _, k := range r.Keys {
			if k.Status == "effective" {
				return true, nil
			}
		}
	}
	return false, nil
}

// overviewInventory adapts the saved hosts and the key vault to
// hostops.Inventory. The vault lists the keys of the principal in the
// context; owner must be that principal (the overview route serves only
// the signed-in account).
type overviewInventory struct {
	hosts *hosts.Service
	vault *vault.Service
}

// overviewRecord holds the members of a stored host record the overview
// reads; every other member is ignored.
type overviewRecord struct {
	ID           string         `json:"id"`
	Host         string         `json:"host"`
	Port         jsontext.Value `json:"port"`
	JumpHostID   *string        `json:"jump_host_id"`
	SOCKSProxyID *string        `json:"socks_proxy_id"`
	AuthType     string         `json:"auth_type"`
	KeyID        *string        `json:"key_id"`
}

func (o overviewInventory) OverviewInventory(ctx context.Context, owner int64) (hostops.OverviewInventory, error) {
	if p, ok := principal.From(ctx); !ok || p.UserID != owner {
		return hostops.OverviewInventory{}, fault.New(fault.Forbidden, "")
	}
	var inv hostops.OverviewInventory
	profiles, err := o.hosts.Profiles(ctx, owner)
	if err != nil {
		return inv, err
	}
	for _, raw := range profiles {
		r, err := decodeRecord(raw)
		if err != nil {
			return inv, err
		}
		inv.Hosts = append(inv.Hosts, hostops.OverviewHost{ID: r.ID, Host: r.Host, Port: recordPort(r.Port),
			JumpHostID: deref(r.JumpHostID), SOCKSProxyID: deref(r.SOCKSProxyID), AuthType: r.AuthType, KeyID: deref(r.KeyID)})
	}
	jumps, err := o.hosts.JumpHosts(ctx, owner)
	if err != nil {
		return inv, err
	}
	for _, raw := range jumps {
		r, err := decodeRecord(raw)
		if err != nil {
			return inv, err
		}
		inv.JumpHostIDs = append(inv.JumpHostIDs, r.ID)
	}
	proxies, err := o.hosts.SOCKSProxies(ctx, owner)
	if err != nil {
		return inv, err
	}
	inv.SOCKSProxies = make(map[string]string, len(proxies))
	for _, raw := range proxies {
		r, err := decodeRecord(raw)
		if err != nil {
			return inv, err
		}
		inv.SOCKSProxies[r.ID] = r.AuthType
	}
	keys, err := o.vault.List(ctx)
	if err != nil {
		return inv, err
	}
	for _, k := range keys {
		inv.KeyIDs = append(inv.KeyIDs, k.ID)
	}
	return inv, nil
}

func decodeRecord(raw jsontext.Value) (overviewRecord, error) {
	var r overviewRecord
	if err := json.Unmarshal(raw, &r, json.RejectUnknownMembers(false)); err != nil {
		return r, fmt.Errorf("stored host record: %w", err)
	}
	return r, nil
}

// recordPort reads a stored port; anything that is not a port number is
// the SSH default (0), which the overview shows as port 22.
func recordPort(v jsontext.Value) int {
	var f float64
	if len(v) == 0 || json.Unmarshal(v, &f) != nil || f != math.Trunc(f) || f < 1 || f > 65535 {
		return 0
	}
	return int(f)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// legacyAlgorithmShells opens terminal shells with the legacy SSH
// algorithms (ssh-rsa, SHA-1 key exchange) on every hop while the
// setting ssh.legacy_algorithms holds. The upgrade writes it for an
// existing installation (D-01), because paramiko offered them to every
// host; a profile may also opt in per host.
//
// observe, when set, sees every connection once it is authenticated (the
// platform detection of the area "discovery").
type legacyAlgorithmShells struct {
	dialer   *client.Dialer
	settings *settings.Service
	observe  func(client.Target, *client.Conn)
}

func (l legacyAlgorithmShells) OpenShell(ctx context.Context, t client.Target, ix client.Interaction, rows, cols int) (client.Shell, error) {
	t, err := l.target(ctx, t)
	if err != nil {
		return nil, err
	}
	if l.observe == nil {
		return l.dialer.OpenShell(ctx, t, ix, rows, cols)
	}
	conn, err := l.dialer.Dial(ctx, t, ix)
	if err != nil {
		return nil, err
	}
	sh, err := conn.Shell(ctx, rows, cols)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	l.observe(t, conn)
	return connShell{sh, conn}, nil
}

// connShell closes its connection with the shell, as the dialer's own
// shells do.
type connShell struct {
	client.Shell
	conn *client.Conn
}

func (c connShell) Close() error {
	return errors.Join(c.Shell.Close(), c.conn.Close())
}

// Dial is the connection of a persistent (tmux) session
// (terminal.Connections), with the same algorithm rule.
func (l legacyAlgorithmShells) Dial(ctx context.Context, t client.Target, ix client.Interaction) (*client.Conn, error) {
	t, err := l.target(ctx, t)
	if err != nil {
		return nil, err
	}
	conn, err := l.dialer.Dial(ctx, t, ix)
	if err == nil && l.observe != nil {
		l.observe(t, conn)
	}
	return conn, err
}

func (l legacyAlgorithmShells) target(ctx context.Context, t client.Target) (client.Target, error) {
	app, err := l.settings.App(ctx)
	if err != nil {
		return t, fault.Wrap(fault.Unavailable, err, "")
	}
	if app.Policy.LegacySSHAlgorithms {
		t.Hop.Legacy = true
		t.Jumps = append([]client.Hop(nil), t.Jumps...)
		for i := range t.Jumps {
			t.Jumps[i].Legacy = true
		}
	}
	return t, nil
}

// dbPinger adapts the store to httpapi.Pinger.
type dbPinger struct{ db *store.DB }

func (p dbPinger) Ping(ctx context.Context) error {
	return p.db.Read(ctx, func(tx *store.Tx) error {
		var one int
		return tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
	})
}
