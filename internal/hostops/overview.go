package hostops

import (
	"context"
	"slices"
)

// OverviewHost is one saved host as the overview readiness needs it.
type OverviewHost struct {
	ID           string
	Host         string
	Port         int // 0 means the SSH default
	JumpHostID   string
	SOCKSProxyID string
	AuthType     string // "password", "key", "tailscale"
	KeyID        string
}

// OverviewInventory is what an account has saved: hosts, the IDs of its
// jump hosts and keys, and the authentication type of each SOCKS5 proxy
// by ID ("none" or "password").
type OverviewInventory struct {
	Hosts        []OverviewHost
	JumpHostIDs  []string
	KeyIDs       []string
	SOCKSProxies map[string]string
}

// Inventory returns an account's saved hosts; the composition root adapts
// internal/hosts and internal/vault to it.
type Inventory interface {
	OverviewInventory(ctx context.Context, owner int64) (OverviewInventory, error)
}

// HostTrust says whether a host key is trusted for host and port, user
// file first, then the global file. A host that is not a valid name or
// address is not trusted. Adapted from internal/ssh/hostkey.
type HostTrust interface {
	Trusted(ctx context.Context, owner int64, host string, port int) (bool, error)
}

// Readiness is one row of /api/overview/status. It is derived from stored
// configuration only and never contacts a host.
type Readiness struct {
	ID           string `json:"id"`
	State        string `json:"state"` // ready, action, broken
	Route        string `json:"route"` // direct, jump, socks, missing
	HostKey      string `json:"host_key"`
	Auth         string `json:"auth"`
	SOCKSProxyID string `json:"socks_proxy_id,omitzero"`
	ViaSOCKS     bool   `json:"via_socks,omitzero"`
	SOCKSAuth    string `json:"socks_auth,omitzero"`
}

// readiness applies the rules of app/overview_routes.py. This release has
// no saved credentials yet, so a password host asks for its password and a
// SOCKS5 proxy with a password needs one.
func readiness(ctx context.Context, owner int64, inv OverviewInventory, trust HostTrust) ([]Readiness, error) {
	out := make([]Readiness, 0, len(inv.Hosts))
	for _, h := range inv.Hosts {
		row := Readiness{ID: h.ID, Route: "direct"}
		if h.JumpHostID != "" {
			row.Route = "missing"
			if slices.Contains(inv.JumpHostIDs, h.JumpHostID) {
				row.Route = "jump"
			}
		}
		if h.SOCKSProxyID != "" {
			row.SOCKSProxyID, row.ViaSOCKS = h.SOCKSProxyID, true
			auth, known := inv.SOCKSProxies[h.SOCKSProxyID]
			row.Route = "missing"
			if known && h.JumpHostID == "" && h.AuthType != "tailscale" {
				row.Route = "socks"
			}
			if known {
				row.SOCKSAuth = "password_required"
				if auth == "none" {
					row.SOCKSAuth = "ready"
				}
			}
		}
		port := h.Port
		if port == 0 {
			port = 22
		}
		trusted, err := trust.Trusted(ctx, owner, h.Host, port)
		if err != nil {
			return nil, err
		}
		row.HostKey = "unknown"
		if trusted {
			row.HostKey = "trusted"
		}
		row.Auth = "prompt"
		if h.AuthType == "key" {
			row.Auth = "key_missing"
			if slices.Contains(inv.KeyIDs, h.KeyID) {
				row.Auth = "ready"
			}
		}
		switch {
		case row.Route == "missing":
			row.State = "broken"
		case row.HostKey != "trusted" || row.Auth == "key_missing" || row.SOCKSAuth == "password_required":
			row.State = "action"
		default:
			row.State = "ready"
		}
		out = append(out, row)
	}
	return out, nil
}
