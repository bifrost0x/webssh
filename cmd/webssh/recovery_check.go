package main

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
)

// recoveryCheck serves /api/account/recovery-check (C-BAK-06,
// customer_workflows.py): the checklist after a portable restore with the
// account's saved hosts, whether each has its credential, route and
// trusted host key, and the review of the restore notice. It reads only
// the account's own data and never connects.
type recoveryCheck struct{ sys *system }

// recoveryHost is one row of the checklist.
type recoveryHost struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Credential string `json:"credential"`
	Route      string `json:"route"`
	HostKey    string `json:"host_key"`
}

// savedProfile holds the members of a saved host the checklist reads.
type savedProfile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	AuthType     string `json:"auth_type"`
	KeyID        string `json:"key_id"`
	JumpHostID   string `json:"jump_host_id"`
	SOCKSProxyID string `json:"socks_proxy_id"`
}

func idsOf(records []jsontext.Value) map[string]bool {
	out := map[string]bool{}
	for _, r := range records {
		var v struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(r, &v) == nil && v.ID != "" {
			out[v.ID] = true
		}
	}
	return out
}

func (rc *recoveryCheck) get(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		rc.fail(w, r, err)
		return
	}
	hosts, err := rc.hosts(r.Context(), p)
	if err != nil {
		rc.fail(w, r, err)
		return
	}
	restoredAt, needsReview, err := rc.sys.settings.RecoveryCheck(r.Context(), p.UserID)
	if err != nil {
		rc.fail(w, r, err)
		return
	}
	var at any
	if restoredAt != "" {
		at = restoredAt
	}
	writeRecoveryJSON(w, http.StatusOK, map[string]any{"restored_at": at, "needs_review": needsReview,
		"coverage": map[string]string{"configuration": "included", "account_authentication": "included",
			"remote_credentials": "excluded", "live_sessions": "excluded"},
		"hosts": hosts, "schedules": []any{}})
}

// hosts builds the rows of the account's saved hosts.
func (rc *recoveryCheck) hosts(ctx context.Context, p principal.Principal) ([]recoveryHost, error) {
	hs := rc.sys.hosts
	profiles, err := hs.Profiles(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	jumpRecords, err := hs.JumpHosts(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	socksRecords, err := hs.SOCKSProxies(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	jumps, socks := idsOf(jumpRecords), idsOf(socksRecords)
	passwords := rc.passwordStatus(principal.With(ctx, p))
	out := make([]recoveryHost, 0, len(profiles))
	var targets []hostkey.Target
	for _, raw := range profiles {
		var sp savedProfile
		if err := json.Unmarshal(raw, &sp); err != nil {
			continue
		}
		row := recoveryHost{ID: sp.ID, Name: sp.Name, Route: "configured", Credential: "interactive"}
		switch sp.AuthType {
		case "key":
			row.Credential = "key_required"
			if sp.KeyID != "" && rc.sys.vault != nil {
				if ok, err := rc.sys.vault.HasKey(ctx, p.UserID, sp.KeyID); err == nil && ok {
					row.Credential = "ready"
				}
			}
		case "password":
			row.Credential = "password_required"
			if passwords[sp.ID] == "ready" {
				row.Credential = "ready"
			}
		}
		if sp.JumpHostID != "" && !jumps[sp.JumpHostID] {
			row.Route = "missing_jump"
		}
		if sp.SOCKSProxyID != "" && !socks[sp.SOCKSProxyID] {
			row.Route = "missing_socks"
		}
		out = append(out, row)
		targets = append(targets, hostkey.Target{ID: sp.ID, Host: sp.Host, Port: sp.Port, Kind: "ssh"})
	}
	trusted := map[string]bool{}
	if rc.sys.hostkeys != nil && len(targets) > 0 {
		reports, err := rc.sys.hostkeys.Effective(ctx, p.UserID, targets)
		if err != nil {
			return nil, err
		}
		for _, rep := range reports {
			for _, k := range rep.Keys {
				if k.Status == "effective" {
					trusted[rep.ID] = true
				}
			}
		}
	}
	for i := range out {
		out[i].HostKey = "review_required"
		if trusted[out[i].ID] {
			out[i].HostKey = "trusted"
		}
	}
	return out, nil
}

// passwordStatus reads the credential status of every saved host from
// the vault's page state; without saved passwords every password host
// needs one.
func (rc *recoveryCheck) passwordStatus(ctx context.Context) map[string]string {
	out := map[string]string{}
	if rc.sys.vault == nil {
		return out
	}
	raw, err := rc.sys.vault.State(ctx)
	if err != nil {
		return out
	}
	var st struct {
		Profiles []struct {
			ID     string `json:"id"`
			Status string `json:"credential_status"`
		} `json:"profiles"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return out
	}
	for _, p := range st.Profiles {
		out[p.ID] = p.Status
	}
	return out
}

// review is POST: the account confirms the checklist of the current
// restore; an older checklist cannot dismiss a newer restore.
func (rc *recoveryCheck) review(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		rc.fail(w, r, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10+1))
	var body map[string]jsontext.Value
	var at string
	if err != nil || len(raw) > 4<<10 || jsontext.Value(raw).Kind() != '{' || json.Unmarshal(raw, &body) != nil ||
		len(body) != 1 || body["restored_at"].Kind() != '"' || json.Unmarshal(body["restored_at"], &at) != nil ||
		!settings.ValidRecoveryTime(at) {
		writeRecoveryJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid recovery review"})
		return
	}
	ok, err := rc.sys.settings.ReviewRecovery(r.Context(), p.UserID, at)
	if err != nil {
		rc.fail(w, r, err)
		return
	}
	if !ok {
		writeRecoveryJSON(w, http.StatusConflict, map[string]any{"error": "The restore marker changed. Review the current checklist.",
			"code": "restore_changed"})
		return
	}
	writeRecoveryJSON(w, http.StatusOK, map[string]any{"restored_at": at, "needs_review": false})
}

func (rc *recoveryCheck) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		rc.sys.log.ErrorContext(r.Context(), "recovery check failed", "err", err)
	}
	writeRecoveryJSON(w, status, map[string]any{"success": false, "code": string(code), "error": message})
}

func writeRecoveryJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
	_, _ = io.WriteString(w, "\n")
}
