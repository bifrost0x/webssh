package hosts

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// RecordIdentityAttempt records when the identity probe last ran; stored
// facts other than a legacy "server" stay (record_identity_attempt). Only
// one number is set, so the store does not grow with repeated attempts.
// It reports false, without an error, when the store limits refuse even
// that; the caller then keeps the attempt in memory.
func (s *Service) RecordIdentityAttempt(ctx context.Context, owner int64, id string, ep Login, at time.Time) (bool, error) {
	_, found, _, err := s.updateProfile(ctx, owner, id, ep, func(r *record) bool {
		r.set("platform_checked_at", stamp(at))
		// The old probe's "server" would otherwise bring the probe back on
		// every login.
		if p, _ := r.str("detected_platform"); p == "server" {
			r.del("detected_platform")
		}
		return true
	})
	if isQuota(err) {
		return false, nil
	}
	return found && err == nil, err
}

// CacheMaintenance stores the update and restart facts of a run of
// MaintenanceScript (cache_detected_facts with maintenance), stamped with
// the time of the run.
func (s *Service) CacheMaintenance(ctx context.Context, owner int64, id string, ep Login, m Maintenance, now time.Time) (bool, error) {
	value := func(v any) jsontext.Value {
		if j, ok := factValue(v); ok {
			return j
		}
		return jsonNull
	}
	facts := record{members: []member{
		{"reboot_required", value(m.RebootRequired)},
		{"updates", value(m.Updates)},
		{"security_updates", value(m.SecurityUpdates)},
		{"checked_at", stamp(now)},
	}}
	_, found, _, err := s.updateProfile(ctx, owner, id, ep, func(r *record) bool {
		r.set("detected_maintenance", facts.encode())
		return true
	})
	return found && err == nil, err
}

// MaintenanceOfRun is _record_maintenance_facts without the store: the
// facts of an automation step that ran exactly MaintenanceScript without
// sudo, succeeded with exit status 0 and was not cut short. ok is false for
// any other step and for a host that reported nothing, which keeps its last
// facts. The host still controls the values; they are shown as reported,
// never acted on.
func MaintenanceOfRun(command string, sudo, succeeded bool, exitStatus int, truncated bool, stdout string) (Maintenance, bool) {
	if command != MaintenanceScript || sudo || !succeeded || exitStatus != 0 || truncated {
		return Maintenance{}, false
	}
	m, err := ParseMaintenance(stdout)
	if err != nil || !m.Known() {
		return Maintenance{}, false
	}
	return m, true
}

// maintenanceFacts reads detected_maintenance as an object.
func maintenanceFacts(r *record) (record, bool) {
	v, ok := r.get("detected_maintenance")
	if !ok || v.Kind() != '{' {
		return record{}, false
	}
	facts, err := parseRecord(v)
	return facts, err == nil
}

// SettleRebootHint lowers a restart hint (cleared) or stops rechecking it,
// if it is still the one from the check stamped checkedAt
// (settle_reboot_hint). A newer full check replaces the facts and starts
// over; update counts and the check time stay as reported.
func (s *Service) SettleRebootHint(ctx context.Context, owner int64, id string, ep Login, checkedAt jsontext.Value, cleared bool) (bool, error) {
	_, found, changed, err := s.updateProfile(ctx, owner, id, ep, func(r *record) bool {
		facts, ok := maintenanceFacts(r)
		if !ok {
			return false
		}
		reboot, _ := facts.get("reboot_required")
		stopped, _ := facts.get("recheck_stopped")
		at, _ := facts.get("checked_at")
		if string(reboot) != "true" || truthy(stopped) || string(at) != string(checkedAt) {
			return false
		}
		if cleared {
			facts.set("reboot_required", jsonFalse)
		} else {
			facts.set("recheck_stopped", jsonTrue)
		}
		r.set("detected_maintenance", facts.encode())
		return true
	})
	return found && changed && err == nil, err
}

// Greeting is what a reachability check read from a saved direct host's
// SSH greeting: the canonical host and port probed and the platform the
// greeting named ("" for none, which drops an older hint).
type Greeting struct {
	Host     string
	Port     int
	Platform string
}

// CacheGreetingPlatforms records the greeting hints of saved direct hosts
// and returns how many changed (cache_greeting_platforms). The greeting
// was read without authentication, so it is a display hint only: it never
// removes stored facts and never decides whether the identity probe runs.
// A host edited meanwhile, routed through a jump host or proxy, or already
// showing the same hint is left alone.
func (s *Service) CacheGreetingPlatforms(ctx context.Context, owner int64, observed map[string]Greeting) (int, error) {
	changed := 0
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		next := slices.Clone(all["profiles"])
		for i := range next {
			r := &next[i]
			g, ok := observed[r.text("id")]
			if !ok || (g.Platform != "" && !platforms[g.Platform]) {
				continue
			}
			jump, _ := r.get("jump_host_id")
			socks, _ := r.get("socks_proxy_id")
			if truthy(jump) || truthy(socks) {
				continue
			}
			host, ok := canonicalHost(r.text("host"))
			port := int64(22)
			if v, has := r.get("port"); has && truthy(v) {
				port, ok = pyInt(v)
			}
			current, _ := r.str("greeting_platform")
			if !ok || host != g.Host || port != int64(g.Port) || current == g.Platform {
				continue
			}
			c := r.clone()
			if g.Platform == "" {
				c.del("greeting_platform")
			} else {
				c.set("greeting_platform", jsonString(g.Platform))
			}
			next[i] = c
			changed++
		}
		if changed == 0 {
			return nil
		}
		if err := checkGrowth(s.Limits, profileKind, all, next); err != nil {
			return err
		}
		return replace(ctx, tx, profileTable, owner, next)
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

// identityNeeded is identity_needed: only saved hosts with the automatic
// icon are probed, at most once a week. A manual icon turns probing off.
// A stored greeting hint does not: it may come from an unauthenticated
// greeting.
func identityNeeded(r *record, now time.Time) bool {
	if icon, ok := r.get("platform_icon"); ok && !isNull(icon) {
		if s, _ := asString(icon); s != "auto" {
			return false
		}
	}
	// "server" came from the old platform probe; the identity probe never
	// reports it.
	if p, _ := r.str("detected_platform"); p == "server" && !r.has("detection_state") {
		return true
	}
	checked, ok := r.get("platform_checked_at")
	at, isNum := number(checked)
	if !ok || !isNum {
		return true
	}
	age := float64(now.UnixMicro())/1e6 - at
	return !(age >= 0 && age < IdentityRefresh.Seconds())
}

// rebootHintNeedsCheck is reboot_hint_needs_check: true only while the
// overview shows a restart hint from a check the user ran.
func rebootHintNeedsCheck(r *record, now time.Time) (checkedAt jsontext.Value, ok bool) {
	facts, ok := maintenanceFacts(r)
	if !ok {
		return nil, false
	}
	reboot, _ := facts.get("reboot_required")
	stopped, _ := facts.get("recheck_stopped")
	at, _ := facts.get("checked_at")
	checked, isNum := number(at)
	if string(reboot) != "true" || truthy(stopped) || !isNum {
		return nil, false
	}
	age := float64(now.UnixMicro())/1e6 - checked
	return at, age >= -SilentRetry.Seconds() && age <= RebootHintMaxAge.Seconds()
}

func isQuota(err error) bool { return fault.CodeOf(err) == fault.QuotaExceeded }
