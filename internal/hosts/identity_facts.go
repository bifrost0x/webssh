package hosts

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Login is one login on one host: what a detection learned stays with
// the saved host while host, port, user and route stay the same
// (host_platform.endpoint). Host is the configured name.
type Login struct {
	Host         string
	Port         int
	User         string
	JumpHostID   string
	SOCKSProxyID string
}

// key is endpointOf for the endpoint, "" for one that is not valid.
func (e Login) key() string {
	host, ok := canonicalHost(e.Host)
	if !ok || e.User == "" || e.Port < 1 || e.Port > 65535 {
		return ""
	}
	route := func(id string) string {
		if id == "" {
			return "null"
		}
		return string(jsonString(id))
	}
	quoted, _ := jsontext.AppendQuote(nil, host)
	return string(quoted) + "|" + strconv.Itoa(e.Port) + "|" + string(jsonString(e.User)) + "|" +
		route(e.JumpHostID) + "|" + route(e.SOCKSProxyID)
}

// Detection intervals (IDENTITY_REFRESH_SECONDS, SILENT_RETRY_SECONDS).
const (
	IdentityRefresh = 7 * 24 * time.Hour
	SilentRetry     = 24 * time.Hour
	// RebootHintMaxAge matches the overview, which stops showing facts
	// older than a week.
	RebootHintMaxAge = 7 * 24 * time.Hour
)

// stamp is time.time() as Python stores it: seconds as a float.
func stamp(t time.Time) jsontext.Value {
	s := strconv.FormatFloat(float64(t.UnixMicro())/1e6, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return jsontext.Value(s)
}

func number(v jsontext.Value) (float64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(v), 64)
	return f, err == nil
}

// updateProfile changes the saved host id of owner, if it still has the
// login ep, under the store lock: change returns whether it changed the
// record. The write keeps the store limits. found is false when the host
// is gone or its endpoint changed meanwhile.
func (s *Service) updateProfile(ctx context.Context, owner int64, id string, ep Login,
	change func(r *record) bool) (saved record, found, changed bool, err error) {
	key := ep.key()
	if key == "" {
		return record{}, false, false, nil
	}
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		profiles := all["profiles"]
		index := find(profiles, id)
		if index < 0 || endpointOf(&profiles[index]) != key {
			return nil
		}
		found = true
		next := slices.Clone(profiles)
		r := profiles[index].clone()
		if changed = change(&r); !changed {
			saved = r
			return nil
		}
		next[index] = r
		if err := checkGrowth(s.Limits, profileKind, all, next); err != nil {
			return err
		}
		saved = r
		return replace(ctx, tx, profileTable, owner, next)
	})
	if err != nil {
		return record{}, false, false, err
	}
	return saved, found, changed, nil
}

// RecordConnectGreeting stores the platform that a connection's
// authenticated SSH version string named ("" for none), and returns the
// stored record and whether it changed (record_connect_greeting). Unlike
// the overview's greeting it came from the host-key-verified transport,
// so it may change detection: a system without a POSIX shell drops what
// the probe found at this endpoint before, and a greeting that differs
// from the previous logged-in one makes the probe due again, at most once
// a day.
func (s *Service) RecordConnectGreeting(ctx context.Context, owner int64, id string, ep Login, platform string, now time.Time) (jsontext.Value, bool, error) {
	if platform != "" && !platforms[platform] {
		return nil, false, nil
	}
	saved, found, changed, err := s.updateProfile(ctx, owner, id, ep, func(r *record) bool {
		previous, hadPrevious := r.str("authenticated_greeting")
		hadPrevious = hadPrevious || r.has("authenticated_greeting")
		greeting, _ := r.str("greeting_platform")
		changed := !hadPrevious || previous != platform || greeting != platform
		if nonPOSIXPlatforms[platform] {
			for _, field := range append([]string{"detected_platform"}, endpointFacts...) {
				if field != "authenticated_greeting" && r.has(field) {
					r.del(field)
					changed = true
				}
			}
		} else if hadPrevious && previous != platform {
			if checked, ok := r.get("platform_checked_at"); ok {
				if at, isNum := number(checked); isNum {
					age := float64(now.UnixMicro())/1e6 - at
					if age >= SilentRetry.Seconds() && age < (IdentityRefresh-SilentRetry).Seconds() {
						r.del("platform_checked_at")
					}
				}
			}
		}
		if !changed {
			return false
		}
		r.set("authenticated_greeting", jsonString(platform))
		if platform == "" {
			r.del("greeting_platform")
		} else {
			r.set("greeting_platform", jsonString(platform))
		}
		return true
	})
	if err != nil || !found {
		return nil, false, err
	}
	return saved.encode(), changed, nil
}

type fact struct {
	field string
	value any
}

// identityFields maps the stored identity facts to their values
// (_IDENTITY_FACTS, in its order).
func identityFields(id Identity) []fact {
	return []fact{
		{"detected_family", id.Family}, {"detected_os_id", id.OSID}, {"detected_os_version", id.OSVersion},
		{"detected_virt", id.Virt}, {"detected_container_access", id.ContainerAccess},
		{"detected_guests", id.Guests}, {"detected_graphical", id.Graphical},
	}
}

func factValue(v any) (jsontext.Value, bool) {
	switch v := v.(type) {
	case string:
		return jsonString(v), v != ""
	case *int:
		if v == nil {
			return nil, false
		}
		return jsonInt(int64(*v)), true
	case *bool:
		if v == nil {
			return nil, false
		}
		if *v {
			return jsonTrue, true
		}
		return jsonFalse, true
	}
	return nil, false
}

// CacheIdentity merges a probed identity into the saved host
// (cache_detected_facts with identity). A detected identity replaces every
// stored identity fact; one that could not be read records the attempt and
// keeps what an earlier probe found. With keepDetected, such an attempt
// leaves a "detected" state as it is.
func (s *Service) CacheIdentity(ctx context.Context, owner int64, id string, ep Login, identity Identity, now time.Time, keepDetected bool) (bool, error) {
	if identity.State != StateDetected && identity.State != StateUnavailable {
		return false, nil
	}
	at := stamp(now)
	_, found, _, err := s.updateProfile(ctx, owner, id, ep, func(r *record) bool {
		state, _ := r.str("detection_state")
		if !(keepDetected && identity.State != StateDetected && state == StateDetected) {
			r.set("detection_state", jsonString(identity.State))
		}
		r.set("platform_checked_at", at)
		if p, _ := r.str("detected_platform"); p == "server" {
			r.del("detected_platform")
		}
		if identity.State == StateDetected {
			list := make([]jsontext.Value, len(identity.Services))
			for i, svc := range identity.Services {
				list[i] = jsonString(svc)
			}
			if identity.Platform != "" {
				r.set("detected_platform", jsonString(identity.Platform))
			} else {
				r.del("detected_platform")
			}
			r.set("detected_services", arrayValue(list))
			for _, f := range identityFields(identity) {
				if v, ok := factValue(f.value); ok {
					r.set(f.field, v)
				} else {
					r.del(f.field)
				}
			}
			r.set("services_checked_at", at)
		}
		return true
	})
	return found && err == nil, err
}

func arrayValue(items []jsontext.Value) jsontext.Value {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(v)
	}
	b.WriteByte(']')
	return jsontext.Value(b.String())
}
