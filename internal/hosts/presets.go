package hosts

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"regexp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Workspace presets (app/customer_workflows.py): up to twelve named
// layouts of one, two or four panes, each with the saved hosts it opens.
// They are stored as the user sent them.

const maxPresets = 12

var presetIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type preset struct {
	id    string
	hosts []string
}

// parsePresets is valid_presets; it returns the presets when the value is
// valid.
func parsePresets(v jsontext.Value) ([]preset, bool) {
	var items []jsontext.Value
	if v.Kind() != '[' || unmarshalArray(v, &items) != nil || len(items) > maxPresets {
		return nil, false
	}
	ids := map[string]bool{}
	out := make([]preset, 0, len(items))
	for _, item := range items {
		r, err := parseRecord(item)
		if err != nil || len(r.members) != 4 {
			return nil, false
		}
		id, idOK := r.str("id")
		name, nameOK := r.str("name")
		layoutValue, _ := r.get("layout")
		layout, layoutOK := asInt(layoutValue)
		hostsValue, hostsOK := r.get("profile_ids")
		if !idOK || !nameOK || !layoutOK || !hostsOK || !r.has("layout") {
			return nil, false
		}
		if !presetIdentifier.MatchString(id) || ids[id] || pyStrip(name) == "" || pyLen(name) > 80 || !printable(name) {
			return nil, false
		}
		if layout != 1 && layout != 2 && layout != 4 {
			return nil, false
		}
		var hostValues []jsontext.Value
		if hostsValue.Kind() != '[' || unmarshalArray(hostsValue, &hostValues) != nil || int64(len(hostValues)) > layout {
			return nil, false
		}
		seen := map[string]bool{}
		p := preset{id: id}
		for _, hv := range hostValues {
			h, ok := asString(hv)
			if !ok || !presetIdentifier.MatchString(h) || seen[h] {
				return nil, false
			}
			seen[h] = true
			p.hosts = append(p.hosts, h)
		}
		ids[id] = true
		out = append(out, p)
	}
	return out, true
}

func validPresets(v jsontext.Value) bool {
	_, ok := parsePresets(v)
	return ok
}

func printable(s string) bool {
	for _, r := range s {
		if !pyPrintable(r) {
			return false
		}
	}
	return true
}

func loadPresets(ctx context.Context, tx *store.Tx, owner int64) (jsontext.Value, bool, error) {
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT presets FROM hosts_workspace_presets WHERE user_id = ?`, owner).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("hosts: read workspace presets: %w", err)
	}
	return jsontext.Value(raw), true, nil
}

func storePresets(ctx context.Context, tx *store.Tx, owner int64, presets jsontext.Value) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO hosts_workspace_presets (user_id, presets) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET presets = excluded.presets`, owner, string(presets))
	if err != nil {
		return fmt.Errorf("hosts: write workspace presets: %w", err)
	}
	return nil
}

var emptyList = jsontext.Value("[]")

// WorkspacePresets returns the presets of owner, [] when there are none.
func (s *Service) WorkspacePresets(ctx context.Context, owner int64) (jsontext.Value, error) {
	var out jsontext.Value
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		presets, found, err := loadPresets(ctx, tx, owner)
		out = emptyList
		if found {
			out = presets
		}
		return err
	})
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "Could not load workspace presets")
	}
	return out, nil
}

var (
	errInvalidPresets = fault.New(fault.InvalidValue, "Invalid workspace presets")
	errPresetHosts    = fault.New(fault.InvalidValue, "Choose existing hosts from your account")
)

// SaveWorkspacePresets replaces the presets of owner. A preset may name
// only the user's saved hosts, or hosts it already named before (a host
// deleted meanwhile does not block saving the rest).
func (s *Service) SaveWorkspacePresets(ctx context.Context, owner int64, presets jsontext.Value) (jsontext.Value, error) {
	presets, err := canonical(presets)
	if err != nil {
		return nil, errInvalidPresets
	}
	next, ok := parsePresets(presets)
	if !ok {
		return nil, errInvalidPresets
	}
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		owned := map[string]bool{}
		for i := range profiles {
			if id, ok := profiles[i].str("id"); ok {
				owned[id] = true
			}
		}
		stored, found, err := loadPresets(ctx, tx, owner)
		if err != nil {
			return err
		}
		previous := map[string]map[string]bool{}
		if found {
			old, _ := parsePresets(stored)
			for _, p := range old {
				previous[p.id] = map[string]bool{}
				for _, h := range p.hosts {
					previous[p.id][h] = true
				}
			}
		}
		for _, p := range next {
			for _, h := range p.hosts {
				if !owned[h] && !previous[p.id][h] {
					return errPresetHosts
				}
			}
		}
		return storePresets(ctx, tx, owner, presets)
	})
	if err != nil {
		if _, ok := fault.From(err); ok {
			return nil, err
		}
		return nil, fault.Wrap(fault.StorageError, err, "Could not save workspace presets")
	}
	return presets, nil
}
