package hosts

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// Profiles returns the saved hosts of owner in list order (list_profiles).
func (s *Service) Profiles(ctx context.Context, owner int64) ([]jsontext.Value, error) {
	var out []jsontext.Value
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		authorized := s.tailscaleAuthorized(ctx)
		for _, r := range profiles {
			out = append(out, publicProfile(r, authorized))
		}
		return err
	})
	if err != nil {
		return nil, classify(err, "Failed to load profiles")
	}
	if out == nil {
		out = []jsontext.Value{}
	}
	return out, nil
}

// DeleteProfile removes a saved host (delete_profile).
func (s *Service) DeleteProfile(ctx context.Context, owner int64, profileID jsontext.Value) error {
	if !truthy(profileID) {
		return invalid("Profile ID required")
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		id, _ := asString(profileID)
		index := -1
		if profileID.Kind() == '"' {
			index = find(profiles, id)
		}
		if index < 0 {
			return errProfileNotFound
		}
		return replace(ctx, tx, profileTable, owner, slices.Delete(slices.Clone(profiles), index, index+1))
	})
	return classify(err, "Failed to delete profile")
}

// OrganizeProfile changes only the group or favorite flag of a saved host
// (update_profile_organization).
func (s *Service) OrganizeProfile(ctx context.Context, owner int64, req protocol.HostsProfileOrganize) (jsontext.Value, error) {
	id, ok := asString(req.ProfileID)
	if !ok || id == "" {
		return nil, invalid("Profile ID required")
	}
	hasGroup, hasFavorite := len(req.Group) > 0, len(req.Favorite) > 0
	if !hasGroup && !hasFavorite {
		return nil, invalid("No organization fields provided")
	}
	var group string
	if hasGroup {
		g, ok := asString(req.Group)
		if !ok {
			return nil, invalid("Invalid group")
		}
		if group = pyStrip(g); pyLen(group) > maxGroupLength {
			return nil, invalid("Group must not exceed 64 characters")
		}
	}
	if hasFavorite && !isBool(req.Favorite) {
		return nil, invalid("favorite must be a boolean")
	}
	var saved record
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		profiles := cloneRecords(all["profiles"])
		index := find(profiles, id)
		if index < 0 {
			return errProfileNotFound
		}
		previous := profiles[index]
		r := previous.clone()
		if hasGroup {
			if group != "" {
				r.set("group", jsonString(group))
			} else {
				r.del("group")
			}
		}
		if hasFavorite {
			if string(req.Favorite) == "true" {
				r.set("favorite", jsonTrue)
			} else {
				r.del("favorite")
			}
		}
		r.set("updated_at", jsonString(isoUTC(s.now())))
		if err := checkBudgets(&r, &previous, profileBudgets, true); err != nil {
			return err
		}
		profiles[index] = r
		saved = r
		if err := checkGrowth(s.Limits, profileKind, all, profiles); err != nil {
			return err
		}
		return replace(ctx, tx, profileTable, owner, profiles)
	})
	if err != nil {
		return nil, classify(err, "Failed to save profile")
	}
	return publicProfile(saved, s.tailscaleAuthorized(ctx)), nil
}

// MoveProfile moves a saved host to a position in a group in one step
// (move_profile). Moving the last host out of a group removes the group
// and needs confirmation; the refusal names the host and the group.
func (s *Service) MoveProfile(ctx context.Context, owner int64, req protocol.HostsProfileMove) (protocol.HostsMoved, error) {
	id, ok := asString(req.ProfileID)
	if !ok || id == "" {
		return protocol.HostsMoved{}, invalid("Profile ID required")
	}
	source, ok := asString(req.ExpectedSourceGroup)
	if !ok {
		return protocol.HostsMoved{}, invalid("Invalid source group")
	}
	target, ok := asString(req.TargetGroup)
	if !ok {
		return protocol.HostsMoved{}, invalid("Invalid target group")
	}
	source, target = pyStrip(source), pyStrip(target)
	if pyLen(source) > maxGroupLength || pyLen(target) > maxGroupLength {
		return protocol.HostsMoved{}, invalid("Group must not exceed 64 characters")
	}
	targetIndex, ok := asInt(req.TargetIndex)
	if !isIntegerToken(req.TargetIndex) || (ok && targetIndex < 0) || (!ok && string(req.TargetIndex)[0] == '-') {
		return protocol.HostsMoved{}, invalid("Invalid target index")
	}
	if !ok {
		targetIndex = 1 << 62 // beyond any group: append
	}
	confirmed := false
	if len(req.ConfirmSourceGroupRemoval) > 0 {
		if !isBool(req.ConfirmSourceGroupRemoval) {
			return protocol.HostsMoved{}, invalid("Invalid confirmation value")
		}
		confirmed = string(req.ConfirmSourceGroupRemoval) == "true"
	}
	var moved []record
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		next, err := moveProfile(all["profiles"], id, source, target, targetIndex, confirmed, jsonString(isoUTC(s.now())))
		if err != nil {
			return err
		}
		if err := checkGrowth(s.Limits, profileKind, all, next); err != nil {
			return err
		}
		moved = next
		return replace(ctx, tx, profileTable, owner, next)
	})
	if err != nil {
		if fe, ok := fault.From(err); ok && fe.Code == fault.Conflict {
			return protocol.HostsMoved{}, err
		}
		if fault.Is(err, fault.NotFound) || fault.Is(err, fault.QuotaExceeded) {
			return protocol.HostsMoved{}, withOrganization(err, nil)
		}
		return protocol.HostsMoved{}, withOrganization(classify(err, "Failed to move profile"), nil)
	}
	return protocol.HostsMoved{Organization: wirePlacements(placementsOf(moved, true))}, nil
}

func moveProfile(profiles []record, id, source, target string, targetIndex int64, confirmed bool, now jsontext.Value) ([]record, error) {
	profiles = cloneRecords(profiles)
	index := find(profiles, id)
	if index < 0 {
		return nil, errProfileNotFound
	}
	previous := profiles[index]
	profile := previous.clone()
	sourceKey := recordGroupKey(&profile)
	if sourceKey != groupKey(source) {
		return nil, withOrganization(fault.New(fault.Conflict, "Profile group changed; retry move"), profiles)
	}
	targetKey := groupKey(target)
	changesGroup := sourceKey != targetKey
	if sourceKey != "" && changesGroup && len(orderedGroup(profiles, sourceKey, nil)) == 1 && !confirmed {
		group, _ := profile.get("group")
		return nil, &fault.Error{
			Code:    fault.Conflict,
			Message: "Confirm removing the group.",
			Details: map[string]any{
				"requires_confirmation": true,
				"profile_id":            id,
				"profile_name":          profile.text("name"),
				"source_group":          group,
			},
		}
	}
	targetMembers := orderedGroup(profiles, targetKey, &id)
	at := len(targetMembers)
	if targetIndex < int64(at) {
		at = int(targetIndex)
	}
	targetMembers = slices.Insert(targetMembers, at, index)
	if changesGroup {
		if target != "" {
			profile.set("group", jsonString(target))
		} else {
			profile.del("group")
		}
		profiles[index] = profile
		for pos, member := range orderedGroup(profiles, sourceKey, &id) {
			profiles[member].set("sort_order", jsonInt(int64(pos)))
		}
	}
	profiles[index] = profile
	for pos, member := range targetMembers {
		profiles[member].set("sort_order", jsonInt(int64(pos)))
		if member == index {
			profiles[member].set("updated_at", now)
		}
	}
	if err := checkBudgets(&profiles[index], &previous, profileBudgets, true); err != nil {
		return nil, err
	}
	return profiles, nil
}

// withOrganization attaches what Python sent beside a failed move: no
// confirmation needed and the current placement of every host.
func withOrganization(err error, profiles []record) error {
	fe, ok := fault.From(err)
	if !ok {
		return err
	}
	out := *fe
	out.Details = map[string]any{
		"requires_confirmation": false,
		"organization":          wirePlacements(placementsOf(profiles, false)),
	}
	return &out
}

func wirePlacements(in []placement) []protocol.HostsPlacement {
	out := make([]protocol.HostsPlacement, len(in))
	for i, pl := range in {
		out[i] = protocol.HostsPlacement{ID: pl.id, Group: pl.group, SortOrder: pl.sort, UpdatedAt: pl.updated}
	}
	return out
}

// ProfileIDs lists the ids of the saved hosts of owner (provided to
// internal/hostops for the host context).
func (s *Service) ProfileIDs(ctx context.Context, owner int64) ([]string, error) {
	var ids []string
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		for _, p := range profiles {
			if id, ok := p.str("id"); ok {
				ids = append(ids, id)
			}
		}
		return err
	})
	if err != nil {
		return nil, classify(err, "Failed to load profiles")
	}
	return ids, nil
}
