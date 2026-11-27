package hosts

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// HerdrOptions reports the Herdr options of a saved host of owner, read
// at this moment (hostops.Profiles): herdr turns on the Herdr overview,
// useHerdr the Herdr session mode. Only the JSON value true counts, as
// profile.get("herdr") is True did; a host that does not exist for owner
// has neither.
func (s *Service) HerdrOptions(ctx context.Context, owner int64, profileID string) (herdr, useHerdr bool, err error) {
	err = s.DB.Read(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		profiles := all["profiles"]
		i := find(profiles, profileID)
		if i < 0 {
			return nil
		}
		h, _ := profiles[i].get("herdr")
		u, _ := profiles[i].get("use_herdr")
		herdr, useHerdr = string(h) == "true", string(u) == "true"
		return nil
	})
	if err != nil {
		return false, false, classify(err, "Failed to load profiles")
	}
	return herdr, herdr && useHerdr, nil
}
