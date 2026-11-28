package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"

	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// userSettingsStep migrates entity E25, users/user_N/settings.json, into
// settings_user (settings.ImportUser) for every account, also those
// without a file. Defaults that depend on settings_default_generation are
// written explicitly (D-01). The notepad (A05) and the workspace presets
// (A06) have their own steps.
//
// Version 2 also grants every account the one-time upgrade notice
// (settings.NoticeUpgrade) in settings_notices; the stored settings stay
// exactly those of settings.json.
type userSettingsStep struct {
	users []userSettings
}

type userSettings struct {
	id         int64
	generation int64
	doc        jsontext.Value // nil without settings.json
	flags      []string
	result     settings.UserImport
}

func (*userSettingsStep) Entity() string { return "E25" }

func (*userSettingsStep) Version() int { return 2 }

func (*userSettingsStep) accountScoped() bool { return true }

func (s *userSettingsStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		u := userSettings{id: a.ID, generation: a.SettingsDefaultGeneration}
		doc, found, err := userStore(src, a.ID, "settings")
		if err != nil {
			return err
		}
		if found {
			u.doc, u.flags = doc.Raw, documentFlags(doc)
		}
		s.users = append(s.users, u)
	}
	return nil
}

// userStore reads one JSON store of a user; found is false when the file
// does not exist.
func userStore(src *Source, userID int64, store string) (Document, bool, error) {
	for _, spec := range userStores {
		if spec.name != store {
			continue
		}
		doc, err := src.readStore(userDir(userID)+"/"+spec.file, spec)
		if errors.Is(err, ErrNotFound) {
			return Document{}, false, nil
		}
		if err != nil {
			return Document{}, false, &StepError{UserID: userID, Record: spec.file, Err: err}
		}
		return doc, true, nil
	}
	return Document{}, false, fmt.Errorf("legacy: unknown store %q", store)
}

// documentFlags names what reading the document had to normalise.
func documentFlags(doc Document) []string {
	var out []string
	if doc.LoneSurrogates {
		out = append(out, "lone_surrogate")
	}
	if doc.DuplicateNames {
		out = append(out, "duplicate_member_name")
	}
	return out
}

func (s *userSettingsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for i := range s.users {
		u := &s.users[i]
		var err error
		if u.result, err = settings.ImportUser(ctx, tx, u.id, u.doc, u.generation); err != nil {
			return &StepError{UserID: u.id, Record: "settings.json", Err: err}
		}
		if err := settings.GrantNotice(ctx, tx, u.id, settings.NoticeUpgrade); err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
	}
	return nil
}

func (s *userSettingsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		if err := settings.VerifyUser(ctx, tx, u.id, u.doc, u.generation); err != nil {
			return &StepError{UserID: u.id, Record: "settings.json", Err: err}
		}
		if err := settings.VerifyNotice(ctx, tx, u.id, settings.NoticeUpgrade); err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
	}
	return nil
}

func (s *userSettingsStep) Report() StepReport {
	r := StepReport{Entity: "E25", Version: 2}
	for _, u := range s.users {
		if u.doc != nil {
			r.Read++
		}
		r.Written += len(u.result.Keys)
		if len(u.result.Materialised) > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("user %d: written from the previous default: %s", u.id, strings.Join(u.result.Materialised, ", ")))
		}
		for _, f := range u.flags {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: "settings.json", Reason: f})
		}
	}
	return r
}
