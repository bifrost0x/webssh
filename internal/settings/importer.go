package settings

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// ErrLegacyDocument marks a legacy settings document the Python release
// would not load. The migration stops on it (E16, E25).
var ErrLegacyDocument = errors.New("settings: invalid legacy settings document")

// UserImport is the outcome of importing one account's settings.json.
type UserImport struct {
	// Keys are the settings stored for the account, sorted.
	Keys []string
	// Materialised are the keys written from the legacy behaviour (D-01)
	// rather than copied, sorted.
	Materialised []string
	// Notepad is the legacy notepad text for the note without a host
	// (A05); "" when absent. WorkspacePresets is the raw legacy value for
	// the hosts (A06), nil when absent. Both are left to their owners.
	Notepad          string
	WorkspacePresets jsontext.Value
	// LoneSurrogates reports strings with an escaped unpaired UTF-16
	// surrogate; they were read as U+FFFD, as the legacy reader does.
	LoneSurrogates bool
}

// ImportUser stores the settings of one account of the Python release in
// the migration transaction. doc is the content of
// users/user_N/settings.json after the legacy reader has applied the
// Python storage migrations (schema 2), or nil when the account has no
// file. Every key is copied verbatim, unknown keys included. Defaults that
// depend on settings_default_generation are written explicitly (D-01):
// accounts below generation 1 keep confirm_session_close = true.
// The notepad and the workspace presets are returned, not stored.
func ImportUser(ctx context.Context, tx *store.Tx, userID int64, doc jsontext.Value, settingsDefaultGeneration int64) (UserImport, error) {
	if userID <= 0 {
		return UserImport{}, fmt.Errorf("%w: user id %d", ErrLegacyDocument, userID)
	}
	var stored map[string]jsontext.Value
	var out UserImport
	if doc != nil {
		parsed, err := parseLegacyDocument(doc)
		if err != nil {
			return UserImport{}, err
		}
		stored, out.Notepad, out.WorkspacePresets = parsed.settings, parsed.notepad, parsed.presets
		out.LoneSurrogates = parsed.lone
	} else {
		stored = map[string]jsontext.Value{}
	}
	if _, ok := stored[keyConfirmSessionClose]; !ok && settingsDefaultGeneration < 1 {
		stored[keyConfirmSessionClose] = jsontext.Value("true")
		out.Materialised = append(out.Materialised, keyConfirmSessionClose)
	}
	for key, v := range stored {
		if err := putUser(ctx, tx, userID, key, v); err != nil {
			return UserImport{}, err
		}
	}
	out.Keys = slices.Sorted(maps.Keys(stored))
	return out, nil
}

// VerifyUser compares the settings stored for an account with the
// effective settings the Python release computes for the same document
// and generation; it is the verification step of E25.
func VerifyUser(ctx context.Context, tx *store.Tx, userID int64, doc jsontext.Value, settingsDefaultGeneration int64) error {
	got, err := readUser(ctx, tx, userID)
	if err != nil {
		return err
	}
	stored := map[string]jsontext.Value{}
	if doc != nil {
		parsed, err := parseLegacyDocument(doc)
		if err != nil {
			return err
		}
		stored = parsed.settings
	}
	if _, ok := stored[keyConfirmSessionClose]; !ok && settingsDefaultGeneration < 1 {
		stored[keyConfirmSessionClose] = jsontext.Value("true")
	}
	want, ok := buildUser(stored)
	if !ok {
		return ErrLegacyDocument
	}
	gotDoc, wantDoc := got.Document(), want.Document()
	if !maps.EqualFunc(gotDoc, wantDoc, func(a, b jsontext.Value) bool { return string(a) == string(b) }) {
		return fmt.Errorf("settings: account %d differs from its legacy settings", userID)
	}
	return nil
}

type legacyDocument struct {
	settings map[string]jsontext.Value
	notepad  string
	presets  jsontext.Value
	lone     bool
}

// parseLegacyDocument checks a settings.json document like
// _valid_settings of the Python release, after reading it like json.loads
// (pythonLoad), and splits it by owner. The version must be the integer
// 2: the Python loader refuses any other type (storage_migrations.py).
func parseLegacyDocument(doc jsontext.Value) (legacyDocument, error) {
	c, lone, err := pythonLoad(doc)
	if err != nil {
		return legacyDocument{}, fmt.Errorf("%w: %v", ErrLegacyDocument, err)
	}
	members, ok := asObject(c)
	if !ok {
		return legacyDocument{}, fmt.Errorf("%w: not an object", ErrLegacyDocument)
	}
	out := legacyDocument{settings: map[string]jsontext.Value{}, lone: lone}
	schemaOK := false
	for _, m := range members {
		switch m.name {
		case legacyKeySchemaVersion:
			n, ok := asInt(m.value)
			schemaOK = ok && n == legacySettingsSchema
		case legacyKeyNotepad:
			s, ok := asString(m.value)
			if !ok {
				return legacyDocument{}, fmt.Errorf("%w: %s", ErrLegacyDocument, m.name)
			}
			out.notepad = s
		case legacyKeyWorkspacePresets:
			out.presets = m.value
		default:
			if !validStored(m.name, m.value) {
				return legacyDocument{}, fmt.Errorf("%w: %s", ErrLegacyDocument, m.name)
			}
			out.settings[m.name] = m.value
		}
	}
	if !schemaOK {
		return legacyDocument{}, fmt.Errorf("%w: schema_version", ErrLegacyDocument)
	}
	return out, nil
}
