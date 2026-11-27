package hostops

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/store"
)

// Profiles lists the ids of the saved hosts of a user (provided by
// internal/hosts). A host context exists only for these.
type Profiles interface {
	ProfileIDs(ctx context.Context, owner int64) ([]string, error)
}

// CommandSets tells whether a user owns a command set (provided by
// internal/commands, M2 contracts: Library.SetExists).
type CommandSets interface {
	SetExists(ctx context.Context, userID int64, setID string) (bool, error)
}

// ContextError is a refused host-context request. Code is the code of the
// Python release, which the page reads: not_found, invalid,
// invalid_reference, conflict or quota.
type ContextError struct{ Code string }

func (e *ContextError) Error() string { return "hostops: host context: " + e.Code }

func contextError(code string) error { return &ContextError{Code: code} }

// Contexts keeps the host contexts of every user: notes, favourite
// directories and command-set references of one saved host, with one
// revision for the whole context (C-CONN-13, D-11).
type Contexts struct {
	DB       *store.DB
	Profiles Profiles
	// Sets checks command-set references. Without it only references that
	// are already stored for the host are accepted, so saving a context
	// never drops or invents a reference while command sets are not built.
	Sets CommandSets
}

func (c *Contexts) owned(ctx context.Context, owner int64, profileID string) ([]string, error) {
	if profileID == "" || utf8.RuneCountInString(profileID) > MaxContextProfileID {
		return nil, contextError("not_found")
	}
	ids, err := c.Profiles.ProfileIDs(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("hostops: list profiles: %w", err)
	}
	if !slices.Contains(ids, profileID) {
		return nil, contextError("not_found")
	}
	return ids, nil
}

// Read returns the context of one saved host of owner; an empty context
// with revision 0 when none was saved.
func (c *Contexts) Read(ctx context.Context, owner int64, profileID string) (HostContext, error) {
	if _, err := c.owned(ctx, owner, profileID); err != nil {
		return HostContext{}, err
	}
	var hc HostContext
	err := c.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		hc, _, err = ContextTx(ctx, tx, owner, profileID)
		return err
	})
	return hc, err
}

// Write replaces the context of one saved host when expected is its
// current revision, and returns the stored context with the next
// revision. Contexts of hosts that no longer exist are removed in the same
// transaction, as the Python release pruned them on every write.
func (c *Contexts) Write(ctx context.Context, owner int64, profileID string, content Content, expected int64) (HostContext, error) {
	if !validContent(content) || contentSize(content) > MaxContextContent {
		return HostContext{}, contextError("invalid")
	}
	ids, err := c.owned(ctx, owner, profileID)
	if err != nil {
		return HostContext{}, err
	}
	var stored []string
	if c.Sets == nil {
		current, err := c.Read(ctx, owner, profileID)
		if err != nil {
			return HostContext{}, err
		}
		stored = current.CommandSets
	}
	for _, ref := range content.CommandSets {
		ok := slices.Contains(stored, ref)
		if c.Sets != nil {
			if ok, err = c.Sets.SetExists(ctx, owner, ref); err != nil {
				return HostContext{}, fmt.Errorf("hostops: check command set: %w", err)
			}
		}
		if !ok {
			return HostContext{}, contextError("invalid_reference")
		}
	}
	updated := HostContext{Content: content, Revision: expected + 1}
	err = c.DB.Write(ctx, func(tx *store.Tx) error {
		previous, _, err := ContextTx(ctx, tx, owner, profileID)
		if err != nil {
			return err
		}
		if expected != previous.Revision {
			return contextError("conflict")
		}
		if err := prune(ctx, tx, owner, ids); err != nil {
			return err
		}
		if err := putContext(ctx, tx, owner, profileID, updated); err != nil {
			return err
		}
		return withinQuota(ctx, tx, owner)
	})
	if err != nil {
		return HostContext{}, err
	}
	return updated, nil
}

// prune removes the contexts and host notes of profiles that are gone.
func prune(ctx context.Context, tx *store.Tx, owner int64, ids []string) error {
	keep, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM hostops_host_context WHERE user_id = ? AND profile_id NOT IN (SELECT value FROM json_each(?))`,
		`DELETE FROM hostops_notes WHERE user_id = ? AND profile_id IS NOT NULL AND profile_id NOT IN (SELECT value FROM json_each(?))`,
	} {
		if _, err := tx.ExecContext(ctx, q, owner, string(keep)); err != nil {
			return fmt.Errorf("hostops: prune host contexts: %w", err)
		}
	}
	return nil
}

func putContext(ctx context.Context, tx *store.Tx, owner int64, profileID string, hc HostContext) error {
	if err := storeLists(ctx, tx, owner, profileID, hc.Directories, hc.CommandSets, hc.Revision, true); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hostops_notes WHERE user_id = ? AND profile_id = ?`, owner, profileID); err != nil {
		return fmt.Errorf("hostops: save host notes: %w", err)
	}
	if hc.Notes == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hostops_notes (user_id, profile_id, body, revision) VALUES (?, ?, ?, ?)`,
		owner, profileID, hc.Notes, hc.Revision); err != nil {
		return fmt.Errorf("hostops: save host notes: %w", err)
	}
	return nil
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// withinQuota refuses more than MaxHostContexts contexts or a document
// larger than MaxContextStoreBytes, measured as the Python release wrote
// host_context.json.
func withinQuota(ctx context.Context, tx *store.Tx, owner int64) error {
	all, err := contextsTx(ctx, tx, owner)
	if err != nil {
		return err
	}
	if len(all) > MaxHostContexts {
		return contextError("quota")
	}
	size := contextDocumentPrefix
	i := 0
	for id, hc := range all {
		if i > 0 {
			size += len(", ")
		}
		size += entrySize(id, hc)
		i++
	}
	if size > MaxContextStoreBytes {
		return contextError("quota")
	}
	return nil
}

// ContextTx returns the context of one saved host inside tx. found is
// false when neither a context nor a host note is stored; the revision of
// a context that has only a note (migrated by an earlier build) is the
// note's revision.
func ContextTx(ctx context.Context, tx *store.Tx, owner int64, profileID string) (hc HostContext, found bool, err error) {
	var dirs, sets string
	err = tx.QueryRowContext(ctx, `SELECT directories, command_sets, revision FROM hostops_host_context
WHERE user_id = ? AND profile_id = ?`, owner, profileID).Scan(&dirs, &sets, &hc.Revision)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return HostContext{}, false, fmt.Errorf("hostops: read host context: %w", err)
	default:
		found = true
		if err := decodeLists(dirs, sets, &hc); err != nil {
			return HostContext{}, false, err
		}
	}
	body, revision, noted, err := NoteTx(ctx, tx, owner, profileID)
	if err != nil {
		return HostContext{}, false, err
	}
	if noted {
		hc.Notes = body
		if !found {
			hc.Revision = revision
		}
	}
	hc.Directories, hc.CommandSets = nonNil(hc.Directories), nonNil(hc.CommandSets)
	return hc, found || noted, nil
}

func decodeLists(dirs, sets string, hc *HostContext) error {
	if err := json.Unmarshal([]byte(dirs), &hc.Directories); err != nil {
		return fmt.Errorf("hostops: stored directories: %w", err)
	}
	if err := json.Unmarshal([]byte(sets), &hc.CommandSets); err != nil {
		return fmt.Errorf("hostops: stored command sets: %w", err)
	}
	return nil
}

// contextsTx returns every context of owner, including those with only a
// note, by profile id.
func contextsTx(ctx context.Context, tx *store.Tx, owner int64) (map[string]HostContext, error) {
	out := map[string]HostContext{}
	err := eachRow(ctx, tx, `SELECT profile_id, directories, command_sets, revision FROM hostops_host_context WHERE user_id = ?`,
		owner, func(rows *sql.Rows) error {
			var id, dirs, sets string
			var hc HostContext
			if err := rows.Scan(&id, &dirs, &sets, &hc.Revision); err != nil {
				return err
			}
			if err := decodeLists(dirs, sets, &hc); err != nil {
				return err
			}
			out[id] = hc
			return nil
		})
	if err != nil {
		return nil, err
	}
	err = eachRow(ctx, tx, `SELECT profile_id, body, revision FROM hostops_notes WHERE user_id = ? AND profile_id IS NOT NULL`,
		owner, func(rows *sql.Rows) error {
			var id, body string
			var revision int64
			if err := rows.Scan(&id, &body, &revision); err != nil {
				return err
			}
			hc, found := out[id]
			if !found {
				hc.Revision = revision
			}
			hc.Notes = body
			out[id] = hc
			return nil
		})
	return out, err
}

func eachRow(ctx context.Context, tx *store.Tx, query string, owner int64, scan func(*sql.Rows) error) error {
	rows, err := tx.QueryContext(ctx, query, owner)
	if err != nil {
		return fmt.Errorf("hostops: list host contexts: %w", err)
	}
	for rows.Next() {
		if err := scan(rows); err != nil {
			_ = rows.Close()
			return fmt.Errorf("hostops: list host contexts: %w", err)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("hostops: list host contexts: %w", err)
	}
	return nil
}

// ImportContext stores the directories and command-set references of one
// legacy host context with its revision, inside the migration's
// transaction. The notes of the context are imported with ImportNote.
func ImportContext(ctx context.Context, tx *store.Tx, owner int64, profileID string, directories, commandSets []string, revision int64) error {
	if revision < 1 {
		return fmt.Errorf("hostops: host context revision %d is not positive", revision)
	}
	if profileID == "" || utf8.RuneCountInString(profileID) > MaxContextProfileID {
		return fmt.Errorf("hostops: invalid profile id for a host context")
	}
	return storeLists(ctx, tx, owner, profileID, directories, commandSets, revision, false)
}

// storeLists writes the lists of one context; without upsert an existing
// row is an error (the migration writes each context once).
func storeLists(ctx context.Context, tx *store.Tx, owner int64, profileID string, directories, commandSets []string, revision int64, upsert bool) error {
	dirs, err := json.Marshal(nonNil(directories))
	if err != nil {
		return err
	}
	sets, err := json.Marshal(nonNil(commandSets))
	if err != nil {
		return err
	}
	q := `INSERT INTO hostops_host_context (user_id, profile_id, directories, command_sets, revision) VALUES (?, ?, ?, ?, ?)`
	if upsert {
		q += ` ON CONFLICT (user_id, profile_id) DO UPDATE SET
directories = excluded.directories, command_sets = excluded.command_sets, revision = excluded.revision`
	}
	if _, err := tx.ExecContext(ctx, q, owner, profileID, string(dirs), string(sets), revision); err != nil {
		return fmt.Errorf("hostops: store host context: %w", err)
	}
	return nil
}
