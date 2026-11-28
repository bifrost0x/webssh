package smb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// DefaultMaxShares is SMB_MAX_SAVED_SHARES.
const DefaultMaxShares = 100

// maxStoredShares is _MAX_SAVED_SHARE_DOCUMENT_ITEMS: a document with
// more records is unreadable for the Python release.
const maxStoredShares = 1000

// Schema is the store of the saved share definitions (migration spec
// E22). A definition is one row per record in the order of the user's
// list, kept as the JSON object Python stored: unknown non-secret members
// and the member order survive every change. No password is ever stored.
func Schema() store.Schema {
	return store.Schema{Owner: "smb", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE smb_shares (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	position INTEGER NOT NULL CHECK (position >= 0),
	id TEXT NOT NULL,
	record TEXT NOT NULL,
	PRIMARY KEY (user_id, position)
) STRICT;
CREATE INDEX smb_shares_by_id ON smb_shares (user_id, id)`,
	}}}
}

// Shares are the saved share definitions of every user.
type Shares struct {
	DB *store.DB
	// Max is SMB_MAX_SAVED_SHARES (DefaultMaxShares when 0).
	Max int
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Messages of upsert_smb_share and delete_smb_share.
var (
	errShareData    = fault.New(fault.ValidationError, "Invalid SMB share data")
	errShareID      = fault.New(fault.ValidationError, "Invalid SMB share ID")
	errShareName    = fault.New(fault.ValidationError, "An SMB share with this name already exists")
	errShareLimit   = fault.New(fault.ValidationError, "Saved SMB share limit reached")
	errShareMissing = fault.New(fault.NotFound, "SMB share not found")
)

// List returns the definitions of owner in list order.
func (s *Shares) List(ctx context.Context, owner int64) ([]jsontext.Value, error) {
	var out []jsontext.Value
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		out, err = SharesTx(ctx, tx, owner)
		return err
	})
	return out, err
}

// SharesTx reads the definitions of owner in list order.
func SharesTx(ctx context.Context, tx *store.Tx, owner int64) ([]jsontext.Value, error) {
	rows, err := tx.QueryContext(ctx, `SELECT record FROM smb_shares WHERE user_id = ? ORDER BY position`, owner)
	if err != nil {
		return nil, fmt.Errorf("smb: read shares: %w", err)
	}
	defer rows.Close()
	out := []jsontext.Value{}
	for rows.Next() {
		var rec string
		if err := rows.Scan(&rec); err != nil {
			return nil, fmt.Errorf("smb: read shares: %w", err)
		}
		out = append(out, jsontext.Value(rec))
	}
	return out, rows.Err()
}

// Lookup returns the fields of one definition of owner.
func (s *Shares) Lookup(ctx context.Context, owner int64, id string) (ShareFields, error) {
	recs, err := s.List(ctx, owner)
	if err != nil {
		return ShareFields{}, err
	}
	for _, rec := range recs {
		if recordID(rec) == id {
			f, ok := validFields(func(n string) (jsontext.Value, bool) { return pyjson.Get(rec, n) })
			if !ok {
				return ShareFields{}, errShareData
			}
			return f, nil
		}
	}
	return ShareFields{}, errShareMissing
}

func recordID(rec jsontext.Value) string {
	v, _ := pyjson.Get(rec, "id")
	id, _ := jsonString(v)
	return id
}

// SaveRequest is a definition to create (ID absent) or update. Members
// are raw JSON values as the page sent them; an absent member is empty.
type SaveRequest struct {
	ID, Name, Host, Share, Domain, Username jsontext.Value
}

func (r SaveRequest) get(name string) (jsontext.Value, bool) {
	v := map[string]jsontext.Value{"name": r.Name, "host": r.Host, "share": r.Share, "domain": r.Domain, "username": r.Username}[name]
	return v, len(v) > 0
}

// Save creates or updates one definition (upsert_smb_share). An update
// keeps created_at and the unknown non-secret members of the record.
func (s *Shares) Save(ctx context.Context, owner int64, req SaveRequest) (jsontext.Value, error) {
	return s.save(ctx, owner, req, nil)
}

// Create stores a new definition as Save does and runs then in the same
// transaction after the record is written; an error of then stores
// nothing. It is how a share and its saved password are created together.
func (s *Shares) Create(ctx context.Context, owner int64, req SaveRequest, then func(ctx context.Context, tx *store.Tx, saved jsontext.Value) error) (jsontext.Value, error) {
	req.ID = nil
	return s.save(ctx, owner, req, then)
}

func (s *Shares) save(ctx context.Context, owner int64, req SaveRequest, then func(ctx context.Context, tx *store.Tx, saved jsontext.Value) error) (jsontext.Value, error) {
	f, id, err := validateSave(req)
	if err != nil {
		return nil, err
	}
	var saved jsontext.Value
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		recs, err := SharesTx(ctx, tx, owner)
		if err != nil {
			return err
		}
		for _, rec := range recs {
			n, _ := jsonString(func() jsontext.Value { v, _ := pyjson.Get(rec, "name"); return v }())
			if strings.EqualFold(n, f.Name) && recordID(rec) != id {
				return errShareName
			}
		}
		now := pythonUTC(s.now())
		if id != "" {
			i := slices.IndexFunc(recs, func(r jsontext.Value) bool { return recordID(r) == id })
			if i < 0 {
				return errShareMissing
			}
			saved = updated(recs[i], f, now)
			_, err := tx.ExecContext(ctx, `UPDATE smb_shares SET record = ? WHERE user_id = ? AND position = ?`, string(saved), owner, i)
			return err
		}
		if len(recs) >= s.max() {
			return errShareLimit
		}
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return err
		}
		saved = record(nil, f, hex.EncodeToString(token[:]), now, now)
		_, err = tx.ExecContext(ctx, `INSERT INTO smb_shares (user_id, position, id, record) VALUES (?, ?, ?, ?)`,
			owner, len(recs), recordID(saved), string(saved))
		if err != nil || then == nil {
			return err
		}
		return then(ctx, tx, saved)
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}

// validateSave is _validate_payload without the secret check: the
// request decoder refuses every member the page does not send.
func validateSave(req SaveRequest) (ShareFields, string, error) {
	f, ok := validFields(req.get)
	if !ok {
		return ShareFields{}, "", errShareData
	}
	id := ""
	if len(req.ID) > 0 && req.ID.Kind() != 'n' {
		var isString bool
		if id, isString = jsonString(req.ID); !isString || !shareIDPattern.MatchString(id) {
			return ShareFields{}, "", errShareID
		}
	}
	return f, id, nil
}

// updated is {**unknown, **validated, id, created_at, updated_at}.
func updated(old jsontext.Value, f ShareFields, now string) jsontext.Value {
	members, _ := pyjson.Members(old)
	var unknown []pyjson.Member
	created := ""
	for _, m := range members {
		switch {
		case m.Name == "created_at":
			created, _ = jsonString(m.Value)
		case slices.Contains(knownShareFields, m.Name), secretField(m.Name):
		default:
			unknown = append(unknown, m)
		}
	}
	return record(unknown, f, recordID(old), created, now)
}

func record(prefix []pyjson.Member, f ShareFields, id, created, now string) jsontext.Value {
	out := append(slices.Clone(prefix),
		pyjson.Member{Name: "name", Value: pyjson.String(f.Name)},
		pyjson.Member{Name: "host", Value: pyjson.String(f.Host)},
		pyjson.Member{Name: "share", Value: pyjson.String(f.Share)},
		pyjson.Member{Name: "domain", Value: pyjson.String(f.Domain)},
		pyjson.Member{Name: "username", Value: pyjson.String(f.Username)},
		pyjson.Member{Name: "id", Value: pyjson.String(id)},
		pyjson.Member{Name: "created_at", Value: pyjson.String(created)},
		pyjson.Member{Name: "updated_at", Value: pyjson.String(now)})
	return pyjson.Object(out)
}

// Delete removes one definition of owner; the list order of the rest is
// kept.
func (s *Shares) Delete(ctx context.Context, owner int64, id string) error {
	if !shareIDPattern.MatchString(id) {
		return errShareMissing
	}
	return s.DB.Write(ctx, func(tx *store.Tx) error {
		recs, err := SharesTx(ctx, tx, owner)
		if err != nil {
			return err
		}
		rest := slices.DeleteFunc(slices.Clone(recs), func(r jsontext.Value) bool { return recordID(r) == id })
		if len(rest) == len(recs) {
			return errShareMissing
		}
		return replaceTx(ctx, tx, owner, rest)
	})
}

func replaceTx(ctx context.Context, tx *store.Tx, owner int64, recs []jsontext.Value) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM smb_shares WHERE user_id = ?`, owner); err != nil {
		return err
	}
	for i, rec := range recs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO smb_shares (user_id, position, id, record) VALUES (?, ?, ?, ?)`,
			owner, i, recordID(rec), string(rec)); err != nil {
			return err
		}
	}
	return nil
}

// ErrInvalidLegacy marks a stored document the Python release refuses to
// read; the migration stops.
var ErrInvalidLegacy = errors.New("smb: legacy SMB share document is invalid")

// ImportTx stores the definitions of owner as the migration read them
// (E22): every record verbatim, in order, after the checks of
// _valid_document.
func ImportTx(ctx context.Context, tx *store.Tx, owner int64, recs []jsontext.Value) error {
	if len(recs) > maxStoredShares {
		return fmt.Errorf("%w: more than %d records", ErrInvalidLegacy, maxStoredShares)
	}
	for i, rec := range recs {
		if !validRecord(rec) {
			return fmt.Errorf("%w: record %d", ErrInvalidLegacy, i)
		}
	}
	return replaceTx(ctx, tx, owner, recs)
}

func (s *Shares) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Shares) max() int {
	if s.Max > 0 {
		return s.Max
	}
	return DefaultMaxShares
}

// pythonUTC formats t like datetime.now(timezone.utc).isoformat():
// microseconds only when not zero, offset +00:00.
func pythonUTC(t time.Time) string {
	t = t.UTC()
	base := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		base += fmt.Sprintf(".%06d", us)
	}
	return base + "+00:00"
}
