package hosts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Keys tells whether a user owns an SSH key (provided by internal/vault).
type Keys interface {
	HasKey(ctx context.Context, owner int64, keyID string) (bool, error)
}

// PersistentSessions lists the persistent terminal sessions of a user that
// use a SOCKS5 proxy (provided by internal/terminal once it keeps tmux
// sessions). Reattaching such a session needs its original proxy, so the
// proxy cannot be deleted while one exists. The labels are display names
// or user@host.
type PersistentSessions interface {
	UsingSOCKSProxy(ctx context.Context, owner int64, proxyID string) (count int, labels []string, err error)
}

// Limits are the record and byte limits of saved connection data
// (PROFILE_MAX_RECORDS, JUMP_HOST_MAX_RECORDS, SOCKS_PROXY_MAX_RECORDS,
// CONNECTION_STORE_MAX_BYTES, CONNECTION_CONFIG_MAX_BYTES). They refuse
// only growth: a store above a limit stays readable and may shrink.
type Limits struct {
	ProfileMaxRecords    int
	JumpHostMaxRecords   int
	SOCKSProxyMaxRecords int
	StoreMaxBytes        int
	ConfigMaxBytes       int
}

// DefaultLimits are the defaults of config.py.
var DefaultLimits = Limits{
	ProfileMaxRecords:    500,
	JumpHostMaxRecords:   100,
	SOCKSProxyMaxRecords: 100,
	StoreMaxBytes:        2 << 20,
	ConfigMaxBytes:       4 << 20,
}

// Service owns the saved hosts, jump hosts, SOCKS5 proxies and workspace
// presets of every user.
type Service struct {
	DB     *store.DB
	Keys   Keys
	Limits Limits
	// Persistent is optional; without it no session blocks a deletion.
	Persistent PersistentSessions
	// Variants is optional; without it gateway selectors and Tailscale
	// SSH hosts are refused.
	Variants Variants
	// Now and NewID default to the clock and random UUIDs (tests set them).
	Now   func() time.Time
	NewID func() string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	return newUUID()
}

// newUUID returns a random UUID in the text form of Python's uuid4().
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails (crypto/rand)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

var errStorage = errors.New("hosts: stored record is damaged")

func columns(t table) string {
	quoted := make([]string, len(t.fields))
	for i, f := range t.fields {
		quoted[i] = `"` + f + `"`
	}
	return strings.Join(quoted, ", ")
}

// load returns the records of owner in list order.
func load(ctx context.Context, tx *store.Tx, t table, owner int64) ([]record, error) {
	rows, err := tx.QueryContext(ctx, `SELECT field_order, legacy_extra, `+columns(t)+
		` FROM `+t.name+` WHERE user_id = ? ORDER BY position`, owner)
	if err != nil {
		return nil, fmt.Errorf("hosts: read %s: %w", t.name, err)
	}
	defer rows.Close()
	var out []record
	for rows.Next() {
		values := make([]sql.NullString, len(t.fields))
		var order, extra string
		dest := []any{&order, &extra}
		for i := range values {
			dest = append(dest, &values[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("hosts: read %s: %w", t.name, err)
		}
		r, err := assemble(t, order, extra, values)
		if err != nil {
			return nil, fmt.Errorf("hosts: %s of user %d: %w", t.name, owner, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hosts: read %s: %w", t.name, err)
	}
	return out, nil
}

func assemble(t table, order, extra string, values []sql.NullString) (record, error) {
	var names []string
	if err := json.Unmarshal([]byte(order), &names); err != nil {
		return record{}, fmt.Errorf("%w: field order: %w", errStorage, err)
	}
	rest, err := parseRecord(jsontext.Value(extra))
	if err != nil {
		return record{}, fmt.Errorf("%w: legacy_extra: %w", errStorage, err)
	}
	var r record
	for _, name := range names {
		if r.has(name) {
			return record{}, fmt.Errorf("%w: field %q appears twice", errStorage, name)
		}
		if i := slices.Index(t.fields, name); i >= 0 {
			if !values[i].Valid {
				return record{}, fmt.Errorf("%w: field %q is missing", errStorage, name)
			}
			r.members = append(r.members, member{name: name, value: jsontext.Value(values[i].String)})
			continue
		}
		v, ok := rest.get(name)
		if !ok {
			return record{}, fmt.Errorf("%w: field %q is missing", errStorage, name)
		}
		r.members = append(r.members, member{name: name, value: v})
	}
	present := 0
	for _, value := range values {
		if value.Valid {
			present++
		}
	}
	if present != countKnown(t, names) || len(rest.members)+present != len(names) {
		return record{}, fmt.Errorf("%w: field order does not match the values", errStorage)
	}
	return r, nil
}

func countKnown(t table, names []string) int {
	n := 0
	for _, name := range names {
		if slices.Contains(t.fields, name) {
			n++
		}
	}
	return n
}

// replace stores records as the whole list of owner.
func replace(ctx context.Context, tx *store.Tx, t table, owner int64, records []record) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+t.name+` WHERE user_id = ?`, owner); err != nil {
		return fmt.Errorf("hosts: clear %s: %w", t.name, err)
	}
	placeholders := strings.Repeat(", ?", len(t.fields))
	insert := `INSERT INTO ` + t.name + ` (user_id, position, field_order, legacy_extra, ` + columns(t) +
		`) VALUES (?, ?, ?, ?` + placeholders + `)`
	for pos, r := range records {
		args, err := split(t, r)
		if err != nil {
			return err
		}
		args = append([]any{owner, pos}, args...)
		if _, err := tx.ExecContext(ctx, insert, args...); err != nil {
			return fmt.Errorf("hosts: write %s: %w", t.name, err)
		}
	}
	return nil
}

// split returns field_order, legacy_extra and the column values of r.
func split(t table, r record) ([]any, error) {
	names := make([]string, len(r.members))
	values := make([]any, len(t.fields))
	var extra record
	for i, m := range r.members {
		names[i] = m.name
		if j := slices.Index(t.fields, m.name); j >= 0 {
			values[j] = string(m.value)
		} else {
			extra.members = append(extra.members, m)
		}
	}
	order, err := json.Marshal(names)
	if err != nil {
		return nil, fmt.Errorf("hosts: encode field order: %w", err)
	}
	return append([]any{string(order), string(extra.encode())}, values...), nil
}

// find returns the index of the first record with id, or -1. Python
// compares with ==, so an ID of another JSON type never matches a string.
func find(records []record, id string) int {
	for i := range records {
		if v, ok := records[i].str("id"); ok && v == id {
			return i
		}
	}
	return -1
}

func encodeAll(records []record) []jsontext.Value {
	out := make([]jsontext.Value, len(records))
	for i, r := range records {
		out[i] = r.encode()
	}
	return out
}
