package commands

import (
	"crypto/rand"
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// Limits are the storage limits of commands and sets (COMMAND_* of the
// configuration). A zero field takes the default of the Python release.
type Limits struct {
	MaxCommands    int   // COMMAND_MAX_RECORDS
	MaxSets        int   // COMMAND_SET_MAX_RECORDS
	MaxSetSteps    int   // COMMAND_SET_MAX_STEPS
	MaxOSEntries   int   // COMMAND_OS_MAX_ENTRIES
	StoreMaxBytes  int64 // COMMAND_STORE_MAX_BYTES
	ConfigMaxBytes int64 // COMMAND_CONFIG_MAX_BYTES
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.MaxCommands, MaxCommands)
	def(&l.MaxSets, MaxSets)
	def(&l.MaxSetSteps, MaxSetSteps)
	def(&l.MaxOSEntries, MaxOSEntries)
	if l.StoreMaxBytes <= 0 {
		l.StoreMaxBytes = 2 << 20
	}
	if l.ConfigMaxBytes <= 0 {
		l.ConfigMaxBytes = 4 << 20
	}
	return l
}

// Library is the command library and the command sets of every user
// (C-CMD-01…05, -07, -08). All writes of the area run in one store
// transaction, so a set and the commands it refers to are always read
// from one snapshot, as the coordinator lock of the Python release
// ensured.
type Library struct {
	DB     *store.DB
	Limits Limits
	// Refs lists the saved hosts that refer to a set or a command. It is
	// required: without it no delete could be checked.
	Refs References
	// Hosts converts the free startup text of a saved host into a set;
	// without it the conversion is not available.
	Hosts Profiles
	// Now and NewID default to the clock and random UUIDs (tests set them).
	Now   func() time.Time
	NewID func() string
}

func (l *Library) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Library) newID() string {
	if l.NewID != nil {
		return l.NewID()
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Errors with the text of the Python release; the page shows them.
func invalid(msg string) error { return fault.New(fault.ValidationError, msg) }

func notFound(msg string) error { return fault.New(fault.NotFound, msg) }

// quotaPrefix starts every message of a storage limit
// (CommandStorageLimitError).
const quotaPrefix = "Command storage quota exceeded: "

func quota(msg string) error { return fault.New(fault.QuotaExceeded, quotaPrefix+msg) }

var (
	errCommandNotFound = notFound("Command not found")
	errSetNotFound     = notFound("Command set not found")
)

// storageError hides the cause of a failed read or write from the page.
func storageError(err error, msg string) error {
	if _, ok := fault.From(err); ok {
		return err
	}
	return fault.Wrap(fault.StorageError, err, msg)
}

// isoNaive is datetime.now(timezone.utc).replace(tzinfo=None).isoformat().
func isoNaive(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

// isoUTC is datetime.now(timezone.utc).isoformat().
func isoUTC(t time.Time) string { return isoNaive(t) + "+00:00" }

// index is _command_index: the built-in templates and the user's
// commands by id; a later record with the same id wins.
type commandIndex map[string]map[string]any

func buildIndex(user []jsontext.Value) (commandIndex, error) {
	system, err := systemCommands()
	if err != nil {
		return nil, err
	}
	idx := commandIndex{}
	for _, rec := range append(append([]jsontext.Value{}, system...), user...) {
		v, _ := decode(rec)
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		id, okID := m["id"].(string)
		_, okCmd := m["command"].(string)
		if okID && okCmd {
			idx[id] = m
		}
	}
	return idx, nil
}

// transition is enforce_store_transition: new growth beyond the record
// count, the store size or the combined size is refused; data already
// beyond a limit may stay as long as it does not grow.
func (l *Library) transition(prospective, current int64, count, currentCount, maxCount int, other int64) error {
	lim := l.Limits.withDefaults()
	if count > maxCount && count > currentCount {
		return quota(fmt.Sprintf("more than %d records are not allowed", maxCount))
	}
	if prospective > lim.StoreMaxBytes && prospective > current {
		return quota("one command store would exceed its byte limit")
	}
	if prospective+other > lim.ConfigMaxBytes && prospective > current {
		return quota("combined command data would exceed its byte limit")
	}
	return nil
}

// storedSize is the size of a store file that exists for these records;
// no records is no file.
func storedSize(records []jsontext.Value, size func([]jsontext.Value) int64) int64 {
	if len(records) == 0 {
		return 0
	}
	return size(records)
}

// boundedText is bounded_text with the limit error: text of at most max
// bytes, or not longer than the stored value it replaces.
func boundedText(v any, maximum int, label string, legacy any) error {
	s, ok := v.(string)
	if !ok {
		return quota(label + " must be text")
	}
	if len(s) <= maximum {
		return nil
	}
	if old, ok := legacy.(string); ok && len(s) <= len(old) {
		return nil
	}
	return quota(label + " is too large")
}

// object rebuilds a record from members in order.
func object(members ...pyjson.Member) jsontext.Value { return pyjson.Object(members) }

func member(name string, v jsontext.Value) pyjson.Member { return pyjson.Member{Name: name, Value: v} }

// lowerOS is the comparison of the OS filter (str.lower).
func lowerOS(s string) string { return strings.ToLower(s) }
