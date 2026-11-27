package hosts

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Offline recovery of oversized connection stores (C-BAK-09, the
// `connection-store` command of app/cli.py). An administrator lists the
// records of one store as non-secret summaries with an opaque selector and
// deletes one record by its selector. The selector binds the record's
// position and its exact content, so a record that moved or changed since
// the listing is not deleted.

// RecoveryKind names a store as the command line does.
type RecoveryKind string

// Store kinds of the recovery command.
const (
	RecoverProfiles     RecoveryKind = "profiles"
	RecoverJumpHosts    RecoveryKind = "jump-hosts"
	RecoverSOCKSProxies RecoveryKind = "socks-proxies"
)

// RecoveryKinds lists the kinds in the order of the command's choices.
func RecoveryKinds() []RecoveryKind {
	return []RecoveryKind{RecoverProfiles, RecoverJumpHosts, RecoverSOCKSProxies}
}

func (k RecoveryKind) store() (kind, bool) {
	switch k {
	case RecoverProfiles:
		return profileKind, true
	case RecoverJumpHosts:
		return jumpKind, true
	case RecoverSOCKSProxies:
		return socksKind, true
	}
	return kind{}, false
}

// RecoveryLimits are CONNECTION_STORE_RECOVERY_MAX_BYTES and
// CONNECTION_STORE_RECOVERY_MAX_RECORDS: recovery reads a store larger than
// the normal limits, but never an unbounded one.
type RecoveryLimits struct {
	MaxBytes   int
	MaxRecords int
}

// RecoverySummary is one record as the list shows it: the selector and
// the printable, bounded id, name and host.
type RecoverySummary struct {
	Selector string `json:"selector"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
}

const recoverySelectorDomain = "webssh-connection-recovery-selector-v1\x00"

var recoverySelectorPattern = regexp.MustCompile(`^r1:(0|[1-9][0-9]{0,9}):([0-9a-f]{64})$`)

// recoverySelector is recovery_record_selector: SHA-256 over the domain,
// the scope, the ordinal and the record as json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=True) writes it.
func recoverySelector(scope string, index int, r record) string {
	sum := sha256.Sum256(slices.Concat([]byte(recoverySelectorDomain+scope+"\x00"+strconv.Itoa(index)+"\x00"),
		flaskJSON(r.encode())))
	return "r1:" + strconv.Itoa(index) + ":" + hex.EncodeToString(sum[:])
}

// resolveRecoverySelector returns the index the selector names, or -1 when
// it is malformed or the record at its ordinal is no longer the same.
func resolveRecoverySelector(scope string, records []record, selector string) int {
	m := recoverySelectorPattern.FindStringSubmatch(selector)
	if m == nil {
		return -1
	}
	index, err := strconv.Atoi(m[1])
	if err != nil || index >= len(records) {
		return -1
	}
	want := recoverySelector(scope, index, records[index])
	if subtle.ConstantTimeCompare([]byte(want), []byte(selector)) != 1 {
		return -1
	}
	return index
}

func recoveryScope(k RecoveryKind, owner int64) string {
	return string(k) + ":" + strconv.FormatInt(owner, 10)
}

// loadForRecovery reads the records of k within the recovery ceilings
// (enforce_store_recovery_limit). The byte ceiling is measured on the
// document Python would write for the records.
func loadForRecovery(ctx context.Context, tx *store.Tx, k kind, owner int64, lim RecoveryLimits) ([]record, error) {
	records, err := load(ctx, tx, k.table, owner)
	if err != nil {
		return nil, err
	}
	if documentSize(k, records, true) > lim.MaxBytes {
		return nil, quotaError("stored data exceeds its recovery byte limit")
	}
	if len(records) > lim.MaxRecords {
		return nil, quotaError(fmt.Sprintf("more than %d recovery records are not allowed", lim.MaxRecords))
	}
	return records, nil
}

// RecoverySummaries lists the records of one store of owner
// (load_*_recovery_summaries).
func (s *Service) RecoverySummaries(ctx context.Context, owner int64, k RecoveryKind, lim RecoveryLimits) ([]RecoverySummary, error) {
	kd, ok := k.store()
	if !ok {
		return nil, fault.New(fault.InvalidValue, "Unknown connection store")
	}
	out := []RecoverySummary{}
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		records, err := loadForRecovery(ctx, tx, kd, owner, lim)
		if err != nil {
			return err
		}
		scope := recoveryScope(k, owner)
		for i := range records {
			out = append(out, RecoverySummary{
				Selector: recoverySelector(scope, i, records[i]),
				ID:       safeReferenceName(records[i].text("id")),
				Name:     safeReferenceName(records[i].text("name")),
				Host:     safeReferenceName(records[i].text("host")),
			})
		}
		return nil
	})
	if err != nil {
		return nil, classify(err, "Failed to load connection store")
	}
	return out, nil
}

// errRecoverySelector is the answer to a selector that no longer matches.
var errRecoverySelector = fault.New(fault.NotFound, "Recovery selector not found; list the store again.")

// DeleteRecovery deletes the one record the selector names
// (delete_*_recovery_record). A jump host or SOCKS5 proxy that a saved
// host uses is kept, with the usage summary of the ordinary delete.
func (s *Service) DeleteRecovery(ctx context.Context, owner int64, k RecoveryKind, selector string, lim RecoveryLimits) error {
	kd, ok := k.store()
	if !ok {
		return fault.New(fault.InvalidValue, "Unknown connection store")
	}
	failure := map[RecoveryKind]string{RecoverProfiles: "Failed to delete profile",
		RecoverJumpHosts: "Failed to delete jump host", RecoverSOCKSProxies: "Failed to delete SOCKS proxy"}[k]
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		profiles, err := loadForRecovery(ctx, tx, profileKind, owner, lim)
		if err != nil {
			return err
		}
		records := profiles
		if k != RecoverProfiles {
			if records, err = loadForRecovery(ctx, tx, kd, owner, lim); err != nil {
				return err
			}
		}
		index := resolveRecoverySelector(recoveryScope(k, owner), records, selector)
		if index < 0 {
			return errRecoverySelector
		}
		if k != RecoverProfiles {
			field, what := "jump_host_id", "Jump host"
			if k == RecoverSOCKSProxies {
				field, what = "socks_proxy_id", "SOCKS proxy"
			}
			if id, ok := records[index].get("id"); ok {
				if err := inUse(profiles, field, id, what); err != nil {
					return err
				}
			}
		}
		return replace(ctx, tx, kd.table, owner, slices.Delete(slices.Clone(records), index, index+1))
	})
	return classify(err, failure)
}
