package legacy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// write runs every step's Write and Verify, re-checks the source digest
// (step 9) and writes the migration record, all in one transaction, so
// that the record exists only together with the data it describes.
func (r *run) write(ctx context.Context) error {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	r.dbID = hex.EncodeToString(b[:])
	return r.db.Write(ctx, func(tx *store.Tx) error {
		write := func(s Step) error {
			if err := s.Write(ctx, tx, r.ring); err != nil {
				return stepStop(s.Entity(), "writing the migrated data failed", err)
			}
			return nil
		}
		verify := func(s Step) error {
			if err := s.Verify(ctx, tx, r.ring); err != nil {
				return &StopError{Code: CodeVerifyFailed, Entity: s.Entity(), Message: "the migrated data does not match the legacy data", Err: err}
			}
			return nil
		}
		for i := range r.segments {
			seg := &r.segments[i]
			var err error
			if seg.step == nil {
				err = r.writeAccounts(ctx, seg, write, verify)
			} else {
				err = write(seg.step)
			}
			if err != nil {
				return err
			}
		}
		r.o.at(PointWritten)
		for _, seg := range r.segments {
			if seg.step == nil {
				for _, rep := range seg.reports {
					r.report.add(rep)
				}
				continue
			}
			if err := verify(seg.step); err != nil {
				return err
			}
			r.report.add(seg.step.Report())
		}
		if err := r.recordSettings(ctx, tx); err != nil {
			return err
		}
		if err := writeKeyID(ctx, tx, r.ring.KeyID()); err != nil {
			return err
		}
		return r.recheckAndRecord(ctx, tx)
	})
}

// recordSettings writes the settings derived from the previous behaviour
// (D-01) through their owner, internal/settings, after every step has
// written, and lists them in the report.
func (r *run) recordSettings(ctx context.Context, tx *store.Tx) error {
	mat, err := settings.MaterialisePolicies(ctx, tx, settings.Legacy{KeepLegacyScheme: r.o.Origin.KeepLegacyScheme}, r.o.now().UnixMicro())
	if err != nil {
		return fmt.Errorf("legacy: store derived settings: %w", err)
	}
	for _, m := range mat {
		s := MaterialisedSetting{Setting: m.Setting, Value: m.Value, Rule: m.Rule, Evidence: m.Evidence}
		if m.Setting == settings.PolicyOriginIgnoreScheme && r.o.Origin.Evidence != "" {
			s.Evidence = r.o.Origin.Evidence
		}
		r.report.MaterialisedSettings = append(r.report.MaterialisedSettings, s)
	}
	if r.o.Origin.KeepLegacyScheme {
		r.report.Warnings = append(r.report.Warnings, Warning{Code: "origin_scheme_not_checked", Message: "realtime " +
			"connections keep the Python rule that compares only host and port of the origin; configure TRUSTED_PROXIES to " +
			"let the scheme be checked"})
	}
	return nil
}
