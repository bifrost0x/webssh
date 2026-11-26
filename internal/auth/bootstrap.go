package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// A factor bootstrap code lets an account that GitHub created and that
// has no durable factor yet confirm the enrollment of its first passkey or
// authenticator (C-MFA-11, factor_bootstrap.py). Only an operator with
// shell access issues it (`webssh issue-factor-bootstrap`); it is valid
// ten minutes, once, for one account, its authentication generation and
// one action. Only its MAC is stored.

// BootstrapTTL is the lifetime of a code.
const BootstrapTTL = 10 * time.Minute

const bootstrapDomain = "webssh-factor-bootstrap-v1\x00"

var bootstrapPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{40,128}$`)

// BootstrapActions are the actions a code may confirm.
var BootstrapActions = []principal.Action{principal.ActionPasskeyEnroll, principal.ActionTOTPEnroll}

// BootstrapStanding says whether an account may use a code now and under
// which generation: active, without MFA, GitHub-managed with its identity,
// no passkey and no active authenticator (user_is_eligible).
type BootstrapStanding interface {
	BootstrapStanding(ctx context.Context, tx *store.Tx, userID int64) (generation int64, eligible bool, err error)
}

// ErrBootstrapIneligible refuses a code for an account that may not have
// one.
var ErrBootstrapIneligible = fault.New(fault.Forbidden, "Only a factorless GitHub-provisioned account is eligible.")

// Bootstrap issues and redeems factor bootstrap codes.
type Bootstrap struct {
	DB       *store.DB
	MAC      MAC
	Standing BootstrapStanding
	Now      func() time.Time
}

func (b *Bootstrap) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func (b *Bootstrap) key(code string) []byte {
	return b.MAC.MAC(keyring.FactorBootstrap, []byte(bootstrapDomain+code))
}

func knownBootstrapAction(a principal.Action) bool {
	return slices.Contains(BootstrapActions, a)
}

func (b *Bootstrap) eligibleTx(ctx context.Context, tx *store.Tx, userID int64, action principal.Action) (int64, bool, error) {
	if !knownBootstrapAction(action) || b.Standing == nil {
		return 0, false, nil
	}
	return b.Standing.BootstrapStanding(ctx, tx, userID)
}

// Issue creates a code for the account and action, replacing every earlier
// code of the account, and returns it with its expiry.
func (b *Bootstrap) Issue(ctx context.Context, userID int64, action principal.Action) (string, time.Time, error) {
	if !knownBootstrapAction(action) {
		return "", time.Time{}, fault.New(fault.InvalidValue, "Unsupported factor enrollment action.")
	}
	var raw [32]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never fails
	code := base64.RawURLEncoding.EncodeToString(raw[:])
	now := b.now()
	expires := now.Add(BootstrapTTL)
	err := b.DB.Write(ctx, func(tx *store.Tx) error {
		gen, ok, err := b.eligibleTx(ctx, tx, userID, action)
		if err != nil {
			return err
		}
		if !ok {
			return ErrBootstrapIneligible
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_factor_bootstrap WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("auth: replace bootstrap codes: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO auth_factor_bootstrap (token_mac, user_id, auth_generation, action, created_us, expires_us)
			VALUES (?, ?, ?, ?, ?, ?)`, b.key(code), userID, gen, string(action), now.UnixMicro(), expires.UnixMicro())
		if err != nil {
			return fmt.Errorf("auth: store bootstrap code: %w", err)
		}
		return nil
	})
	if err != nil {
		if _, ok := fault.From(err); ok {
			return "", time.Time{}, err
		}
		return "", time.Time{}, fault.Wrap(fault.StorageError, err, "")
	}
	return code, expires.Truncate(time.Microsecond), nil
}

// Live reports whether the account has a code for action it may redeem
// now (has_live_factor_bootstrap).
func (b *Bootstrap) Live(ctx context.Context, userID int64, action principal.Action) (bool, error) {
	var live bool
	err := b.DB.Read(ctx, func(tx *store.Tx) error {
		gen, ok, err := b.eligibleTx(ctx, tx, userID, action)
		if err != nil || !ok {
			return err
		}
		var n int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM auth_factor_bootstrap WHERE user_id = ? AND auth_generation = ?
			AND action = ? AND consumed_us IS NULL AND expires_us > ?`, userID, gen, string(action), b.now().UnixMicro()).Scan(&n)
		live = n > 0
		return err
	})
	if err != nil {
		return false, fault.Wrap(fault.StorageError, err, "")
	}
	return live, nil
}

// Redeem spends code for the account and action
// (consume_factor_bootstrap). It is false for a malformed, unknown,
// expired, used or foreign code and for an account that is no longer
// eligible; a code works at most once, also under concurrent requests.
func (b *Bootstrap) Redeem(ctx context.Context, userID int64, action principal.Action, code string) (bool, error) {
	if !bootstrapPattern.MatchString(code) {
		return false, nil
	}
	var ok bool
	err := b.DB.Write(ctx, func(tx *store.Tx) error {
		gen, eligible, err := b.eligibleTx(ctx, tx, userID, action)
		if err != nil || !eligible {
			return err
		}
		now := b.now().UnixMicro()
		res, err := tx.ExecContext(ctx, `UPDATE auth_factor_bootstrap SET consumed_us = ? WHERE token_mac = ? AND user_id = ?
			AND auth_generation = ? AND action = ? AND consumed_us IS NULL AND expires_us > ?`,
			now, b.key(code), userID, gen, string(action), now)
		if err != nil {
			return fmt.Errorf("auth: redeem bootstrap code: %w", err)
		}
		n, err := res.RowsAffected()
		ok = n == 1
		return err
	})
	if err != nil {
		return false, fault.Wrap(fault.StorageError, err, "")
	}
	return ok, nil
}
