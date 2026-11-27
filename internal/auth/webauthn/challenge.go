package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Ceremony purposes; a challenge answers only the purpose it was issued
// for.
const (
	purposeRegister = "register"
	purposeLogin    = "login"
	purposeMFA      = "mfa_login"
	purposeStepUp   = "step_up"
)

// Limits of the challenge store.
const (
	ChallengeTTL   = 5 * time.Minute // webauthn_service.create_challenge
	challengeBytes = 64              // py_webauthn generate_challenge
	minBinding     = 16
	// maxChallenges bounds the anonymous sign-in challenges and, apart
	// from them, the challenges of accounts against option requests from
	// many sources; the oldest of the same kind gives way, so anonymous
	// requests never push out the challenge of a signed-in ceremony. The
	// per-source rate limit keeps a single client far below it.
	maxChallenges = 10000
	// maxRegistrations bounds the open registrations of one account,
	// maxPerAccount all its open challenges.
	maxRegistrations = 5
	maxPerAccount    = 16
)

var (
	errChallenge = errors.New("webauthn: challenge is not available")
	// errNoBinding answers a ceremony request of a browser without the
	// binding cookie of the HTTP edge.
	errNoBinding = fault.New(fault.InvalidRequest, "Reload the page and try again")
)

type challenges struct {
	db   *store.DB
	ring *keyring.Ring
	now  func() time.Time
}

func bindingHash(binding string) []byte {
	sum := sha256.Sum256([]byte(binding))
	return sum[:]
}

func challengeAAD(purpose string, hash []byte) keyring.AAD {
	return keyring.AAD{Table: "webauthn_challenges", Column: "sealed_challenge", Row: purpose + "/" + hex.EncodeToString(hash)}
}

func nullableUser(userID int64) any {
	if userID == 0 {
		return nil
	}
	return userID
}

// issue creates a challenge for purpose, bound to binding and, unless 0,
// to userID. It replaces an earlier challenge of the same purpose and
// binding.
func (c challenges) issue(ctx context.Context, purpose string, userID int64, binding string) ([]byte, error) {
	if len(binding) < minBinding {
		return nil, errNoBinding
	}
	challenge := make([]byte, challengeBytes)
	_, _ = rand.Read(challenge) // crypto/rand.Read never fails
	hash := bindingHash(binding)
	sealed, err := c.ring.Seal(keyring.WebAuthnChallenge, challengeAAD(purpose, hash), challenge)
	if err != nil {
		return nil, fmt.Errorf("webauthn: seal challenge: %w", err)
	}
	now := c.now()
	err = c.db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE expires_at <= ? OR (purpose = ? AND binding_hash = ?)`,
			now.UnixMicro(), purpose, hash); err != nil {
			return err
		}
		if purpose == purposeRegister {
			if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE purpose = ? AND user_id = ? AND id <= (
				SELECT id FROM webauthn_challenges WHERE purpose = ? AND user_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
				purpose, userID, purpose, userID, maxRegistrations-1); err != nil {
				return err
			}
		}
		if userID != 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE user_id = ? AND id <= (
				SELECT id FROM webauthn_challenges WHERE user_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
				userID, userID, maxPerAccount-1); err != nil {
				return err
			}
		}
		anonymous := userID == 0
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE (user_id IS NULL) = ? AND id <= (
			SELECT id FROM webauthn_challenges WHERE (user_id IS NULL) = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
			anonymous, anonymous, maxChallenges-1); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO webauthn_challenges (purpose, binding_hash, user_id, sealed_challenge, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`, purpose, hash, nullableUser(userID), sealed, now.UnixMicro(), now.Add(ChallengeTTL).UnixMicro())
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: store challenge: %w", err)
	}
	return challenge, nil
}

// consume removes the challenge of purpose and binding and returns it. It
// succeeds at most once; an expired challenge, one of another account and
// one of another purpose or binding are not available. The removal
// commits before the caller verifies anything, so a failed answer uses
// the challenge up as well.
func (c challenges) consume(ctx context.Context, purpose string, userID int64, binding string) ([]byte, error) {
	if len(binding) < minBinding {
		return nil, errChallenge
	}
	hash := bindingHash(binding)
	var sealed []byte
	var expires int64
	err := c.db.Write(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `DELETE FROM webauthn_challenges WHERE purpose = ? AND binding_hash = ? AND user_id IS ?
			RETURNING sealed_challenge, expires_at`, purpose, hash, nullableUser(userID)).Scan(&sealed, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errChallenge
	}
	if err != nil {
		return nil, fmt.Errorf("webauthn: consume challenge: %w", err)
	}
	if expires <= c.now().UnixMicro() {
		return nil, fmt.Errorf("%w: expired", errChallenge)
	}
	challenge, err := c.ring.Open(keyring.WebAuthnChallenge, challengeAAD(purpose, hash), sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errChallenge, err)
	}
	return challenge, nil
}
