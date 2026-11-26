package auth

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/bifrost0x/webssh/internal/store"
)

// Recovery codes are single-use codes for a sign-in without the second
// factor. Only a domain-separated SHA-256 of each code is stored (algorithm
// tag sha256-webssh-v1, the format of the Python release, so migrated codes
// keep working).
const (
	RecoveryAlgorithm  = "sha256-webssh-v1"
	RecoveryCodeCount  = 10
	MaxRecoveryCodes   = 20
	recoveryDomain     = "webssh-recovery-code-v1\x00"
	dummyKDFSalt       = "webssh-recovery-verification-v1"
	dummyKDFIterations = 200_000
)

var errRecoveryCount = errors.New("auth: recovery code count must be between 1 and 20")

// NormalizeRecoveryCode removes white space, upper-cases ASCII letters and
// drops every other non-ASCII character. Python upper-cases with Unicode
// rules first (a ligature like "ﬀ" became "FF"); generated codes are hex
// groups, so only ASCII input can match either way.
func NormalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r), r > unicode.MaxASCII:
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		default:
			return r
		}
	}, code)
}

// HashRecoveryCode returns the stored form of code.
func HashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte(recoveryDomain + NormalizeRecoveryCode(code)))
	return sum[:]
}

var dummyHashes = func() (out [MaxRecoveryCodes][]byte) {
	for i := range out {
		out[i] = HashRecoveryCode(fmt.Sprintf("dummy-recovery-code-%d", i))
	}
	return out
}()

// Recovery stores and checks recovery codes.
type Recovery struct {
	DB  *store.DB
	Now func() time.Time
	// iterations of the fixed verification work; 0 is the production value.
	iterations int
}

func (rc *Recovery) now() time.Time {
	if rc.Now != nil {
		return rc.Now()
	}
	return time.Now()
}

// newRecoveryCode returns 20 random hex digits in five groups of four.
func newRecoveryCode() string {
	var raw [10]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never fails
	h := strings.ToUpper(hex.EncodeToString(raw[:]))
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20]
}

// ReplaceTx replaces the codes of userID with count new ones in the
// caller's transaction and returns them. They are shown once and never
// stored in clear.
func (rc *Recovery) ReplaceTx(ctx context.Context, tx *store.Tx, userID int64, count int) ([]string, error) {
	if count < 1 || count > MaxRecoveryCodes {
		return nil, errRecoveryCount
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, fmt.Errorf("auth: replace recovery codes: %w", err)
	}
	now := micros(rc.now())
	codes := make([]string, count)
	for i := range codes {
		codes[i] = newRecoveryCode()
		_, err := tx.ExecContext(ctx, `INSERT INTO auth_recovery_codes (user_id, algorithm, hash, created_at) VALUES (?, ?, ?, ?)`,
			userID, RecoveryAlgorithm, HashRecoveryCode(codes[i]), now)
		if err != nil {
			return nil, fmt.Errorf("auth: store recovery code: %w", err)
		}
	}
	return codes, nil
}

// Generate replaces the codes of userID with ten new ones.
func (rc *Recovery) Generate(ctx context.Context, userID int64) ([]string, error) {
	var codes []string
	err := rc.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		codes, err = rc.ReplaceTx(ctx, tx, userID, RecoveryCodeCount)
		return err
	})
	return codes, err
}

// HasCodesTx reports whether userID has an unused code.
func HasCodesTx(ctx context.Context, tx *store.Tx, userID int64) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM auth_recovery_codes WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return false, fmt.Errorf("auth: count recovery codes: %w", err)
	}
	return n > 0, nil
}

// ImportTx stores migrated hashes (entity E11) as they are.
func (rc *Recovery) ImportTx(ctx context.Context, tx *store.Tx, userID int64, hashes [][]byte) error {
	now := micros(rc.now())
	for _, h := range hashes {
		if len(h) != sha256.Size {
			return fmt.Errorf("auth: recovery code hash of user %d has %d bytes", userID, len(h))
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_recovery_codes (user_id, algorithm, hash, created_at) VALUES (?, ?, ?, ?)`,
			userID, RecoveryAlgorithm, h, now); err != nil {
			return fmt.Errorf("auth: import recovery code: %w", err)
		}
	}
	return nil
}

// Consume accepts code once for userID. Every call does the same fixed
// work and compares against MaxRecoveryCodes slots, whether the account
// exists, has codes or not, so the timing tells nothing about the codes.
func (rc *Recovery) Consume(ctx context.Context, userID int64, code string) (bool, error) {
	candidate := HashRecoveryCode(code)
	iterations := rc.iterations
	if iterations == 0 {
		iterations = dummyKDFIterations
	}
	if _, err := pbkdf2.Key(sha256.New, string(candidate), []byte(dummyKDFSalt), iterations, 32); err != nil {
		return false, fmt.Errorf("auth: recovery verification work: %w", err)
	}
	matched := false
	err := rc.DB.Write(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, hash FROM auth_recovery_codes WHERE user_id = ? AND algorithm = ? ORDER BY id LIMIT ?`,
			userID, RecoveryAlgorithm, MaxRecoveryCodes)
		if err != nil {
			return fmt.Errorf("auth: read recovery codes: %w", err)
		}
		var ids []int64
		var hashes [][]byte
		for rows.Next() {
			var id int64
			var h []byte
			if err := rows.Scan(&id, &h); err != nil {
				return errors.Join(fmt.Errorf("auth: read recovery codes: %w", err), rows.Close())
			}
			ids, hashes = append(ids, id), append(hashes, h)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("auth: read recovery codes: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("auth: read recovery codes: %w", err)
		}
		match := int64(-1)
		for i := range MaxRecoveryCodes {
			expected := dummyHashes[i]
			if i < len(hashes) {
				expected = hashes[i]
			}
			if hmac.Equal(expected, candidate) && i < len(hashes) {
				match = ids[i]
			}
		}
		if match < 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_recovery_codes WHERE id = ?`, match); err != nil {
			return fmt.Errorf("auth: use recovery code: %w", err)
		}
		matched = true
		return nil
	})
	return matched, err
}
