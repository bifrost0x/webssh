// Package totp is the TOTP second factor: enrolment with a QR code, several
// authenticators per account, replay-safe verification and the sign-in
// completion. Codes are RFC 6238 with HMAC-SHA1, six digits and a 30 s step
// (internal/otp); one step of clock skew is accepted either way, and a step
// at or below the last accepted one is a replay.
package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/store"
)

// Limits of app/totp_service.py.
const (
	EnrollmentTTL     = 5 * time.Minute
	MaxAuthenticators = 5
	MaxEnrollments    = 5
	MaxLabelChars     = 80
	DefaultLabel      = "Authenticator"
	Issuer            = "WebSSH"
	secretBytes       = 20 // 32 base32 characters, 160 bits
)

// Service is the TOTP factor of the accounts in DB.
type Service struct {
	DB       *store.DB
	Ring     *keyring.Ring
	MFA      *auth.MFA
	Recovery *auth.Recovery
	Throttle *auth.Throttle
	Now      func() time.Time
	Logger   *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func digest(v string) []byte {
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func newSecret() string {
	var b [secretBytes]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

func aad(table string, id, userID int64) keyring.AAD {
	return keyring.AAD{Table: table, Column: "sealed_secret", Row: strconv.FormatInt(id, 10) + "/" + strconv.FormatInt(userID, 10)}
}

func (s *Service) seal(table string, id, userID int64, secret string) ([]byte, error) {
	sealed, err := s.Ring.Seal(keyring.TOTP, aad(table, id, userID), []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("totp: seal secret: %w", err)
	}
	return sealed, nil
}

func (s *Service) open(table string, id, userID int64, sealed []byte) ([]byte, error) {
	plain, err := s.Ring.Open(keyring.TOTP, aad(table, id, userID), sealed)
	if err != nil {
		return nil, fmt.Errorf("totp: open secret: %w", err)
	}
	key, err := otp.DecodeSecret(string(plain))
	if err != nil {
		return nil, fmt.Errorf("totp: stored secret: %w", err)
	}
	return key, nil
}

// NormalizeLabel trims the label and checks its length (1 to 80
// characters). An absent label is "Authenticator".
func NormalizeLabel(label string, present bool) (string, bool) {
	if !present || label == "" {
		// Python's `data.get("label") or "Authenticator"` treats "" as absent.
		return DefaultLabel, true
	}
	label = strings.TrimFunc(label, unicode.IsSpace)
	n := utf8.RuneCountInString(label)
	return label, n > 0 && n <= MaxLabelChars
}

// acceptedStep returns the time step of now-1, now or now+1 whose code is
// code, or ok=false. code must be six ASCII digits after trimming.
func acceptedStep(key []byte, code string, now time.Time) (uint64, bool) {
	code = strings.TrimFunc(code, unicode.IsSpace)
	if len(code) != 6 {
		return 0, false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	base := now.Unix() / int64(otp.DefaultPeriod/time.Second)
	for _, offset := range [3]int64{-1, 0, 1} {
		step := base + offset
		if step < 0 {
			continue
		}
		want, err := otp.TOTP(key, uint64(step)) // #nosec G115 -- step is not negative
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return uint64(step), true // #nosec G115 -- step is not negative
		}
	}
	return 0, false
}

// isoformat renders t as Python's datetime.isoformat() of the naive UTC
// value the Python release returned.
func isoformat(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}
