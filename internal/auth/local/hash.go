// Package local is the password sign-in (ADR 0009): Argon2id for new
// hashes, verification of the bcrypt hashes of the Python release and a
// transparent rehash after a successful sign-in.
package local

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the fixed upper bound for passwords (decision D-12).
// Longer input is refused before any hashing, as a guard against DoS.
const MaxPasswordBytes = 1024

// bcryptMaxBytes is the part of a password bcrypt reads. A bcrypt hash
// never matches a longer password, as in the Python release.
const bcryptMaxBytes = 72

// Algorithm names stored beside each hash.
const (
	AlgorithmArgon2id = "argon2id"
	AlgorithmBcrypt   = "bcrypt"
)

// Params are the Argon2id cost parameters.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultParams follow the OWASP baseline for Argon2id (19 MiB, two
// passes, one lane). With DefaultConcurrency computations at a time the
// sign-in needs at most about 76 MiB, which the smallest supported
// hardware (a 1 GiB single-board computer or NAS) carries beside the
// terminals. The measurement is in the M1 report of package C2.
var DefaultParams = Params{Memory: 19 * 1024, Time: 2, Threads: 1, KeyLen: 32, SaltLen: 16}

// DefaultConcurrency bounds simultaneous hash computations.
const DefaultConcurrency = 4

// Bounds for parameters read from a stored hash, so a tampered row cannot
// make one verification take gigabytes or minutes.
const (
	maxMemory  = 256 * 1024
	maxTime    = 16
	maxThreads = 16
)

var (
	// ErrTooLong is a password above MaxPasswordBytes.
	ErrTooLong = errors.New("local: password too long")
	// ErrFormat is a stored hash with an unknown algorithm or a malformed
	// encoding. Verification fails closed.
	ErrFormat = errors.New("local: unknown or malformed password hash")
)

// Hasher hashes and verifies passwords with bounded concurrency. It is safe
// for concurrent use.
type Hasher struct {
	params Params
	slots  chan struct{}
	dummy  string

	legacyOnce  sync.Once
	legacyDummy string
}

// NewHasher returns a hasher. concurrency < 1 uses DefaultConcurrency.
func NewHasher(p Params, concurrency int) (*Hasher, error) {
	if p.Memory < 8*uint32(p.Threads) || p.Time < 1 || p.Threads < 1 || p.KeyLen < 16 || p.SaltLen < 16 ||
		p.Memory > maxMemory || p.Time > maxTime || p.Threads > maxThreads || p.KeyLen > 64 || p.SaltLen > 64 {
		return nil, fmt.Errorf("local: Argon2id parameters out of range: %+v", p)
	}
	if concurrency < 1 {
		concurrency = DefaultConcurrency
	}
	h := &Hasher{params: p, slots: make(chan struct{}, concurrency)}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	dummy, err := h.argon2(secret, p)
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("local: wait for hash slot: %w", ctx.Err())
	}
}

func (h *Hasher) release() { <-h.slots }

// Hash returns a new Argon2id hash in PHC format.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrTooLong
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.argon2([]byte(password), h.params)
}

func (h *Hasher) argon2(password []byte, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("local: salt: %w", err)
	}
	key := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// Verify checks password against a stored hash. It returns whether the
// password matches and whether the stored hash should be replaced by a
// hash with the current parameters. A malformed hash or an unknown
// algorithm is ErrFormat.
func (h *Hasher) Verify(ctx context.Context, algorithm, stored, password string) (ok, rehash bool, err error) {
	if len(password) > MaxPasswordBytes {
		return false, false, nil
	}
	switch algorithm {
	case AlgorithmBcrypt:
		if !validBcrypt(stored) {
			return false, false, ErrFormat
		}
		if err := h.acquire(ctx); err != nil {
			return false, false, err
		}
		defer h.release()
		if len(password) > bcryptMaxBytes {
			// Spend the same time as a real check, so a long password
			// does not reveal that the account still has a bcrypt hash;
			// the result is discarded, a bcrypt hash never matches.
			_ = bcrypt.CompareHashAndPassword([]byte(stored), []byte(password[:bcryptMaxBytes]))
			return false, false, nil
		}
		err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
		return err == nil, err == nil, nil
	case AlgorithmArgon2id:
		p, salt, key, err := parseArgon2(stored)
		if err != nil {
			return false, false, err
		}
		if err := h.acquire(ctx); err != nil {
			return false, false, err
		}
		defer h.release()
		got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(key))) // #nosec G115 -- parseArgon2 bounds the key to 16–64 bytes
		ok := subtle.ConstantTimeCompare(got, key) == 1
		cur := h.params
		weaker := p.Memory < cur.Memory || p.Time < cur.Time || p.Threads < cur.Threads || len(key) < int(cur.KeyLen) || len(salt) < int(cur.SaltLen)
		return ok, ok && weaker, nil
	default:
		return false, false, ErrFormat
	}
}

// VerifyDummy spends the time of a real verification against a hash of a
// random secret. Sign-in uses it for unknown names, so the answer time
// does not show whether an account exists. legacy selects a bcrypt dummy
// with the cost of the Python release, used while migrated bcrypt hashes
// remain: most accounts then still answer at bcrypt speed.
func (h *Hasher) VerifyDummy(ctx context.Context, password string, legacy bool) {
	if legacy {
		h.legacyOnce.Do(func() {
			secret := make([]byte, 32)
			_, _ = rand.Read(secret)
			if b, err := bcrypt.GenerateFromPassword(secret, legacyCost); err == nil {
				h.legacyDummy = string(b)
			}
		})
		if h.legacyDummy != "" {
			_, _, _ = h.Verify(ctx, AlgorithmBcrypt, h.legacyDummy, password)
			return
		}
	}
	_, _, _ = h.Verify(ctx, AlgorithmArgon2id, h.dummy, password)
}

// legacyCost is the bcrypt cost of the Python release (bcrypt.gensalt()).
const legacyCost = 12

// validBcrypt accepts the modular crypt forms the Python release can
// store: $2a$, $2b$ or $2y$, a two-digit cost and 53 characters of salt
// and hash.
func validBcrypt(s string) bool {
	if len(s) != 60 || s[0] != '$' || s[1] != '2' || !strings.ContainsRune("aby", rune(s[2])) || s[3] != '$' || s[6] != '$' {
		return false
	}
	cost, err := strconv.Atoi(s[4:6])
	if err != nil || cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return false
	}
	const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 7; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

// parseArgon2 reads "$argon2id$v=19$m=…,t=…,p=…$salt$hash" strictly.
func parseArgon2(s string) (Params, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrFormat
	}
	var p Params
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return Params{}, nil, nil, ErrFormat
	}
	for i, prefix := range []string{"m=", "t=", "p="} {
		v, ok := strings.CutPrefix(fields[i], prefix)
		if !ok || v == "" || (len(v) > 1 && v[0] == '0') {
			return Params{}, nil, nil, ErrFormat
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Params{}, nil, nil, ErrFormat
		}
		switch i {
		case 0:
			p.Memory = uint32(n)
		case 1:
			p.Time = uint32(n)
		case 2:
			if n > maxThreads {
				return Params{}, nil, nil, ErrFormat
			}
			p.Threads = uint8(n)
		}
	}
	if p.Time < 1 || p.Time > maxTime || p.Threads < 1 || p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory {
		return Params{}, nil, nil, ErrFormat
	}
	enc := base64.RawStdEncoding.Strict()
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Params{}, nil, nil, ErrFormat
	}
	key, err := enc.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return Params{}, nil, nil, ErrFormat
	}
	return p, salt, key, nil
}
