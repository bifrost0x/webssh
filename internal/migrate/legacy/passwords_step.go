package legacy

import (
	"context"
	"errors"
	"time"

	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/store"
)

// passwordsStep migrates entity E02: the bcrypt hash of every account,
// copied unchanged. The first Go sign-in replaces it with Argon2id
// (D-12); the 72-byte rule of bcrypt hashes stays (I-06).
type passwordsStep struct {
	hashes []accountHash
	at     time.Time
}

type accountHash struct {
	id   int64
	hash string
}

func (*passwordsStep) Entity() string { return "E02" }

func (*passwordsStep) Version() int { return 1 }

func (s *passwordsStep) Read(ctx context.Context, src *Source) error {
	users, err := src.Users(ctx)
	if err != nil {
		return err
	}
	s.at = time.Now().UTC()
	for _, u := range users {
		// A hash Python's bcrypt.checkpw cannot use is damaged user data.
		if _, err := BcryptCost(u.PasswordHash); err != nil {
			return &StepError{UserID: u.ID, Err: local.ErrLegacyHash} // the cause can quote the hash
		}
		s.hashes = append(s.hashes, accountHash{id: u.ID, hash: u.PasswordHash})
	}
	return nil
}

func (s *passwordsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, h := range s.hashes {
		if err := local.ImportTx(ctx, tx, h.id, h.hash, s.at); err != nil {
			return &StepError{UserID: h.id, Err: err}
		}
	}
	return nil
}

func (s *passwordsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, h := range s.hashes {
		algorithm, hash, found, err := local.StoredTx(ctx, tx, h.id)
		if err != nil || !found || algorithm != local.AlgorithmBcrypt || hash != h.hash {
			return &StepError{UserID: h.id, Err: errors.Join(errors.New("legacy: the stored password hash differs"), err)}
		}
		if _, err := BcryptCost(hash); err != nil {
			return &StepError{UserID: h.id, Err: local.ErrLegacyHash}
		}
	}
	return nil
}

func (s *passwordsStep) Report() StepReport {
	return StepReport{Entity: "E02", Version: 1, Read: len(s.hashes), Written: len(s.hashes),
		Notes: []string{"bcrypt hashes are kept and replaced by Argon2id at each account's first sign-in"}}
}
