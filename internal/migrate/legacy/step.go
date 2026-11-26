package legacy

import (
	"context"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Step migrates one entity of the legacy data (E01 ... of the migration
// specification). The framework calls Read for every registered step, then
// Write for each step inside the staging transaction, then Verify against
// the staged database. Any error stops the whole migration without a
// change to the legacy data or to an active Go database.
type Step interface {
	// Entity is the specification's entity ID, for example "E19".
	Entity() string
	// Version is the step's format version, recorded in the coverage list
	// of the migration record.
	Version() int
	// Read loads and checks the entity from the legacy source. It keeps
	// what Write needs; it never writes.
	Read(ctx context.Context, src *Source) error
	// Write stores the entity through the capability's tables.
	Write(ctx context.Context, tx *store.Tx, seal Sealer) error
	// Verify reads the staged data back and compares it with what Read
	// loaded, secrets included (opened, compared, discarded).
	Verify(ctx context.Context, tx *store.Tx, open Opener) error
	// Report summarizes the step without secret values.
	Report() StepReport
}

// StepReport is one entry of the migration report.
type StepReport struct {
	Entity  string `json:"entity"`
	Version int    `json:"version"`
	Read    int    `json:"read"`
	Written int    `json:"written"`
	// Notes are safe, user-facing remarks (for example a profile field
	// kept verbatim in legacy_extra).
	Notes []string `json:"notes,omitzero"`
}

// Pending is an entity M1 leaves in place (KEEP-IN-PLACE), with the build
// phase that migrates it and the number of records found.
type Pending struct {
	Entity string `json:"entity"`
	Phase  string `json:"phase"`
	Count  int    `json:"count"`
}

// Sealer encrypts a secret for the record it belongs to (*keyring.Ring).
type Sealer interface {
	Seal(p keyring.Purpose, ad keyring.AAD, plain []byte) ([]byte, error)
}

// Opener decrypts a sealed secret (*keyring.Ring).
type Opener interface {
	Open(p keyring.Purpose, ad keyring.AAD, sealed []byte) ([]byte, error)
}
