package github

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// A flight is stored server-side until its callback, bound to the browser
// binding and the configuration generation (create_oauth_state). Only the
// MAC of the state and of the binding is kept, so a copy of the database
// cannot complete a redirect.

func (s *Service) flightMAC(kind, v string) []byte {
	return s.Ring.MAC(keyring.SessionToken, []byte("webssh-github-"+kind+"-v1\x00"+v))
}

// errState is every refused callback state (GitHubStateError): missing,
// expired, replayed, from another browser or another configuration.
var errState = errors.New("github: OAuth state is unavailable")

// storeFlight saves f for the browser binding.
func (s *Service) storeFlight(ctx context.Context, binding string, f auth.Flight, generation int64) error {
	if binding == "" || f.State == "" || f.Verifier == "" {
		return errState
	}
	now := s.now()
	var userID, authGen sql.NullInt64
	var sessionID sql.NullString
	if f.Purpose == auth.PurposeLink {
		userID = sql.NullInt64{Int64: f.UserID, Valid: true}
		authGen = sql.NullInt64{Int64: f.Generation, Valid: true}
		sessionID = sql.NullString{String: f.SessionID, Valid: true}
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM authgithub_flights WHERE expires_us < ?`, now.UnixMicro()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO authgithub_flights (state_mac, binding_mac, purpose, verifier, user_id,
			auth_generation, session_id, continuation, config_generation, issued_us, expires_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.flightMAC("state", f.State), s.flightMAC("binding", binding), string(f.Purpose), f.Verifier, userID, authGen,
			sessionID, auth.SafeContinuation(f.Continuation), generation, f.IssuedAt.UnixMicro(), now.Add(auth.FlightTTL).UnixMicro())
		return err
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, fmt.Errorf("github: store flight: %w", err), "")
	}
	return nil
}

// takeFlight removes and returns the flight of state for this browser. It
// succeeds at most once; an expired flight or one of an older
// configuration is consumed and refused.
func (s *Service) takeFlight(ctx context.Context, binding, state string, generation int64) (auth.Flight, error) {
	if binding == "" || state == "" {
		return auth.Flight{}, errState
	}
	f := auth.Flight{Provider: auth.ProviderGitHub, State: state}
	var purpose string
	var userID, authGen sql.NullInt64
	var sessionID sql.NullString
	var cfgGen, issued, expires int64
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `DELETE FROM authgithub_flights WHERE state_mac = ? AND binding_mac = ?
			RETURNING purpose, verifier, user_id, auth_generation, session_id, continuation, config_generation, issued_us, expires_us`,
			s.flightMAC("state", state), s.flightMAC("binding", binding)).
			Scan(&purpose, &f.Verifier, &userID, &authGen, &sessionID, &f.Continuation, &cfgGen, &issued, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Flight{}, errState
	}
	if err != nil {
		return auth.Flight{}, fault.Wrap(fault.StorageError, fmt.Errorf("github: read flight: %w", err), "")
	}
	if expires < s.now().UnixMicro() || cfgGen != generation {
		return auth.Flight{}, errState
	}
	f.Purpose = auth.Purpose(purpose)
	f.UserID, f.Generation, f.SessionID = userID.Int64, authGen.Int64, sessionID.String
	f.IssuedAt = time.UnixMicro(issued).UTC()
	return f, nil
}
