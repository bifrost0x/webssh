package session

import (
	"context"
	"crypto/hmac"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Service is the session service. It is safe for concurrent use.
type Service struct {
	db        *store.DB
	mac       MAC
	accounts  Accounts
	durations Durations
	// Now replaces the clock in tests.
	Now func() time.Time

	mu     sync.Mutex
	subs   map[int]func(principal.Revocation)
	nextID int
}

// New returns the service. durations may be nil (every account uses
// DefaultMinutes).
func New(db *store.DB, mac MAC, accounts Accounts, durations Durations) *Service {
	return &Service{db: db, mac: mac, accounts: accounts, durations: durations, Now: time.Now, subs: map[int]func(principal.Revocation){}}
}

func (s *Service) now() time.Time { return s.Now().UTC() }

// IssueRequest describes a completed sign-in.
type IssueRequest struct {
	UserID int64
	// Generation is the auth_generation the sign-in was verified against;
	// a changed generation (password change, lock) refuses the issue.
	Generation    int64
	PrimaryMethod string
	// Methods are every method verified, the primary one included.
	Methods   []string
	Assurance Assurance
	Remember  bool
	// StrongAt is kept when a session is replaced; for a new sign-in it is
	// set to now for assurance above Basic.
	StrongAt time.Time
	// ExpiresAt is kept when a session is replaced; zero computes the
	// lifetime from Remember and the account setting.
	ExpiresAt time.Time
}

var errNotEligible = fault.New(fault.AuthenticationNeeded, "")

func normalizeMethods(methods []string, primary string) ([]string, error) {
	var out []string
	for _, m := range methods {
		if !methodPattern.MatchString(m) {
			return nil, errors.New("session: invalid authentication method")
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	if len(out) == 0 || len(out) > maxMethods || !slices.Contains(out, primary) {
		return nil, errors.New("session: methods do not match the primary method")
	}
	return out, nil
}

func (s *Service) lifetime(ctx context.Context, req IssueRequest) time.Duration {
	if req.Remember {
		return RememberLifetime
	}
	minutes := DefaultMinutes
	if s.durations != nil {
		if m, err := s.durations.SessionMinutes(ctx, req.UserID); err == nil && slices.Contains(AllowedMinutes, m) {
			minutes = m
		}
	}
	return time.Duration(minutes) * time.Minute
}

// prepare validates req against the account and returns the row to store.
func (s *Service) prepare(ctx context.Context, req IssueRequest) (Session, error) {
	methods, err := normalizeMethods(req.Methods, req.PrimaryMethod)
	if err != nil {
		return Session{}, err
	}
	if req.Assurance.Rank() < 0 {
		return Session{}, errors.New("session: unsupported assurance level")
	}
	st, err := s.accounts.Standing(ctx, req.UserID)
	if err != nil {
		return Session{}, err
	}
	if !st.eligible() || st.Generation != req.Generation {
		return Session{}, errNotEligible
	}
	now := s.now()
	sess := Session{
		ID: randomHex(16), UserID: req.UserID, AuthGeneration: req.Generation, PrimaryMethod: req.PrimaryMethod,
		Methods: methods, Assurance: req.Assurance, Remember: req.Remember, AuthenticatedAt: now,
		StrongAt: req.StrongAt, ExpiresAt: req.ExpiresAt,
	}
	if sess.StrongAt.IsZero() && req.Assurance != Basic {
		sess.StrongAt = now
	}
	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt = now.Add(s.lifetime(ctx, req))
	}
	return sess, nil
}

// Issue stores a new session and returns it with its token. The token is
// shown once, for the cookie; the database keeps only its MAC.
func (s *Service) Issue(ctx context.Context, req IssueRequest) (Session, string, error) {
	sess, err := s.prepare(ctx, req)
	if err != nil {
		return Session{}, "", err
	}
	token := randomText(32)
	err = s.db.Write(ctx, func(tx *store.Tx) error { return s.insert(ctx, tx, &sess, token) })
	if err != nil {
		return Session{}, "", storageErr(err)
	}
	return sess, token, nil
}

// IssueTx is Issue inside the caller's write transaction, for a change
// that ends the account's other sessions and keeps the current browser
// signed in (password change). The account standing is read before the
// transaction; the caller has checked it.
func (s *Service) IssueTx(ctx context.Context, tx *store.Tx, req IssueRequest) (Session, string, error) {
	methods, err := normalizeMethods(req.Methods, req.PrimaryMethod)
	if err != nil {
		return Session{}, "", err
	}
	now := s.now()
	sess := Session{
		ID: randomHex(16), UserID: req.UserID, AuthGeneration: req.Generation, PrimaryMethod: req.PrimaryMethod,
		Methods: methods, Assurance: req.Assurance, Remember: req.Remember, AuthenticatedAt: now,
		StrongAt: req.StrongAt, ExpiresAt: req.ExpiresAt,
	}
	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt = now.Add(s.lifetime(ctx, req))
	}
	token := randomText(32)
	if err := s.insert(ctx, tx, &sess, token); err != nil {
		return Session{}, "", err
	}
	return sess, token, nil
}

func (s *Service) insert(ctx context.Context, tx *store.Tx, sess *Session, token string) error {
	epoch, err := currentEpoch(ctx, tx)
	if err != nil {
		return err
	}
	sess.epoch = epoch
	methods, _ := json.Marshal(sess.Methods)
	var strong sql.NullInt64
	if !sess.StrongAt.IsZero() {
		strong = sql.NullInt64{Int64: sess.StrongAt.UnixMicro(), Valid: true}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO session_sessions (id, token_mac, user_id, auth_generation, epoch, primary_method,
		methods, assurance, remember, authenticated_us, strong_us, expires_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, tokenMAC(s.mac, token), sess.UserID, sess.AuthGeneration, epoch, sess.PrimaryMethod, string(methods),
		string(sess.Assurance), sess.Remember, sess.AuthenticatedAt.UnixMicro(), strong, sess.ExpiresAt.UnixMicro())
	if err != nil {
		return fmt.Errorf("session: insert: %w", err)
	}
	return nil
}

func currentEpoch(ctx context.Context, tx *store.Tx) (string, error) {
	var epoch string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM session_epoch WHERE singleton = 1`).Scan(&epoch); err != nil {
		return "", fmt.Errorf("session: read epoch: %w", err)
	}
	return epoch, nil
}

const selectColumns = `id, user_id, auth_generation, epoch, primary_method, methods, assurance, remember,
	authenticated_us, strong_us, expires_us`

type scanner interface{ Scan(dest ...any) error }

func scanSession(row scanner) (Session, error) {
	var sess Session
	var methods, assurance string
	var authUS, expUS int64
	var strong sql.NullInt64
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.AuthGeneration, &sess.epoch, &sess.PrimaryMethod, &methods,
		&assurance, &sess.Remember, &authUS, &strong, &expUS); err != nil {
		return Session{}, err
	}
	if err := json.Unmarshal([]byte(methods), &sess.Methods); err != nil {
		return Session{}, fmt.Errorf("session: stored methods: %w", err)
	}
	sess.Assurance = Assurance(assurance)
	sess.AuthenticatedAt = time.UnixMicro(authUS).UTC()
	sess.ExpiresAt = time.UnixMicro(expUS).UTC()
	if strong.Valid {
		sess.StrongAt = time.UnixMicro(strong.Int64).UTC()
	}
	return sess, nil
}

// load reads one session and the current epoch in one snapshot.
func (s *Service) load(ctx context.Context, where string, arg any) (Session, string, error) {
	var sess Session
	var epoch string
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		if sess, err = scanSession(tx.QueryRowContext(ctx, `SELECT `+selectColumns+` FROM session_sessions WHERE `+where, arg)); err != nil {
			return err
		}
		epoch, err = currentEpoch(ctx, tx)
		return err
	})
	return sess, epoch, err
}

// Validate returns the session of a token. Every failure is
// fault.AuthenticationNeeded; an expired session is removed and its end
// published.
func (s *Service) Validate(ctx context.Context, token string) (Session, error) {
	if token == "" || len(token) > maxTokenLen {
		return Session{}, errNotEligible
	}
	mac := tokenMAC(s.mac, token)
	sess, epoch, err := s.load(ctx, `token_mac = ?`, mac)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Session{}, errNotEligible
	case err != nil:
		return Session{}, storageErr(err)
	}
	if _, err := s.verify(ctx, sess, epoch); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// verify checks a loaded session against the clock, the epoch and the
// account and returns the account's standing.
func (s *Service) verify(ctx context.Context, sess Session, epoch string) (Standing, error) {
	if !s.now().Before(sess.ExpiresAt) {
		if err := s.Revoke(ctx, sess.ID, principal.ReasonExpired); err != nil {
			return Standing{}, err
		}
		return Standing{}, errNotEligible
	}
	if !hmac.Equal([]byte(sess.epoch), []byte(epoch)) {
		return Standing{}, errNotEligible
	}
	st, err := s.accounts.Standing(ctx, sess.UserID)
	if err != nil {
		return Standing{}, err
	}
	if !st.eligible() || st.Generation != sess.AuthGeneration {
		return Standing{}, errNotEligible
	}
	return st, nil
}

// Authenticate returns the principal of a valid session token
// (realtime.SessionValidator, HTTP session middleware).
func (s *Service) Authenticate(ctx context.Context, token string) (principal.Principal, error) {
	sess, err := s.Validate(ctx, token)
	if err != nil {
		return principal.Principal{}, err
	}
	st, err := s.accounts.Standing(ctx, sess.UserID)
	if err != nil {
		return principal.Principal{}, err
	}
	return principal.Principal{UserID: sess.UserID, SessionID: sess.ID, Username: st.Username, IsAdmin: st.IsAdmin, Recovery: sess.Recovery()}, nil
}

// Check re-validates p: the session still exists, has not expired, the
// account is eligible under the same generation, administrator rights
// recorded in p are still held, and the recovery restriction did not
// appear.
func (s *Service) Check(ctx context.Context, p principal.Principal) error {
	if !p.Valid() {
		return errNotEligible
	}
	sess, epoch, err := s.load(ctx, `id = ?`, p.SessionID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return errNotEligible
	case err != nil:
		return storageErr(err)
	}
	if sess.UserID != p.UserID {
		return errNotEligible
	}
	st, err := s.verify(ctx, sess, epoch)
	if err != nil {
		return err
	}
	if (p.IsAdmin && !st.IsAdmin) || (sess.Recovery() && !p.Recovery) {
		return errNotEligible
	}
	return nil
}

// Lookup returns a session by ID if it is still valid.
func (s *Service) Lookup(ctx context.Context, id string) (Session, error) {
	sess, epoch, err := s.load(ctx, `id = ?`, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Session{}, errNotEligible
	case err != nil:
		return Session{}, storageErr(err)
	}
	if _, err := s.verify(ctx, sess, epoch); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// List returns the user's valid sessions, newest sign-in first.
func (s *Service) List(ctx context.Context, userID int64) ([]Session, error) {
	st, err := s.accounts.Standing(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []Session
	now := s.now().UnixMicro()
	err = s.db.Read(ctx, func(tx *store.Tx) error {
		epoch, err := currentEpoch(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+selectColumns+` FROM session_sessions
			WHERE user_id = ? AND auth_generation = ? AND epoch = ? AND expires_us > ?
			ORDER BY authenticated_us DESC, id DESC`, userID, st.Generation, epoch, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sess, err := scanSession(rows)
			if err != nil {
				return err
			}
			out = append(out, sess)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, storageErr(err)
	}
	return out, nil
}

func storageErr(err error) error {
	if _, ok := fault.From(err); ok {
		return err
	}
	return fault.Wrap(fault.StorageError, err, "")
}
