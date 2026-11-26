package stepup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Channels say which URL family created an intent. They share every rule;
// the admin family keeps at most one pending passkey intent per session
// because its page does not send the intent back.
const (
	ChannelAccount = "account"
	ChannelAdmin   = "admin"
)

const targetDomain = "webssh-step-up-target-v1\x00"

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TargetHash binds a grant to its target as app/step_up.py does.
func TargetHash(target string) []byte {
	sum := sha256.Sum256([]byte(targetDomain + target))
	return sum[:]
}

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *Service) mac(kind, token string) []byte {
	return s.Ring.MAC(keyring.StepUpGrant, []byte(kind+"\x00"+token))
}

// issue stores a new grant for action and target at level and returns it.
// The session keeps at most MaxGrantsPerSess grants; older ones are dropped.
func (s *Service) issue(ctx context.Context, p principal.Principal, action principal.Action, target string, level auth.Assurance, channel string) (string, error) {
	grant := newToken()
	err := s.DB.Write(ctx, func(tx *store.Tx) error { return s.issueTx(ctx, tx, p, action, TargetHash(target), level, grant) })
	if err != nil {
		return "", err
	}
	s.audit().Security(ctx, slog.LevelInfo, event(channel, "GRANTED"), "user", p.Username, "action", string(action), "method", MethodRecent, "assurance", string(level))
	return grant, nil
}

// event names the audit event of a channel as the Python release does
// (ACCOUNT_STEP_UP_… and ADMIN_STEP_UP_…).
func event(channel, what string) string {
	if channel == ChannelAdmin {
		return "ADMIN_STEP_UP_" + what
	}
	return "ACCOUNT_STEP_UP_" + what
}

func (s *Service) issueTx(ctx context.Context, tx *store.Tx, p principal.Principal, action principal.Action, targetHash []byte, level auth.Assurance, grant string) error {
	now := s.now()
	if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_grants WHERE expires_at <= ?`, now.UnixMicro()); err != nil {
		return fmt.Errorf("stepup: expire grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_grants WHERE session_id = ? AND id NOT IN (
		SELECT id FROM stepup_grants WHERE session_id = ? ORDER BY created_at DESC, id DESC LIMIT ?)`,
		p.SessionID, p.SessionID, MaxGrantsPerSess-1); err != nil {
		return fmt.Errorf("stepup: limit grants: %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO stepup_grants (token_mac, user_id, session_id, action, target_hash, assurance, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, s.mac("grant", grant), p.UserID, p.SessionID, string(action), targetHash, string(level),
		now.UnixMicro(), now.Add(GrantTTL).UnixMicro())
	if err != nil {
		return fmt.Errorf("stepup: store grant: %w", err)
	}
	return nil
}

// Challenge is a pending step-up of the account family.
type Challenge struct {
	Plan
	Intent string
}

// Begin plans a step-up and, unless a grant is issued at once, stores an
// intent bound to the principal's session for IntentTTL.
func (s *Service) Begin(ctx context.Context, p principal.Principal, action principal.Action, target, channel string) (Challenge, error) {
	return s.begin(ctx, p, action, target, channel, true)
}

// BeginCeremony is Begin without the shortcut for a recent strong sign-in:
// it always stores an intent that needs a proof.
func (s *Service) BeginCeremony(ctx context.Context, p principal.Principal, action principal.Action, target, channel string) (Challenge, error) {
	return s.begin(ctx, p, action, target, channel, false)
}

func (s *Service) begin(ctx context.Context, p principal.Principal, action principal.Action, target, channel string, allowRecent bool) (Challenge, error) {
	plan, target, err := s.plan(ctx, p, action, target, channel, allowRecent)
	if err != nil || plan.Grant != "" {
		return Challenge{Plan: plan}, err
	}
	token := newToken()
	now := s.now()
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_intents WHERE expires_at <= ?`, now.UnixMicro()); err != nil {
			return fmt.Errorf("stepup: expire intents: %w", err)
		}
		if channel == ChannelAdmin {
			if _, err := tx.ExecContext(ctx, `DELETE FROM stepup_intents WHERE session_id = ? AND channel = ?`, p.SessionID, ChannelAdmin); err != nil {
				return fmt.Errorf("stepup: replace intent: %w", err)
			}
		}
		var live int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stepup_intents WHERE session_id = ?`, p.SessionID).Scan(&live); err != nil {
			return fmt.Errorf("stepup: count intents: %w", err)
		}
		if live >= MaxIntentsPerSess {
			return ErrInvalid
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO stepup_intents (token_mac, user_id, session_id, channel, action, target_hash, required, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.mac("intent", token), p.UserID, p.SessionID, channel, string(action),
			TargetHash(target), string(plan.Required), now.UnixMicro(), now.Add(IntentTTL).UnixMicro())
		if err != nil {
			return fmt.Errorf("stepup: store intent: %w", err)
		}
		return nil
	})
	if err != nil {
		return Challenge{}, err
	}
	s.audit().Security(ctx, slog.LevelInfo, event(channel, "CREATED"), "user", p.Username, "action", string(action), "assurance", string(plan.Required))
	return Challenge{Plan: plan, Intent: token}, nil
}

type intent struct {
	id         int64
	channel    string
	action     principal.Action
	targetHash []byte
	required   auth.Assurance
}

// load returns a live intent of the principal's session. With an empty
// token it returns the newest admin intent of the session.
func (s *Service) load(ctx context.Context, p principal.Principal, token string) (intent, error) {
	var in intent
	if len(token) > maxTokenBytes {
		return in, ErrFailed
	}
	query := `SELECT id, channel, action, target_hash, required FROM stepup_intents
		WHERE token_mac = ? AND session_id = ? AND user_id = ? AND expires_at > ?`
	args := []any{s.mac("intent", token), p.SessionID, p.UserID, s.now().UnixMicro()}
	if token == "" {
		query = `SELECT id, channel, action, target_hash, required FROM stepup_intents
			WHERE channel = ? AND session_id = ? AND user_id = ? AND expires_at > ? ORDER BY id DESC LIMIT 1`
		args[0] = ChannelAdmin
	}
	var action, required string
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(&in.id, &in.channel, &action, &in.targetHash, &required)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return in, ErrFailed
	}
	if err != nil {
		return in, fmt.Errorf("stepup: read intent: %w", err)
	}
	in.action, in.required = principal.Action(action), auth.Assurance(required)
	if !in.action.Known() {
		return in, ErrFailed
	}
	// MFA switched on or off since the intent was made: start again.
	if now, err := s.required(ctx, p.UserID); err != nil || now != in.required {
		return in, errors.Join(ErrFailed, err)
	}
	return in, nil
}

// allowed checks that method can confirm the intent for p now.
func (s *Service) allowed(ctx context.Context, p principal.Principal, in intent, method string) error {
	sa, err := s.Sessions.Assurance(ctx, p)
	if err != nil {
		return ErrFailed
	}
	methods, err := s.offered(ctx, p, sa, in.required, in.action)
	if err != nil {
		return err
	}
	if !slices.Contains(methods, method) {
		return ErrFailed
	}
	return nil
}

// Proof is the user's answer to a step-up prompt.
type Proof struct {
	Method string
	// Secret is the password, the directory password or the TOTP code.
	Secret string
	// Credential is the serialized passkey assertion.
	Credential jsontext.Value
}

func passkeyBinding(p principal.Principal, intentID int64) string {
	return "step-up:" + p.SessionID + ":" + itoa(intentID)
}

// PasskeyOptions starts the passkey assertion of an intent (an empty
// token means the newest admin intent of the session).
func (s *Service) PasskeyOptions(ctx context.Context, p principal.Principal, token string) (jsontext.Value, error) {
	in, err := s.load(ctx, p, token)
	if err != nil {
		return nil, err
	}
	if err := s.allowed(ctx, p, in, MethodPasskey); err != nil {
		return nil, err
	}
	return s.Passkeys.AssertionOptions(ctx, p.UserID, passkeyBinding(p, in.id))
}

// Prove checks proof for an intent and, if it holds, completes the intent
// and returns its single grant. A wrong password or code fails with an
// error for which Rejected is true, and the intent stays open.
func (s *Service) Prove(ctx context.Context, p principal.Principal, token string, proof Proof) (string, error) {
	in, err := s.load(ctx, p, token)
	if err != nil {
		return "", err
	}
	if err := s.allowed(ctx, p, in, proof.Method); err != nil {
		return "", err
	}
	if err := s.verify(ctx, p, in, proof); err != nil {
		s.audit().Security(ctx, slog.LevelWarn, event(in.channel, "REJECTED"), "user", p.Username, "action", string(in.action), "method", proof.Method)
		return "", err
	}
	level := assurance(proof.Method)
	if level.Rank() < in.required.Rank() {
		return "", ErrFailed
	}
	grant := newToken()
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM stepup_intents WHERE id = ?`, in.id)
		if err != nil {
			return fmt.Errorf("stepup: complete intent: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(ErrFailed, err) // a concurrent proof completed it
		}
		return s.issueTx(ctx, tx, p, in.action, in.targetHash, level, grant)
	})
	if err != nil {
		return "", err
	}
	s.audit().Security(ctx, slog.LevelInfo, event(in.channel, "GRANTED"), "user", p.Username, "action", string(in.action), "method", proof.Method, "assurance", string(level))
	return grant, nil
}

func (s *Service) verify(ctx context.Context, p principal.Principal, in intent, proof Proof) error {
	switch proof.Method {
	case MethodPassword:
		ok, err := s.Passwords.VerifyPassword(ctx, p.UserID, proof.Secret)
		if err != nil {
			return err
		}
		if !ok {
			return rejected()
		}
		return nil
	case MethodLDAP:
		ok, err := s.LDAP.VerifyStepUp(ctx, p.UserID, proof.Secret)
		if err != nil {
			return err
		}
		if !ok {
			return rejected()
		}
		return nil
	case MethodTOTP:
		err := s.TOTP.CheckCode(ctx, p.UserID, proof.Secret, auth.ScopeStepUp)
		if fault.Is(err, fault.AuthFailed) {
			return rejected()
		}
		return err
	case MethodPasskey:
		if err := s.Passkeys.VerifyAssertion(ctx, p.UserID, passkeyBinding(p, in.id), proof.Credential); err != nil {
			// Like the Python release, every refusal of the assertion ends
			// the prompt; only classified storage failures pass through.
			if fe, ok := fault.From(err); ok && (fe.Code == fault.Internal || fe.Code == fault.StorageError) {
				return err
			}
			return ErrFailed
		}
		return nil
	case MethodBootstrap:
		return s.redeemBootstrap(ctx, p, in, proof.Secret)
	default:
		return ErrFailed
	}
}

// Consume spends grant for action and target. The grant is deleted first
// and then checked against every binding: user, session, action, target,
// expiry, and that its assurance still meets the account's requirement.
// Every refusal is fault.StepUpRequired.
func (s *Service) Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error {
	if grant == "" || len(grant) > maxTokenBytes || !p.Valid() {
		return ErrRequired
	}
	var userID, expires int64
	var sessionID, storedAction, level string
	var targetHash []byte
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `DELETE FROM stepup_grants WHERE token_mac = ?
			RETURNING user_id, session_id, action, target_hash, assurance, expires_at`, s.mac("grant", grant)).
			Scan(&userID, &sessionID, &storedAction, &targetHash, &level, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRequired
	}
	if err != nil {
		return fmt.Errorf("stepup: consume grant: %w", err)
	}
	required, err := s.required(ctx, p.UserID)
	if err != nil {
		return err
	}
	if userID != p.UserID || sessionID != p.SessionID || storedAction != string(action) || !action.Known() ||
		target == "" || !hmac.Equal(targetHash, TargetHash(target)) || expires <= s.now().UnixMicro() ||
		auth.Assurance(level).Rank() < required.Rank() {
		return ErrRequired
	}
	if !slices.Contains(adminActions, action) {
		s.audit().Security(ctx, slog.LevelInfo, "ACCOUNT_STEP_UP_CONSUMED", "user", p.Username, "action", string(action))
	}
	return nil
}
