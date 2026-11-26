package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Limits of one attempt. They match the Python release
// (app/ssh_gateway_interaction.py).
const (
	MaxPrompts        = protocol.MaxInteractivePrompts
	MaxChallengeBytes = protocol.MaxInteractiveBytes
	MaxAnswerBytes    = protocol.MaxInteractiveBytes
	MaxInputFrame     = protocol.MaxGatewayInput
	MaxInputTotal     = 8 << 10
	MaxOutputFrame    = 4096
	MaxOutputTotal    = 8 << 20
	MaxUnackedFrames  = 4
	ChallengeTimeout  = 120 * time.Second
	DefaultAckTimeout = 5 * time.Second
	AuthTimeout       = 180 * time.Second
	SetupTimeout      = 180 * time.Second
	AttemptTimeout    = 300 * time.Second
	promptIDEntropy   = 24
)

// Attempt failures, with the texts of the Python release.
var (
	// ErrCancelled is what the browser sees for every timeout and
	// cancellation of an attempt.
	ErrCancelled = fault.New(fault.Cancelled, "Gateway connection cancelled or timed out")
	// ErrDisabled ends a gateway attempt when the administrator switches
	// the gateway off.
	ErrDisabled = fault.New(fault.Forbidden, "SSH gateway integration is disabled by the administrator")

	errChallenge     = fault.New(fault.SSHProtocol, "Invalid gateway challenge")
	errChallengeSize = fault.New(fault.SSHProtocol, "Gateway challenge exceeds byte limit")
	errPending       = fault.New(fault.SSHProtocol, "Gateway challenge already pending")
	errOutputFrame   = fault.New(fault.SSHProtocol, "Invalid gateway output frame")
	errOutputLimit   = fault.New(fault.SSHProtocol, "Gateway output limit exceeded")
	errPeerGone      = fault.New(fault.Cancelled, "")
)

// Owner identifies the realtime connection and the user an attempt belongs
// to; only they can answer it.
type Owner struct {
	Peer   uint64
	UserID int64
}

// Events sends a server event to the connection that started the attempt.
// protocol.Peer implements it.
type Events interface {
	SendEvent(typ string, payload any) error
}

// Prompt is one keyboard-interactive question.
type Prompt struct {
	Label string
	Echo  bool
}

// Attempt is the browser side of one connection attempt: one pending
// challenge at a time, bounded input during setup and an output stream with
// acknowledgement-based flow control. All methods are safe for concurrent
// use. Nothing stored here outlives the attempt; no answer is kept after
// it was handed to the SSH client.
type Attempt struct {
	owner     Owner
	requestID string
	events    Events
	// check reports ErrDisabled for a gateway attempt once the gateway is
	// switched off; nil for other attempts.
	check        func() error
	authDeadline time.Time
	ackTimeout   time.Duration

	mu         sync.Mutex
	phase      string // "auth" or "setup"
	pending    *challenge
	inputs     [][]byte
	inputBytes int
	inputReady chan struct{} // signalled when inputs becomes non-empty
	outBytes   int
	seq        uint64
	unacked    map[uint64]struct{}
	ackSignal  chan struct{}
	carry      []byte // incomplete UTF-8 sequence held for the next frame
}

type challenge struct {
	id      string
	prompts int
	answer  chan []string // capacity 1; written once under mu
}

func newAttempt(owner Owner, requestID string, events Events, check func() error, now time.Time) *Attempt {
	return &Attempt{
		owner: owner, requestID: requestID, events: events, check: check,
		authDeadline: now.Add(AuthTimeout), ackTimeout: DefaultAckTimeout, phase: "auth",
		inputReady: make(chan struct{}, 1),
		unacked:    map[uint64]struct{}{},
		ackSignal:  make(chan struct{}, 1),
	}
}

// RequestID is the request_id of the attempt.
func (a *Attempt) RequestID() string { return a.requestID }

// Check returns ErrDisabled once a gateway attempt may no longer run.
func (a *Attempt) Check() error {
	if a.check == nil {
		return nil
	}
	return a.check()
}

// Challenge forwards one keyboard-interactive round to the browser and
// waits for the matching answer. It gives up with ErrCancelled after
// ChallengeTimeout, at the end of the authentication budget or of ctx.
// role is the prompt context of the realtime protocol ("target",
// "jump_host").
func (a *Attempt) Challenge(ctx context.Context, role, title, instructions string, prompts []Prompt) ([]string, error) {
	if len(prompts) > MaxPrompts {
		return nil, errChallenge
	}
	size := len(title) + len(instructions)
	for _, p := range prompts {
		size += len(p.Label)
	}
	if size > MaxChallengeBytes {
		return nil, errChallengeSize
	}
	if err := a.Check(); err != nil {
		return nil, err
	}
	wait := min(ChallengeTimeout, time.Until(a.authDeadline))
	if d, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(d))
	}
	if wait <= 0 {
		return nil, ErrCancelled
	}
	c := &challenge{id: newPromptID(), prompts: len(prompts), answer: make(chan []string, 1)}
	a.mu.Lock()
	if a.pending != nil {
		a.mu.Unlock()
		return nil, errPending
	}
	a.pending = c
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.pending == c {
			a.pending = nil
		}
		a.mu.Unlock()
	}()

	shown := make([]protocol.InteractivePrompt, len(prompts))
	for i, p := range prompts {
		shown[i] = protocol.InteractivePrompt{Label: validText(p.Label), Echo: p.Echo}
	}
	err := a.events.SendEvent(protocol.TypePromptInteractive, protocol.PromptInteractive{
		PromptID: c.id, RequestID: a.requestID, Context: role,
		Title: validText(title), Instructions: validText(instructions), Prompts: shown,
		ExpiresIn: int((wait + time.Second - 1) / time.Second),
	})
	if err != nil {
		return nil, errPeerGone
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case answers := <-c.answer:
		if err := a.Check(); err != nil {
			return nil, err
		}
		return answers, nil
	case <-timer.C:
		return nil, ErrCancelled
	case <-ctx.Done():
		return nil, ErrCancelled
	}
}

// Answer delivers the browser's answers. It accepts exactly one answer for
// the pending challenge from the owner, with one string per prompt and at
// most MaxAnswerBytes in total.
func (a *Attempt) Answer(owner Owner, promptID string, answers []string) bool {
	if owner != a.owner {
		return false
	}
	size := 0
	for _, s := range answers {
		if !utf8.ValidString(s) {
			return false
		}
		size += len(s)
	}
	if size > MaxAnswerBytes {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.pending
	if c == nil || c.id != promptID || len(answers) != c.prompts {
		return false
	}
	a.pending = nil // one-shot: a replay finds nothing pending
	c.answer <- append([]string(nil), answers...)
	return true
}

// StartSetup switches from authentication to the setup phase, in which the
// browser may type into the temporary gateway terminal.
func (a *Attempt) StartSetup() error {
	if err := a.Check(); err != nil {
		return err
	}
	a.mu.Lock()
	a.phase = "setup"
	a.mu.Unlock()
	if err := a.events.SendEvent(protocol.TypeGatewaySetup, protocol.GatewaySetup{RequestID: a.requestID, Phase: "setup"}); err != nil {
		return errPeerGone
	}
	return nil
}

// Input queues keystrokes for the gateway terminal during setup: at most
// MaxInputFrame bytes per call and MaxInputTotal per attempt.
func (a *Attempt) Input(owner Owner, value string) bool {
	if owner != a.owner || value == "" || len(value) > MaxInputFrame || !utf8.ValidString(value) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != "setup" || a.inputBytes+len(value) > MaxInputTotal {
		return false
	}
	a.inputBytes += len(value)
	a.inputs = append(a.inputs, []byte(value))
	select {
	case a.inputReady <- struct{}{}:
	default:
	}
	return true
}

// NextInput waits for queued input or ctx.
func (a *Attempt) NextInput(ctx context.Context) ([]byte, error) {
	for {
		a.mu.Lock()
		if len(a.inputs) > 0 {
			data := a.inputs[0]
			a.inputs = a.inputs[1:]
			a.mu.Unlock()
			return data, nil
		}
		a.mu.Unlock()
		select {
		case <-a.inputReady:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Output forwards gateway terminal output. At most MaxUnackedFrames frames
// are in flight; a browser that stops acknowledging cancels the attempt
// after the acknowledgement timeout instead of letting output pile up.
func (a *Attempt) Output(ctx context.Context, data []byte) error {
	if len(data) > MaxOutputFrame {
		return errOutputFrame
	}
	if err := a.Check(); err != nil {
		return err
	}
	timer := time.NewTimer(a.ackTimeout)
	defer timer.Stop()
	for {
		a.mu.Lock()
		if a.outBytes+len(data) > MaxOutputTotal {
			a.mu.Unlock()
			return errOutputLimit
		}
		if len(a.unacked) < MaxUnackedFrames {
			a.outBytes += len(data)
			a.seq++
			a.unacked[a.seq] = struct{}{}
			seq, text := a.seq, a.decode(data)
			a.mu.Unlock()
			if err := a.events.SendEvent(protocol.TypeGatewayOutput, protocol.GatewayOutput{RequestID: a.requestID, Sequence: seq, Data: text}); err != nil {
				return errPeerGone
			}
			return nil
		}
		a.mu.Unlock()
		select {
		case <-a.ackSignal:
		case <-timer.C:
			return ErrCancelled
		case <-ctx.Done():
			return ErrCancelled
		}
	}
}

// Ack releases one output frame of the owner.
func (a *Attempt) Ack(owner Owner, seq uint64) bool {
	if owner != a.owner {
		return false
	}
	a.mu.Lock()
	_, ok := a.unacked[seq]
	delete(a.unacked, seq)
	a.mu.Unlock()
	if ok {
		select {
		case a.ackSignal <- struct{}{}:
		default:
		}
	}
	return ok
}

// decode turns bytes into text without splitting a UTF-8 sequence across
// frames (the Python release decoded each 4 KiB chunk alone and replaced
// split characters). Caller holds mu.
func (a *Attempt) decode(data []byte) string {
	buf := append(a.carry, data...)
	cut := len(buf)
	for i := len(buf) - 1; i >= 0 && i >= len(buf)-utf8.UTFMax; i-- {
		if utf8.RuneStart(buf[i]) {
			if !utf8.FullRune(buf[i:]) {
				cut = i
			}
			break
		}
	}
	a.carry = append([]byte(nil), buf[cut:]...)
	return validText(string(buf[:cut]))
}

// validText replaces every invalid UTF-8 byte with U+FFFD, as Python's
// decode(errors="replace") did.
func validText(s string) string { return string([]rune(s)) }

// newPromptID returns 32 URL-safe characters (Python: token_urlsafe(24)).
func newPromptID() string {
	var b [promptIDEntropy]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
