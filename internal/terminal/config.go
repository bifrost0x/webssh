package terminal

import (
	"time"

	"github.com/bifrost0x/webssh/internal/config"
)

// Config holds the limits of the terminal capability. Zero fields take the
// defaults, which are those of the Python release where it had one.
type Config struct {
	Flow  FlowLimits
	Input InputLimits

	// IdleTimeout ends a session without output, input or keepalive for
	// this long (SESSION_TIMEOUT, default 30 min); IdleWarning before it,
	// terminal.timeout_warning is sent once (2 min).
	IdleTimeout time.Duration
	IdleWarning time.Duration

	// ReplayBytes is the output kept per session for a reattaching
	// browser (Python: 512000 characters). It is capped to the
	// per-connection output budget, so a replay always fits an idle
	// connection.
	ReplayBytes int
	// ReadSize is one read from the shell and the largest output frame
	// (32 KiB, as the Python reader).
	ReadSize int

	// PromptTimeout bounds one host-key or banner prompt (60 s).
	PromptTimeout time.Duration
	// MaxPrompts bounds pending prompts of the process (128).
	MaxPrompts int
	// OpenTimeout bounds terminal.open including every prompt (10 min;
	// the dialer bounds each hop by its own timeouts).
	OpenTimeout time.Duration
	// MaxChannels bounds the terminals of one connection (64).
	MaxChannels int
	// SweepEvery is the period of the idle and acknowledgement checks
	// (1 s).
	SweepEvery time.Duration
	// TmuxPrefix starts the names of new tmux sessions
	// (TMUX_SESSION_PREFIX, config.Features.TmuxSessionPrefix; "webssh"
	// when empty).
	TmuxPrefix string
	// HoldBack is how long the output filter keeps the start of a
	// possible device-attribute sequence at the end of a read before it
	// sends it unchanged (20 ms).
	HoldBack time.Duration
}

// Defaults of Config.
const (
	DefaultIdleTimeout   = 30 * time.Minute
	DefaultIdleWarning   = 2 * time.Minute
	DefaultReplayBytes   = 512000
	DefaultReadSize      = 32 << 10
	DefaultPromptTimeout = 60 * time.Second
	DefaultMaxPrompts    = 128
	DefaultOpenTimeout   = 10 * time.Minute
	DefaultMaxChannels   = 64
	DefaultSweepEvery    = time.Second
	DefaultHoldBack      = 20 * time.Millisecond
)

// FromConfig takes the documented settings (SESSION_TIMEOUT, SSH_OUTPUT_*,
// SSH_INPUT_*) from the loaded configuration. QUOTA_SSH_SESSION_* reach
// the manager through Deps.Quotas.
func FromConfig(t config.Terminal) Config {
	o, in := t.Output, t.Input
	return Config{
		Flow: FlowLimits{
			ConnBytes: o.BytesPerSocket, ConnFrames: o.EventsPerSocket,
			UserBytes: o.BytesPerUser, UserFrames: o.EventsPerUser,
			GlobalBytes: o.BytesGlobal, GlobalFrames: o.EventsGlobal,
			AckTimeout: o.AckTimeout,
		},
		Input: InputLimits{
			MaxFrameBytes: in.MaxBytes,
			SessionRate:   float64(in.SessionBytesPerSecond), SessionBurst: float64(in.SessionBurstBytes),
			UserRate: float64(in.UserBytesPerSecond), UserBurst: float64(in.UserBurstBytes),
		},
		IdleTimeout: t.SessionTimeout,
	}
}

func (c *Config) defaults() {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	c.Flow.defaults()
	c.Input.defaults()
	defD(&c.IdleTimeout, DefaultIdleTimeout)
	defD(&c.IdleWarning, DefaultIdleWarning)
	c.IdleWarning = min(c.IdleWarning, c.IdleTimeout)
	def(&c.ReadSize, DefaultReadSize)
	def(&c.ReplayBytes, DefaultReplayBytes)
	c.ReplayBytes = min(c.ReplayBytes, c.Flow.ConnBytes, c.Flow.UserBytes, c.Flow.GlobalBytes)
	defD(&c.PromptTimeout, DefaultPromptTimeout)
	def(&c.MaxPrompts, DefaultMaxPrompts)
	defD(&c.OpenTimeout, DefaultOpenTimeout)
	def(&c.MaxChannels, DefaultMaxChannels)
	defD(&c.SweepEvery, DefaultSweepEvery)
	defD(&c.HoldBack, DefaultHoldBack)
}
