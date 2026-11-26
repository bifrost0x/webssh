package config

import (
	"errors"
	"slices"
	"time"
)

// SMB holds the SMB file source settings of config.py.
type SMB struct {
	// Enabled is SMB_ENABLED.
	Enabled bool
	// AllowedTargets is SMB_ALLOWED_TARGETS in the canonical form of the
	// start-up check (_canonical_smb_target); entries that need IDNA are
	// left out with a warning, as for the other host allowlists.
	AllowedTargets []string
	// ConnectTimeout is SMB_CONNECT_TIMEOUT_SECONDS, IOIdleTimeout
	// SMB_IO_IDLE_TIMEOUT_SECONDS.
	ConnectTimeout, IOIdleTimeout time.Duration
	// The rate limits of the realtime messages in Flask-Limiter notation:
	// SMB_CONNECT_RATELIMIT, SMB_SHARE_MUTATION_RATELIMIT and
	// SMB_SHARE_LIST_RATELIMIT.
	ConnectRateLimit, ShareMutationRateLimit, ShareListRateLimit string
	// MaxSavedShares is SMB_MAX_SAVED_SHARES (1 to 1000).
	MaxSavedShares int
}

// loadSMB reads the SMB settings. The checks of validate_security_config
// run in validate.
func loadSMB(p *parser, c *Config, in *pending) {
	s := &c.SMB
	s.Enabled = in.smbEnabled
	s.ConnectTimeout = time.Duration(in.smbConnectTimeout) * time.Second
	s.IOIdleTimeout = time.Duration(in.smbIdleTimeout) * time.Second
	s.ConnectRateLimit = p.str("SMB_CONNECT_RATELIMIT", "SMB_CONNECT_RATELIMIT", "5 per minute", false)
	s.ShareMutationRateLimit = p.str("SMB_SHARE_MUTATION_RATELIMIT", "SMB_SHARE_MUTATION_RATELIMIT", "30 per minute", false)
	s.ShareListRateLimit = p.str("SMB_SHARE_LIST_RATELIMIT", "SMB_SHARE_LIST_RATELIMIT", "60 per minute", false)
	s.MaxSavedShares = int(p.bounded("SMB_MAX_SAVED_SHARES", 100, 1, 1000))
	for _, raw := range in.smbTargets {
		canonical, err := smbTarget(raw)
		if errors.Is(err, errNonASCIIHost) {
			p.warn(WarnNoEffect, "SMB_ALLOWED_TARGETS", "the entry %q is ignored: this preview supports only ASCII host names here", raw)
			continue
		}
		if err == nil && !slices.Contains(s.AllowedTargets, canonical) {
			s.AllowedTargets = append(s.AllowedTargets, canonical)
		}
	}
}
