package main

import (
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/store"
)

var (
	_ smb.Network = (*netpolicy.Policy)(nil)
	_ smb.Sources = (*files.Registry)(nil)
)

// smbArea wires the area "smb" (FS3): the SMB file backend
// (internal/files/smb), the saved share definitions and their migration
// (E22). Opened shares are sources of the file source registry, which
// owns their quota and idle expiry; saved passwords come from the vault.
//
// With SMB_ENABLED false no smb.* type is mounted: the shim answers the
// page with SMB_DISABLED, as the Python handlers did. The saved
// definitions stay in the store either way.
func smbArea() extension {
	return extension{
		name:    "smb",
		schemas: []store.Schema{smb.Schema()},
		wire: func(sys *system) error {
			cfg := sys.cfg.SMB
			if !cfg.Enabled {
				return nil
			}
			svc := &smb.Service{
				Shares: &smb.Shares{DB: sys.db, Max: cfg.MaxSavedShares},
				Config: smb.Config{Network: sys.policy, AllowedTargets: smbAllowedTargets(cfg),
					ConnectTimeout: cfg.ConnectTimeout, IOIdleTimeout: cfg.IOIdleTimeout},
				Sources:   sys.fileSources,
				Passwords: savedPasswords{sys.vault},
				Logger:    sys.log,
			}
			sys.realtime.Mount(svc.Routes()...)
			return nil
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddSMB(r)
		},
	}
}

// smbAllowedTargets puts SMB_ALLOWED_TARGETS into the canonical form the
// backend compares requested hosts in (parse_smb_allowed_targets).
func smbAllowedTargets(cfg config.SMB) []string {
	var out []string
	for _, t := range cfg.AllowedTargets {
		if c, err := netpolicy.CanonicalHost(t); err == nil {
			out = append(out, c)
		}
	}
	return out
}
