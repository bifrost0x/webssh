// Package netpolicy is the one policy for all outbound targets (ADR 0010):
// roles, shared address classes, the optional restriction through
// BLOCK_INTERNAL_SSH and its allowances, and the tailnet rule. A target is
// resolved and admitted once; the dialer connects to the admitted address.
package netpolicy

// Role says what an outbound connection is for. Address rules and refusal
// messages differ per role.
type Role string

// Roles of outbound connections.
const (
	RoleSSH   Role = "ssh"   // SSH target and jump hosts
	RoleSMB   Role = "smb"   // SMB servers
	RoleSOCKS Role = "socks" // SOCKS5 proxies
	RoleProbe Role = "probe" // reachability checks
)
