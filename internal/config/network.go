package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// allowlistableNetworks are ALLOWLISTABLE_INTERNAL_NETWORKS of config.py.
var allowlistableNetworks = func() []pyNetwork {
	var out []pyNetwork
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"} {
		n, err := pyIPNetwork(s)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

// loadNetwork follows config.py from BLOCK_INTERNAL_SSH to the tmux
// settings.
func loadNetwork(p *parser, c *Config, in *pending) {
	n := &c.Network
	n.BlockInternalSSH = p.flag("BLOCK_INTERNAL_SSH", "BLOCK_INTERNAL_SSH", "false")
	n.ProxyJumpRemoteDNS = p.csvList("PROXY_JUMP_REMOTE_DNS_ALLOWLIST", "PROXY_JUMP_REMOTE_DNS_ALLOWLIST")
	if !p.failed() {
		names, err := remoteDNSAllowlist(p.raw("SOCKS_REMOTE_DNS_ALLOWLIST", ""), "SOCKS_REMOTE_DNS_ALLOWLIST")
		if err != nil {
			p.fail(err)
		}
		n.SOCKSRemoteDNS = names
		p.record("SOCKS_REMOTE_DNS_ALLOWLIST", listView(names))
	}
	if !p.failed() {
		nets, err := internalNetworkAllowlist(p.raw("SSH_ALLOWED_INTERNAL_NETWORKS", ""))
		if err != nil {
			p.fail(err)
		}
		view := []string{}
		for _, net := range nets {
			view = append(view, net.String())
			if pf := net.prefix(); !containsPrefix(n.AllowedInternalNetworks, pf) {
				n.AllowedInternalNetworks = append(n.AllowedInternalNetworks, pf)
			}
		}
		p.record("SSH_ALLOWED_INTERNAL_NETWORKS", view)
	}

	s := &c.Stores
	s.SSHKeyMaxRecords = int(p.bounded("SSH_KEY_MAX_RECORDS", 100, 1, 1000))
	s.SSHKeyStoreMaxBytes = int(p.bounded("SSH_KEY_STORE_MAX_BYTES", 8*mib, 64*kib, 64*mib))

	in.smbEnabled = p.flag("SMB_ENABLED", "SMB_ENABLED", "false")
	in.smbTargets = p.csvList("SMB_ALLOWED_TARGETS", "SMB_ALLOWED_TARGETS")
	in.smbConnectTimeout = p.positive("SMB_CONNECT_TIMEOUT_SECONDS", 10)
	in.smbIdleTimeout = p.positive("SMB_IO_IDLE_TIMEOUT_SECONDS", 30)
	p.str("SMB_CONNECT_RATELIMIT", "SMB_CONNECT_RATELIMIT", "5 per minute", false)
	p.str("SMB_SHARE_MUTATION_RATELIMIT", "SMB_SHARE_MUTATION_RATELIMIT", "30 per minute", false)
	p.str("SMB_SHARE_LIST_RATELIMIT", "SMB_SHARE_LIST_RATELIMIT", "60 per minute", false)
	p.bounded("SMB_MAX_SAVED_SHARES", 100, 1, 1000)

	p.anyInt("MAX_DOWNLOAD_SIZE", 100*mib)
	p.anyInt("MAX_ZIP_DOWNLOAD_SIZE", 500*mib)
	c.Files.MaxTransferMembers = int(p.positive("MAX_TRANSFER_MEMBERS", 10000))
	c.Files.MaxPreviewBytes = p.positive("MAX_PREVIEW_SIZE", 512000)
	c.Files.MaxPreviewTailLines = p.positive("MAX_PREVIEW_TAIL_LINES", 10000)
	c.Files.MaxSupportedFileSize = p.positive("MAX_SUPPORTED_FILE_SIZE", gib)
	s.MaxWebAuthnJSONSize = int(min(p.positive("MAX_WEBAUTHN_JSON_SIZE", 64*kib), 64*kib))
	p.record("MAX_WEBAUTHN_JSON_SIZE", fmt.Sprint(s.MaxWebAuthnJSONSize))
	s.MaxRecoveryJSONSize = int(min(p.positive("MAX_RECOVERY_JSON_SIZE", 4096), 4096))
	p.record("MAX_RECOVERY_JSON_SIZE", fmt.Sprint(s.MaxRecoveryJSONSize))

	loadTmux(p, c)
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool { return slices.Contains(list, p) }

// internalNetworkAllowlist is parse_internal_network_allowlist of
// config.py.
func internalNetworkAllowlist(raw string) ([]pyNetwork, error) {
	var out []pyNetwork
	for part := range strings.SplitSeq(raw, ",") {
		entry := pyStrip(part)
		if entry == "" {
			continue
		}
		n, err := pyIPNetwork(entry)
		if err != nil {
			return nil, configError("SSH_ALLOWED_INTERNAL_NETWORKS", "SECURITY ERROR: SSH_ALLOWED_INTERNAL_NETWORKS contains an invalid network: "+pyRepr(entry))
		}
		allowed := slices.ContainsFunc(allowlistableNetworks, n.subnetOf)
		if !allowed {
			return nil, configError("SSH_ALLOWED_INTERNAL_NETWORKS", "SECURITY ERROR: SSH_ALLOWED_INTERNAL_NETWORKS accepts only networks inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7: "+pyRepr(entry))
		}
		dup := false
		for _, o := range out {
			if o.equal(n) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, n)
		}
	}
	return out, nil
}
