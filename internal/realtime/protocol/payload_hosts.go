package protocol

import "encoding/json/jsontext"

// The hosts.* requests carry the members the frontend sends today
// (profile-manager.js, jump-host-manager.js, socks-proxy-manager.js and the
// workspace's move and organize calls). Every member is a raw JSON value:
// the owner applies the rules of the Python release, which look at
// presence, truthiness and type separately ("in payload", "or 22", "is
// not bool"), so a typed field would change which inputs are refused and
// with which text. An absent member is a zero-length value, an explicit
// null is "null". Unknown members are still refused by the strict decoder.

// HostsProfileSave creates or updates a saved host (save_profile). Without
// ID it creates one.
type HostsProfileSave struct {
	ID                 jsontext.Value `json:"id"`
	Name               jsontext.Value `json:"name"`
	PlatformIcon       jsontext.Value `json:"platform_icon"`
	Group              jsontext.Value `json:"group"`
	Host               jsontext.Value `json:"host"`
	Port               jsontext.Value `json:"port"`
	Username           jsontext.Value `json:"username"`
	AuthType           jsontext.Value `json:"auth_type"`
	KeyID              jsontext.Value `json:"key_id"`
	JumpHostID         jsontext.Value `json:"jump_host_id"`
	SOCKSProxyID       jsontext.Value `json:"socks_proxy_id"`
	StartupMode        jsontext.Value `json:"startup_mode"`
	StartupCommands    jsontext.Value `json:"startup_commands"`
	CommandID          jsontext.Value `json:"command_id"`
	CommandSetID       jsontext.Value `json:"command_set_id"`
	ParametersOverride jsontext.Value `json:"parameters_override"`
	UseTmux            jsontext.Value `json:"use_tmux"`
	Herdr              jsontext.Value `json:"herdr"`
	UseHerdr           jsontext.Value `json:"use_herdr"`
	GreetingPlatform   jsontext.Value `json:"greeting_platform"`
	Favorite           jsontext.Value `json:"favorite"`
	RoleOverride       jsontext.Value `json:"role_override"`
}

// HostsProfileRef names one saved host (delete_profile).
type HostsProfileRef struct {
	ProfileID jsontext.Value `json:"profile_id"`
}

// HostsProfileOrganize changes the group or favorite flag of one saved
// host (update_profile_organization).
type HostsProfileOrganize struct {
	ProfileID jsontext.Value `json:"profile_id"`
	Group     jsontext.Value `json:"group"`
	Favorite  jsontext.Value `json:"favorite"`
}

// HostsProfileMove moves one saved host to a position in a group
// (move_profile).
type HostsProfileMove struct {
	ProfileID                 jsontext.Value `json:"profile_id"`
	ExpectedSourceGroup       jsontext.Value `json:"expected_source_group"`
	TargetGroup               jsontext.Value `json:"target_group"`
	TargetIndex               jsontext.Value `json:"target_index"`
	ConfirmSourceGroupRemoval jsontext.Value `json:"confirm_source_group_removal"`
}

// HostsJumpSave creates or updates a jump host (save_jump_host).
type HostsJumpSave struct {
	JumpHostID jsontext.Value `json:"jump_host_id"`
	Name       jsontext.Value `json:"name"`
	Host       jsontext.Value `json:"host"`
	Port       jsontext.Value `json:"port"`
	Username   jsontext.Value `json:"username"`
	AuthType   jsontext.Value `json:"auth_type"`
	KeyID      jsontext.Value `json:"key_id"`
}

// HostsJumpRef names one jump host (delete_jump_host).
type HostsJumpRef struct {
	JumpHostID jsontext.Value `json:"jump_host_id"`
}

// HostsSOCKSSave creates or updates a SOCKS5 proxy (save_socks_proxy).
type HostsSOCKSSave struct {
	SOCKSProxyID jsontext.Value `json:"socks_proxy_id"`
	Name         jsontext.Value `json:"name"`
	Host         jsontext.Value `json:"host"`
	Port         jsontext.Value `json:"port"`
	Username     jsontext.Value `json:"username"`
	AuthType     jsontext.Value `json:"auth_type"`
	RemoteDNS    jsontext.Value `json:"remote_dns"`
}

// HostsSOCKSRef names one SOCKS5 proxy (delete_socks_proxy).
type HostsSOCKSRef struct {
	SOCKSProxyID jsontext.Value `json:"socks_proxy_id"`
}

// Results. A stored record is sent as the JSON object it is stored as,
// with its member order, so a saved host keeps fields this release does
// not know.

// HostsProfiles is the result of hosts.profile.list.
type HostsProfiles struct {
	Profiles []jsontext.Value `json:"profiles"`
}

// HostsProfile is the result of hosts.profile.save and
// hosts.profile.organize.
type HostsProfile struct {
	Profile jsontext.Value `json:"profile"`
}

// HostsPlacement is where one saved host stands after a move.
type HostsPlacement struct {
	ID        string         `json:"id"`
	Group     jsontext.Value `json:"group"`
	SortOrder jsontext.Value `json:"sort_order"`
	UpdatedAt jsontext.Value `json:"updated_at,omitzero"`
}

// HostsMoved is the result of hosts.profile.move. The member names are
// those the page reads from the move acknowledgement.
type HostsMoved struct {
	RequiresConfirmation bool             `json:"requires_confirmation"`
	Organization         []HostsPlacement `json:"organization"`
}

// HostsJumpHosts is the result of hosts.jump.list.
type HostsJumpHosts struct {
	JumpHosts []jsontext.Value `json:"jump_hosts"`
}

// HostsJumpHost is the result of hosts.jump.save.
type HostsJumpHost struct {
	JumpHost jsontext.Value `json:"jump_host"`
}

// HostsSOCKSProxies is the result of hosts.socks.list.
type HostsSOCKSProxies struct {
	SOCKSProxies []jsontext.Value `json:"socks_proxies"`
}

// HostsSOCKSProxy is the result of hosts.socks.save.
type HostsSOCKSProxy struct {
	SOCKSProxy jsontext.Value `json:"socks_proxy"`
}
