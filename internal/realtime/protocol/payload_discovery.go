package protocol

// Message types of the area "hostops.discovery" (HO2): what a connection
// to a saved host found out about it (docs/architecture/m2-contracts.md,
// "Message types (hostops.discovery)"). They are pushed to every open
// connection of the account, because the facts belong to the saved host
// and not to the browser tab that connected.
const (
	// TypeDiscoveryPlatform carries the facts of the identity probe or of
	// the authenticated greeting (Socket.IO host_platform).
	TypeDiscoveryPlatform = "hostops.discovery.platform"
	// TypeDiscoveryMaintenance says that the login recheck lowered a
	// restart hint (Socket.IO host_maintenance).
	TypeDiscoveryMaintenance = "hostops.discovery.maintenance"
)

// DiscoveryIdentity is the stored identity of a saved host as the probe
// read it; nil members are unknown.
type DiscoveryIdentity struct {
	State           string   `json:"state"`
	Platform        *string  `json:"platform"`
	Family          *string  `json:"family"`
	OSID            *string  `json:"os_id"`
	OSVersion       *string  `json:"os_version"`
	Virt            *string  `json:"virt"`
	Graphical       *bool    `json:"graphical"`
	Guests          *int     `json:"guests"`
	Services        []string `json:"services"`
	ContainerAccess *string  `json:"container_access"`
}

// DiscoveryPlatform names the saved host whose facts changed. Without
// Identity only the stored host changed (a greeting without a POSIX shell,
// or a probe that found nothing) and the page reloads the saved hosts.
type DiscoveryPlatform struct {
	ProfileID string             `json:"profile_id"`
	Platform  string             `json:"platform,omitzero"`
	Services  []string           `json:"services,omitzero"`
	Identity  *DiscoveryIdentity `json:"identity,omitzero"`
}

// DiscoveryMaintenance names the saved host whose restart hint changed.
type DiscoveryMaintenance struct {
	ProfileID string `json:"profile_id"`
}
