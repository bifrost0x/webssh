package settings

import (
	"strconv"

	"github.com/bifrost0x/webssh/internal/principal"
)

func itoa(n int) string { return strconv.Itoa(n) }

// weakening are the values that open the instance further: they are
// audited at level WARNING (self-registration, the SSH gateway, lifting
// the tailnet block and the role permissions of D-18/D-29).
var weakening = map[string]bool{
	"registration_enabled": true, "ssh_gateway_enabled": true, "tailscale_ssh_restrict_tailnet_routes": false,
	SettingDiscoveryUsers: true, SettingReachabilityUsers: true,
}

var flagMessages = []struct{ name, message string }{
	{"registration_enabled", "Admin changed registration setting"},
	{"ssh_gateway_enabled", "Admin changed SSH gateway setting"},
	{"herdr_enabled", "Admin changed Herdr setting"},
	{"support_links_enabled", "Admin changed support links setting"},
	{"tailscale_ssh_restrict_tailnet_routes", "Admin changed tailnet route restriction"},
	{SettingDiscoveryUsers, "Admin changed host discovery permission"},
	{SettingReachabilityUsers, "Admin changed reachability check permission"},
}

// audit writes the events of admin_set_settings for one accepted write.
// app is the state before the write, for values nothing was stored for.
func (h *AdminHTTP) audit(p principal.Principal, before App, results map[string]AdminChange) {
	event := func(warn bool, kv ...any) {
		if warn {
			h.Audit.SecurityWarning("APPLICATION_FEATURE_CHANGED", kv...)
		} else {
			h.Audit.Security("APPLICATION_FEATURE_CHANGED", kv...)
		}
	}
	for _, f := range flagMessages {
		c, ok := results[f.name]
		if !ok {
			continue
		}
		h.logger().Info(f.message, "admin", p.Username, f.name, c.Current)
		previous := c.Previous
		if previous == nil {
			// Nothing stored yet: compare against the value in effect.
			switch f.name {
			case "registration_enabled":
				previous = before.env.Values["REGISTRATION_ENABLED"]
			case "ssh_gateway_enabled":
				previous = false
			}
		}
		weak, listed := weakening[f.name]
		warned := listed && c.Current == weak && previous != c.Current
		event(warned, "admin", p.Username, "feature", f.name, "enabled", c.Current)
	}
	for _, b := range SignInBounds {
		c, ok := results[b.Name]
		if !ok || c.Previous == c.Current {
			continue
		}
		prev, _ := c.Previous.(int64)
		cur, _ := c.Current.(int64)
		h.logger().Info("Admin changed sign-in protection setting", "admin", p.Username, "setting", b.Name,
			"previous_value", prev, "value", cur)
		// Every value here loosens protection as it grows.
		event(cur > prev, "admin", p.Username, "feature", b.Name, "previous_value", prev, "value", cur)
	}
	for _, name := range featurePolicies {
		if c, ok := results[name]; ok && c.Previous != c.Current {
			event(false, "admin", p.Username, "feature", name, "enabled", c.Current)
		}
	}
	for _, name := range runtimeFeatureOrder {
		if c, ok := results[name]; ok {
			h.Audit.Security("RUNTIME_FEATURE_CHANGED", "admin", p.Username, "feature", name, "enabled", c.Current)
		}
	}
}
