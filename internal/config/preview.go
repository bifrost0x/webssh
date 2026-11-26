package config

import (
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"time"
)

// previewChecks adds what the Go release reads beyond config.py and the
// limits of this preview.
func previewChecks(p *parser, c *Config, lookup LookupFunc) {
	if c.Profile == ProfileProduction {
		p.fail(configError("DEPLOYMENT_PROFILE", "DEPLOYMENT_PROFILE=production is not supported by this preview: it cannot yet enforce every rule of the production profile. Run the preview with the homelab profile on a copy of the data volume, or keep the Python release for production."))
		return
	}
	cidrs, err := parseProxyCIDRs(p.raw("TRUSTED_PROXY_CIDRS", ""))
	if err != nil {
		p.fail(err)
		return
	}
	c.Proxies.CIDRs = cidrs
	switch {
	case c.Proxies.Hops > 0 && len(cidrs) == 0:
		p.warn(WarnProxy, "TRUSTED_PROXIES", "forwarding headers are trusted from every client that reaches the port directly, so a client can choose the address used for sign-in limits and audit; set TRUSTED_PROXY_CIDRS to the addresses of the proxy")
	case c.Proxies.Hops == 0 && len(cidrs) > 0:
		p.warn(WarnProxy, "TRUSTED_PROXY_CIDRS", "has no effect while TRUSTED_PROXIES is 0")
	}
	if c.Origins.AllowAny {
		if c.Origins.SkipSameOrigin {
			p.warn(WarnOrigin, "SOCKETIO_ALLOW_ANY_ORIGIN", "realtime connections from any web page are accepted; list the trusted origins in CORS_ORIGINS instead")
		} else {
			p.warn(WarnOrigin, "CORS_ORIGINS", "with the wildcard, realtime connections are accepted only from the address WebSSH itself is served from")
		}
	}
	c.Listen = parseListen(p, lookup)
	c.CABundle = caBundle(lookup)
	usageWarnings(p, c)
	if w, ok := timeZoneWarning(lookup, loadZone); ok {
		p.warns = append(p.warns, w)
	}
}

// parseProxyCIDRs reads TRUSTED_PROXY_CIDRS, a list of networks or single
// addresses separated by commas. The variable is new in the Go release, so
// it is strict: an entry that is not an exact network stops the start.
func parseProxyCIDRs(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for part := range strings.SplitSeq(raw, ",") {
		entry := pyStrip(part)
		if entry == "" {
			continue
		}
		var prefix netip.Prefix
		var err error
		if strings.Contains(entry, "/") {
			prefix, err = netip.ParsePrefix(entry)
			if err == nil && prefix != prefix.Masked() {
				err = fmt.Errorf("host bits are set")
			}
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(entry)
			if err == nil && addr.Zone() != "" {
				err = fmt.Errorf("zones are not allowed")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if err != nil {
			return nil, configError("TRUSTED_PROXY_CIDRS", fmt.Sprintf("CONFIGURATION ERROR: TRUSTED_PROXY_CIDRS must list IP networks or addresses separated by commas: %s", pyRepr(entry)))
		}
		if !containsPrefix(out, prefix) {
			out = append(out, prefix)
		}
	}
	return out, nil
}

var maxPort = big.NewInt(65535)

// parseListen reads HOST and PORT like start.py of the Python release.
// The container ignored both and listened on 0.0.0.0:5000, so a PORT that
// start.py would reject is reported and replaced by 5000 instead of
// stopping the start.
func parseListen(p *parser, lookup LookupFunc) Listen {
	l := Listen{Host: "127.0.0.1", Port: 5000}
	if v, ok := lookup("HOST"); ok {
		l.Host = v
	}
	raw, ok := lookup("PORT")
	if !ok {
		return l
	}
	v, parsed := pyInt(raw)
	if !parsed || v.Sign() < 0 || v.Cmp(maxPort) > 0 {
		p.warn(WarnQuirk, "PORT", "the value %q is not a port number; 5000 is used", raw)
		return l
	}
	if !canonicalInt(raw, v) {
		p.warn(WarnQuirk, "PORT", "the value %q is read as %s, as in the Python release", raw, v)
	}
	l.Port = int(v.Int64())
	return l
}

// CABundle is the extra trust anchor location of REQUESTS_CA_BUNDLE or
// CURL_CA_BUNDLE (requests: the first that is not empty). The Python
// release replaced its trust store with it; the Go release adds it to the
// system trust store, so a private certificate authority keeps working.
type CABundle struct {
	Path     string
	Variable string
}

func caBundle(lookup LookupFunc) CABundle {
	for _, name := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		if v, ok := lookup(name); ok && v != "" {
			return CABundle{Path: v, Variable: name}
		}
	}
	return CABundle{}
}

// loadZone is the time zone lookup of the Go runtime for TZ.
func loadZone(name string) error {
	if strings.HasPrefix(name, "/") {
		data, err := os.ReadFile(name) // #nosec G304 -- the zone file the operator names in TZ
		if err != nil {
			return err
		}
		_, err = time.LoadLocationFromTZData(name, data)
		return err
	}
	_, err := time.LoadLocation(name)
	return err
}

// timeZoneWarning reports a TZ the Go runtime cannot load (condition K9).
// Go then uses UTC; glibc also accepts POSIX rules such as
// "CET-1CEST,M3.5.0,M10.5.0/3", which Go does not.
func timeZoneWarning(lookup LookupFunc, load func(string) error) (Warning, bool) {
	tz, ok := lookup("TZ")
	if !ok || tz == "" {
		return Warning{}, false
	}
	name := strings.TrimPrefix(tz, ":")
	if name == "" || name == "UTC" {
		return Warning{}, false
	}
	if err := load(name); err == nil {
		return Warning{}, false
	}
	msg := fmt.Sprintf("the time zone %q cannot be loaded; times are shown in UTC", tz)
	if strings.ContainsAny(name, "0123456789") && (strings.Contains(name, ",") || !strings.Contains(name, "/")) {
		msg += "; POSIX time zone rules are not supported, use a name such as Europe/Berlin"
	}
	return Warning{Kind: WarnTimeZone, Variable: "TZ", Message: msg}, true
}
