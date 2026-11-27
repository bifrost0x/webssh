package httpapi

import (
	"regexp"
	"slices"
	"testing"
)

var assetRef = regexp.MustCompile(`(?:src|href)="(?:/webssh)?/static/([^"?]+)\?v=`)

// assetOrder lists the static files a page references, in document order.
func assetOrder(page []byte) []string {
	var out []string
	for _, m := range assetRef.FindAllSubmatch(page, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// realtimeClient is the load order of the realtime client (shim) in the
// workspace: each file registers on the one before it.
var realtimeClient = []string{
	"js/realtime-emitter.js",
	"js/realtime-acks.js",
	"js/realtime-wire.js",
	"js/realtime-shim-hosts.js",
	"js/realtime-shim-keys.js",
	"js/realtime-shim-settings.js",
	"js/realtime-shim-notes.js",
	"js/realtime-shim-files.js",
	"js/realtime-shim-smb.js",
	"js/realtime-shim-transfer.js",
	"js/realtime-shim-commands.js",
	"js/realtime-shim-insights.js",
	"js/realtime-shim-terminal-tools.js",
	"js/realtime-catalog.js",
	"js/realtime-terminal.js",
	"js/realtime-shim.js",
}

func TestWorkspaceLoadsRealtimeClientInOrder(t *testing.T) {
	r := testRenderer(t)
	for _, c := range loadCases(t) {
		if c.Page != PageWorkspace {
			continue
		}
		order := assetOrder(renderCase(t, r, c))
		start := slices.Index(order, realtimeClient[0])
		if start < 0 || len(order) < start+len(realtimeClient) || !slices.Equal(order[start:start+len(realtimeClient)], realtimeClient) {
			t.Errorf("%s: realtime client not loaded as %v", c.Name, realtimeClient)
			continue
		}
		for _, later := range []string{"js/socket-protocol.js", "js/app.js"} {
			if i := slices.Index(order, later); i < start {
				t.Errorf("%s: %s must load after the realtime client", c.Name, later)
			}
		}
	}
}
