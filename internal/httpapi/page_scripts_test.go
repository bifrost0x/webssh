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

func TestPreviewNoticeAssets(t *testing.T) {
	r := testRenderer(t)
	for _, c := range loadCases(t) {
		order := assetOrder(renderCase(t, r, c))
		notice := slices.Index(order, "js/preview-notice.js")
		css := slices.Contains(order, "css/preview-notice.css")
		i18nNotice := slices.Index(order, "js/preview-notice-i18n.js")
		switch c.Name {
		case "workspace_preview", "settings_preview":
			if notice < 0 || !css || i18nNotice < 0 || i18nNotice > notice || i18nNotice < slices.Index(order, "js/i18n.js") {
				t.Errorf("%s: want css, i18n.js, preview-notice-i18n.js, preview-notice.js; got %v", c.Name, order)
			}
		case "login_preview":
			// The sign-in page has no i18n.js; the notice uses its
			// built-in English texts there.
			if notice < 0 || !css || i18nNotice >= 0 {
				t.Errorf("%s: want css and preview-notice.js without translations; got %v", c.Name, order)
			}
		default:
			if notice >= 0 || css || i18nNotice >= 0 {
				t.Errorf("%s: preview assets outside a preview", c.Name)
			}
		}
	}
}
