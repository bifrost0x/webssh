package main

import "github.com/bifrost0x/webssh/internal/httpapi"

// The areas this preview does not offer. The page script hides their
// entry points and names them in the preview notice; the server answers
// their routes with not_available_in_preview (internal/httpapi) and the
// realtime shim answers their events locally. The identifiers are those of
// static/js/preview-notice.js. Every sign-in provider is built, so the
// pages before sign-in carry no notice.
var previewWorkspaceAreas = []string{
	"files", "smb", "automation", "credentials", "discovery", "commands",
	"herdr", "gateway", "tailscale", "serverOps",
}

const previewWorkspaceMessage = "Preview: some areas are not available yet."

// previewNotice describes the preview for a page; signIn selects the
// pages before sign-in, which need none.
func previewNotice(signIn bool) httpapi.PreviewNotice {
	if signIn {
		return httpapi.PreviewNotice{}
	}
	return httpapi.PreviewNotice{Enabled: true, Unavailable: previewWorkspaceAreas, Message: previewWorkspaceMessage}
}
