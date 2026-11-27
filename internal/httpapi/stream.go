package httpapi

import "fmt"

// StreamBody marks a registered route whose request body the handler
// reads itself, such as the upload of a backup archive (up to
// BACKUP_UPLOAD_MAX_SIZE): the edge does not buffer it, checks the
// session and access level before any byte of the body is read, and
// accepts the CSRF token only from the X-CSRFToken header. The handler
// bounds the body and sets its own read deadline. Call it before Finish.
func (h *Handler) StreamBody(pattern string) error {
	if !h.registered(pattern) {
		return fmt.Errorf("httpapi: stream body: %s is not registered", pattern)
	}
	if h.streamed == nil {
		h.streamed = map[string]bool{}
	}
	h.streamed[patternKey(pattern)] = true
	return nil
}
