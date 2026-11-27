package transfer

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/bifrost0x/webssh/internal/principal"
)

// started redeems the token of the request for its route. Without a
// match it answers 404 without a body and returns nil.
func (m *Manager) started(w http.ResponseWriter, r *http.Request, dir Direction, archive bool) (*record, principal.Principal, *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		notFound(w)
		return nil, p, r
	}
	rec, ctx := m.consume(r.Context(), r.PathValue("token"), p, dir, archive)
	if rec == nil {
		notFound(w)
		return nil, p, r
	}
	return rec, p, r.WithContext(ctx)
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
}

// writeFailure answers f as JSON with its status (_json_failure).
func writeFailure(w http.ResponseWriter, f Failure) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(f.Code.HTTPStatus())
	_ = json.MarshalWrite(w, f.body())
}

// attachment sets the headers of a download.
func attachment(w http.ResponseWriter, name, mime string) {
	h := w.Header()
	h.Set("Content-Type", mime)
	h.Set("Content-Disposition", contentDisposition(name))
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Accept-Ranges", "none")
}

// contentDisposition is an attachment with an ASCII fallback name and the
// UTF-8 name (_content_disposition): non-ASCII dropped, controls removed,
// other characters outside [A-Za-z0-9._ -] replaced by "_". Python
// decomposed the name first (NFKD), which kept the base letter of an
// accented one; browsers use the UTF-8 name, so the fallback only drops
// such letters here.
func contentDisposition(name string) string {
	original := name[strings.LastIndexByte(name, '/')+1:]
	if original == "" {
		original = "download"
	}
	var b strings.Builder
	for _, c := range original {
		switch {
		case c > unicode.MaxASCII:
		case c < 32 || c == 127:
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', strings.ContainsRune("._ -", c):
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	ascii := b.String()
	if ascii == "" {
		ascii = "download"
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + pathEscape(original)
}

// pathEscape is urllib.parse.quote(s, safe=""): everything but
// [A-Za-z0-9_.~-] is percent-encoded.
func pathEscape(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("_.~-", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// conn extends the deadlines of a long transfer one chunk at a time; the
// edge sets fixed deadlines for ordinary requests.
type conn struct {
	rc   *http.ResponseController
	idle time.Duration
	now  func() time.Time
}

func (m *Manager) conn(w http.ResponseWriter) *conn {
	return &conn{rc: http.NewResponseController(w), idle: m.o.IdleTimeout, now: time.Now}
}

func (c *conn) beforeWrite() { _ = c.rc.SetWriteDeadline(c.now().Add(c.idle)) }
func (c *conn) beforeRead()  { _ = c.rc.SetReadDeadline(c.now().Add(c.idle)) }
