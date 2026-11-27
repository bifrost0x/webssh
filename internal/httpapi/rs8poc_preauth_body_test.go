package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type countingBody struct {
	n, size int
}

func (c *countingBody) Read(p []byte) (int, error) {
	if c.n >= c.size {
		return 0, io.EOF
	}
	k := min(len(p), c.size-c.n)
	for i := range k {
		p[i] = 'a'
	}
	c.n += k
	return k, nil
}

func (c *countingBody) Close() error { return nil }

// RS8-01: the edge buffers the body of an unsafe request before it looks at
// the session, so a client without a session makes the server hold up to
// the route's limit (1 MiB for the host context) per request.
func TestRS8PocBodyReadBeforeAuthentication(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("PUT /api/profiles/{id}/context", echo)
	body := &countingBody{size: hostContextRequestLimit}
	r := httptest.NewRequest(http.MethodPut, "/api/profiles/7/context", nil)
	r.Body = body
	r.ContentLength = int64(body.size)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	t.Logf("status %d, body bytes read without a session: %d", w.Code, body.n)
	if w.Code == http.StatusUnauthorized && body.n > 0 {
		t.Errorf("read %d body bytes of an unauthenticated request before answering 401", body.n)
	}
}
