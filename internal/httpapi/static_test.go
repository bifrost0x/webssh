package httpapi

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStaticCachePolicy(t *testing.T) {
	e := newEdge(t)
	v, ok := testAssets(t).Version("css/style.css")
	if !ok {
		t.Fatal("css/style.css is not staged")
	}
	cases := map[string]string{
		"/static/css/style.css?v=" + v:             cacheImmutable,
		"/static/css/style.css":                    cacheRevalidate,
		"/static/css/style.css?v=0000000000000000": cacheNoStore,
		"/static/css/style.css?v=" + v + "&x=1":    cacheNoStore,
	}
	for target, want := range cases {
		w := e.do(req{target: target})
		if w.Code != 200 || w.Header().Get("Cache-Control") != want {
			t.Errorf("%s: %d Cache-Control %q, want %q", target, w.Code, w.Header().Get("Cache-Control"), want)
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", target, ct)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("%s sets a cookie", target)
		}
	}
	if e.sessions.calls.Load() != 0 {
		t.Fatal("static files looked up the session")
	}
}

func TestStaticGzipAndConditional(t *testing.T) {
	e := newEdge(t)
	plain := e.do(req{target: "/static/js/app.js"})
	if plain.Code != 200 || plain.Header().Get("Content-Encoding") != "" || !strings.Contains(plain.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("plain: %d %v", plain.Code, plain.Header())
	}
	gz := e.do(req{target: "/static/js/app.js", headers: map[string]string{"Accept-Encoding": "gzip, deflate"}})
	if gz.Header().Get("Content-Encoding") != "gzip" || gz.Header().Get("ETag") == plain.Header().Get("ETag") {
		t.Fatalf("gzip: %v", gz.Header())
	}
	zr, err := gzip.NewReader(gz.Body)
	if err != nil {
		t.Fatal(err)
	}
	unpacked, _ := io.ReadAll(zr)
	if !bytes.Equal(unpacked, plain.Body.Bytes()) {
		t.Fatal("gzip body differs from the file")
	}
	for name, etag := range map[string]string{"plain": plain.Header().Get("ETag"), "gzip": gz.Header().Get("ETag")} {
		headers := map[string]string{"If-None-Match": etag}
		if name == "gzip" {
			headers["Accept-Encoding"] = "gzip"
		}
		if w := e.do(req{target: "/static/js/app.js", headers: headers}); w.Code != http.StatusNotModified {
			t.Errorf("%s revalidation: %d", name, w.Code)
		}
	}
	// A range request is served uncompressed.
	w := e.do(req{target: "/static/js/app.js", headers: map[string]string{"Accept-Encoding": "gzip", "Range": "bytes=0-9"}})
	if w.Code != http.StatusPartialContent || w.Body.Len() != 10 || w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("range: %d %d %v", w.Code, w.Body.Len(), w.Header())
	}
	// Images are not compressed.
	if w := e.do(req{target: "/static/images/webssh-logo.svg", headers: map[string]string{"Accept-Encoding": "gzip"}}); w.Code != 200 {
		t.Fatalf("svg: %d", w.Code)
	}
}

func TestStaticRefusesUnknownPaths(t *testing.T) {
	e := newEdge(t)
	for _, target := range []string{"/static/missing.js", "/static/../go.mod", "/static/%2e%2e/go.mod", "/static/", "/static/js"} {
		w := e.do(req{target: target})
		if w.Code == http.StatusOK {
			t.Errorf("%s served", target)
		}
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"": false, "gzip": true, "deflate": false, "gzip;q=0": false, "*": true, "*;q=0": false,
		"identity;q=1, gzip;q=0.5": false, "gzip;q=0.5, identity;q=0.5": true, "br, gzip;q=0.8": true, "x-gzip": true,
	} {
		if acceptsGzip(header) != want {
			t.Errorf("acceptsGzip(%q) = %v", header, !want)
		}
	}
}
