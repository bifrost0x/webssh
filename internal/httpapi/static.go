package httpapi

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// staticTypes pins the media types of the bundled files, so they do not
// depend on the host's MIME database (the Python release pins webp and the
// fonts the same way). Files with another extension are served as
// application/octet-stream.
var staticTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".json":  "application/json",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".webp":  "image/webp",
	".ico":   "image/vnd.microsoft.icon",
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".txt":   "text/plain; charset=utf-8",
	".md":    "text/plain; charset=utf-8",
	".bash":  "text/plain; charset=utf-8",
	"":       "text/plain; charset=utf-8", // LICENSE files
}

// compressible are the types gzip helps, as in static_delivery.py.
var compressible = map[string]bool{".css": true, ".js": true, ".svg": true, ".ttf": true, ".otf": true}

// minCompressSize: smaller files are sent as they are.
const minCompressSize = 1024

// Cache policies of static_delivery.py.
const (
	cacheImmutable   = "public, max-age=31536000, immutable"
	cacheRevalidate  = "public, max-age=0, must-revalidate"
	cacheNoStore     = "no-store"
	maxGzipCacheSize = 16 << 20
)

// staticHandler serves the indexed files of static/. Requests name a file
// of the index exactly; no request value is joined to a file system path.
// Every file has a strong ETag from its content version; compressible
// files are gzipped once and kept, bounded by the size of the bundle.
type staticHandler struct {
	assets *Assets

	mu  sync.Mutex
	gz  map[string]*gzipped
	gzN int
}

type gzipped struct {
	once sync.Once
	data []byte // nil when gzip does not help
}

func newStatic(a *Assets) *staticHandler {
	return &staticHandler{assets: a, gz: map[string]*gzipped{}}
}

func (s *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	version, ok := s.assets.Version(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := s.assets.FS().Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "file cannot be served", http.StatusInternalServerError)
		return
	}
	ext := path.Ext(name)
	ctype, known := staticTypes[ext]
	if !known {
		ctype = "application/octet-stream"
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", cachePolicy(r, version))
	h.Del("Pragma")
	h.Add("Vary", "Accept-Encoding")

	if compressible[ext] && r.Header.Get("Range") == "" && acceptsGzip(r.Header.Get("Accept-Encoding")) {
		if data := s.gzipOf(name, rs); data != nil {
			h.Set("Content-Encoding", "gzip")
			h.Set("ETag", `"`+version+`-gzip"`)
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
			return
		}
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "file cannot be served", http.StatusInternalServerError)
			return
		}
	}
	h.Set("ETag", `"`+version+`"`)
	http.ServeContent(w, r, "", time.Time{}, rs)
}

// cachePolicy is the Cache-Control of static_delivery.py: a URL whose
// only query is the current ?v= is immutable, any other query is not
// stored, a plain URL is revalidated.
func cachePolicy(r *http.Request, version string) string {
	q := r.URL.Query()
	if len(q) == 1 && len(q["v"]) == 1 && q.Get("v") == version {
		return cacheImmutable
	}
	if r.URL.RawQuery != "" {
		return cacheNoStore
	}
	return cacheRevalidate
}

// gzipOf returns the gzip form of a file, computing it once. nil means
// the file is sent uncompressed (small, not smaller when compressed, or
// the cache is full).
func (s *staticHandler) gzipOf(name string, src io.Reader) []byte {
	s.mu.Lock()
	g, ok := s.gz[name]
	if !ok {
		g = &gzipped{}
		s.gz[name] = g
	}
	s.mu.Unlock()
	g.once.Do(func() {
		plain, err := io.ReadAll(src)
		if err != nil || len(plain) < minCompressSize {
			return
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, 6) // level 6 is valid
		if _, err := zw.Write(plain); err != nil || zw.Close() != nil || buf.Len() >= len(plain) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gzN+buf.Len() > maxGzipCacheSize {
			return
		}
		s.gzN += buf.Len()
		g.data = buf.Bytes()
	})
	return g.data
}

// acceptsGzip applies Werkzeug's best_match(("gzip", "identity")): gzip
// wins unless its quality is zero or identity's is higher.
func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	qGzip, qIdentity, qAny := -1.0, -1.0, -1.0
	for part := range strings.SplitSeq(header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			q = f
		}
		switch strings.ToLower(strings.TrimSpace(coding)) {
		case "gzip", "x-gzip":
			qGzip = q
		case "identity":
			qIdentity = q
		case "*":
			qAny = q
		}
	}
	if qGzip < 0 {
		qGzip = qAny
	}
	if qIdentity < 0 {
		qIdentity = qAny
	}
	return qGzip > 0 && qGzip >= qIdentity
}
