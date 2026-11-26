package auth

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
)

// MaxBodyBytes bounds the JSON body of the factor and step-up routes. Their
// largest request is a WebAuthn assertion.
const MaxBodyBytes = 64 << 10

// Object is a decoded JSON request object.
type Object map[string]jsontext.Value

// ReadObject decodes the request body as a JSON object. Like the Python
// release it treats a missing or malformed body as an empty object; each
// route then rejects what it misses.
func ReadObject(w http.ResponseWriter, r *http.Request) Object {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		return Object{}
	}
	var obj Object
	if json.Unmarshal(body, &obj) != nil || obj == nil {
		return Object{}
	}
	return obj
}

// String returns a string member.
func (o Object) String(key string) (string, bool) {
	raw, ok := o[key]
	if !ok || raw.Kind() != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// True reports whether the member is the JSON literal true.
func (o Object) True(key string) bool {
	raw, ok := o[key]
	return ok && raw.Kind() == 't'
}

// WriteJSON sends body with status. Responses of these routes carry
// authentication material or factor state and are never cached.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, body)
}

type errorBody struct {
	Success    bool   `json:"success"`
	Code       string `json:"code"`
	Error      string `json:"error"`
	RetryAfter int64  `json:"retry_after,omitzero"`
}

// WriteError sends err in the shape the pages expect:
// {"success": false, "code", "error"}, plus "retry_after" (seconds) and the
// Retry-After header for rate_limited. Unclassified errors are logged and
// sent as internal.
func WriteError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "factor request failed", "path", r.URL.Path, "error", err)
	}
	body := errorBody{Code: string(code), Error: message}
	if code == fault.RateLimited {
		body.RetryAfter = retrySeconds(fault.RetryAfter(err).Seconds())
		w.Header().Set("Retry-After", strconv.FormatInt(body.RetryAfter, 10))
	}
	WriteJSON(w, status, body)
}

func retrySeconds(s float64) int64 {
	return max(1, int64(math.Ceil(s)))
}
