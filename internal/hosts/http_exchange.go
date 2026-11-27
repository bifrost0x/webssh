package hosts

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// maxExchangeBody is the body limit of request_limits.py for the preview
// and import routes.
const maxExchangeBody = 512 << 10

// KeyRef names one usable SSH key of a user for the import mapping.
type KeyRef struct{ ID, Name string }

// UsableKeys lists the SSH keys of a user that WebSSH can load (provided
// by internal/vault).
type UsableKeys interface {
	UsableKeys(ctx context.Context, owner int64) ([]KeyRef, error)
}

// ExchangeHTTP serves the host import and export
// (/api/profiles/exchange): a preview that stores nothing, an import of
// explicitly selected and mapped hosts, and an export of host metadata
// without secrets. The edge mounts it behind session, CSRF and origin
// checks.
type ExchangeHTTP struct {
	Service *Service
	Keys    UsableKeys
	// Limited reports that the user or source is over the preview limit
	// (RATELIMIT_SSH_KEY_LIST): the preview lists the usable keys, which
	// opens every stored key.
	Limited func(r *http.Request, userID int64) bool
	Logger  *slog.Logger
	// importProfile replaces Service.ImportProfile in tests.
	importProfile func(ctx context.Context, owner int64, req protocol.HostsProfileSave) ImportOutcome
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *ExchangeHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/profiles/exchange/preview", h.preview)
	mux.HandleFunc("POST /api/profiles/exchange", h.importHosts)
	mux.HandleFunc("GET /api/profiles/exchange", h.export)
}

// publicErrors are the texts the route shows; every other refusal is
// shown as genericImportError, so no internal text leaks.
var publicErrors = map[string]bool{
	knownHostsMessage: true, "Invalid import request.": true, "Import supports at most 100 hosts.": true,
	"Import must contain text.": true, "Import must contain valid UTF-8.": true, "Import exceeds 64 KiB.": true,
	"Unsupported import format.": true, "Invalid JSON document.": true, "Unsupported host exchange document.": true,
	"Host document contains unsupported fields.": true, "Choose up to 100 hosts.": true, "Invalid host selection.": true,
	"Unsupported configuration cannot be imported.": true, "Invalid host mapping.": true,
}

const genericImportError = "Invalid import document. Check its format and syntax."

var errInvalidImportRequest = exchangeError("Invalid import request.")

func publicError(err error) string {
	_, _, message := fault.Status(err)
	if publicErrors[message] {
		return message
	}
	return genericImportError
}

func (h *ExchangeHTTP) refuse(w http.ResponseWriter, err error) {
	writeRaw(w, http.StatusBadRequest, flaskJSON(objectOf("error", jsonString(publicError(err)))))
}

// readRequest decodes the body like request.get_json(silent=True): a JSON
// media type and a JSON object, else an invalid request.
func readRequest(w http.ResponseWriter, r *http.Request) (jsontext.Value, pyjson.Report, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !hasJSONSuffix(mediaType)) {
		return nil, pyjson.Report{}, errInvalidImportRequest
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxExchangeBody))
	if err != nil {
		return nil, pyjson.Report{}, errInvalidImportRequest
	}
	body, rep, err := pyjson.Load(raw)
	if err != nil || body.Kind() != '{' {
		return nil, pyjson.Report{}, errInvalidImportRequest
	}
	return body, rep, nil
}

func sourceOf(body jsontext.Value, rep pyjson.Report) exchangeSource {
	source, _ := pyjson.Get(body, "source")
	format, _ := pyjson.Get(body, "format")
	// A Go string cannot hold an unpaired surrogate: the decoder replaced
	// it with U+FFFD, and Python refused such a source.
	lone := rep.LoneSurrogates && bytes.Contains(source, []byte("�"))
	return exchangeSource{Source: source, Format: format, LoneSurrogate: lone}
}

func (s *Service) selector() selectorCheck {
	if s.Variants == nil {
		return nil
	}
	return func(username string) bool { return s.Variants.GatewaySelector(username) == nil }
}

func (h *ExchangeHTTP) preview(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.Limited != nil && h.Limited(r, p.UserID) {
		writeRaw(w, http.StatusTooManyRequests, flaskJSON(objectOf("error", jsonString("Too many import previews. Please wait a moment."))))
		return
	}
	body, rep, err := readRequest(w, r)
	var preview Preview
	if err == nil {
		preview, err = previewImport(sourceOf(body, rep), h.Service.selector())
	}
	if err != nil {
		h.refuse(w, err)
		return
	}
	keys, err := h.usableKeys(r.Context(), p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	jumps, err := h.Service.JumpHosts(r.Context(), p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeRaw(w, http.StatusOK, flaskJSON(previewBody(preview, keys, jumps)))
}

func (h *ExchangeHTTP) usableKeys(ctx context.Context, owner int64) ([]KeyRef, error) {
	if h.Keys == nil {
		return nil, nil
	}
	return h.Keys.UsableKeys(ctx, owner)
}

func previewBody(p Preview, keys []KeyRef, jumps []jsontext.Value) jsontext.Value {
	keyItems := make([]jsontext.Value, 0, len(keys))
	for _, k := range keys {
		keyItems = append(keyItems, pyjson.Object([]pyjson.Member{{Name: "id", Value: jsonString(k.ID)}, {Name: "name", Value: jsonString(k.Name)}}))
	}
	jumpItems := make([]jsontext.Value, 0, len(jumps))
	for _, j := range jumps {
		id, _ := pyjson.Get(j, "id")
		name, _ := pyjson.Get(j, "name")
		jumpItems = append(jumpItems, pyjson.Object([]pyjson.Member{{Name: "id", Value: orNull(id)}, {Name: "name", Value: orNull(name)}}))
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "records", Value: pyjson.Array(p.Records)},
		{Name: "warnings", Value: stringArray(p.Warnings)},
		{Name: "keys", Value: pyjson.Array(keyItems)},
		{Name: "jump_hosts", Value: pyjson.Array(jumpItems)},
	})
}

func orNull(v jsontext.Value) jsontext.Value {
	if len(v) == 0 {
		return jsonNull
	}
	return v
}

func objectOf(name string, v jsontext.Value) jsontext.Value {
	return pyjson.Object([]pyjson.Member{{Name: name, Value: v}})
}

func (h *ExchangeHTTP) importHosts(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, rep, err := readRequest(w, r)
	var preview Preview
	var selections []importSelection
	if err == nil {
		preview, err = previewImport(sourceOf(body, rep), h.Service.selector())
	}
	if err == nil {
		raw, _ := pyjson.Get(body, "selections")
		selections, err = readSelections(raw, preview.rows)
	}
	if err != nil {
		h.refuse(w, err)
		return
	}
	results := make([]jsontext.Value, 0, len(selections))
	for _, sel := range selections {
		row := &preview.rows[sel.Index]
		members := []pyjson.Member{{Name: "index", Value: jsonInt(int64(sel.Index))}}
		var outcome ImportOutcome
		if missingMapping(row, sel) {
			outcome.Err = errMappingMissing
		} else {
			save := h.Service.ImportProfile
			if h.importProfile != nil {
				save = h.importProfile
			}
			outcome = save(r.Context(), p.UserID, importPayload(row, sel))
		}
		switch {
		case outcome.Err == nil && !outcome.Duplicate:
			members = append(members, pyjson.Member{Name: "status", Value: jsonString("imported")}, pyjson.Member{Name: "id", Value: jsonString(outcome.ID)})
		case outcome.Duplicate:
			members = append(members, pyjson.Member{Name: "status", Value: jsonString("skipped")}, pyjson.Member{Name: "error", Value: jsonString("Duplicate profile")})
		default:
			status, code, message := fault.Status(outcome.Err)
			if status >= http.StatusInternalServerError {
				h.logger().ErrorContext(r.Context(), "host import failed", "code", string(code), "error", outcome.Err)
			}
			members = append(members, pyjson.Member{Name: "status", Value: jsonString("error")}, pyjson.Member{Name: "error", Value: jsonString(message)})
		}
		results = append(results, pyjson.Object(members))
	}
	writeRaw(w, http.StatusOK, flaskJSON(objectOf("results", pyjson.Array(results))))
}

func (h *ExchangeHTTP) export(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	profiles, jumps, err := h.Service.exportRecords(r.Context(), p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	batches := exportBatches(profiles, jumps)
	omitted := 0
	for _, batch := range batches {
		for _, row := range batch {
			if v, _ := row.get("socks_route_omitted"); truthy(v) {
				omitted++
			}
		}
	}
	w.Header().Set("X-WebSSH-SOCKS-Routes-Omitted", strconv.Itoa(omitted))
	if len(batches) == 1 {
		writeRaw(w, http.StatusOK, flaskJSON(exchangeDocument(batches[0]).encode()))
		return
	}
	archive, err := exportArchive(batches, time.Now())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=webssh-hosts.zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive)
}

func (h *ExchangeHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := fault.Status(err)
	if code == fault.Internal || code == fault.StorageError {
		h.logger().ErrorContext(r.Context(), "host exchange request failed", "error", err)
	}
	writeJSON(w, status, errorBody{Success: false, Code: string(code), Error: message})
}

func (h *ExchangeHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n')) // Flask ends every JSON response with a newline
}
