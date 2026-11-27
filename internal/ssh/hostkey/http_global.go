package hostkey

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// maxGlobalBody bounds the body of an add request: one entry of at most
// 16 KiB, escaped (the edge refuses more than 64 KiB before this).
const maxGlobalBody = 64 << 10

// Auditor records security events in the audit log (provided by
// internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// GlobalHTTP serves the global trust store to administrators
// (/admin/api/host-keys). The edge mounts it as an admin route: a signed-in
// administrator without a recovery session, 404 while the admin panel is
// off. Adding and deleting need a step-up grant (host_key.global_add with
// target "global", host_key.global_delete with the entry id).
type GlobalHTTP struct {
	Store  *Store
	StepUp StepUp
	Audit  Auditor
	// Enabled is HOST_KEY_MANAGEMENT_ENABLED; off answers 404 everywhere.
	Enabled bool
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *GlobalHTTP) Register(mux *http.ServeMux) {
	inner := &HTTP{Enabled: h.Enabled, Logger: h.Logger}
	mux.HandleFunc("GET /admin/api/host-keys", inner.serve(adminOnly(h.list)))
	mux.HandleFunc("POST /admin/api/host-keys", inner.serveStatus(http.StatusCreated, adminOnly(h.add)))
	mux.HandleFunc("DELETE /admin/api/host-keys/{id}", inner.serve(adminOnly(h.delete)))
}

var errNotAdmin = fault.New(fault.Forbidden, "")

// adminOnly repeats the edge's admin check: the global store changes the
// trust of every user, so a routing mistake must not open it.
func adminOnly(fn handler) handler {
	return func(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
		if !p.IsAdmin || p.Recovery {
			return nil, errNotAdmin
		}
		return fn(ctx, p, r)
	}
}

func globalJSON(e GlobalEntry) entryJSON {
	j := entryJSON{
		ID: e.ID, Algorithm: e.Algorithm, Fingerprint: e.Fingerprint, Scope: string(ScopeGlobal),
		FirstSeen: pythonISOTime(e.Modified), LastSeen: pythonISOTime(e.Modified),
		Hosts: make([]hostJSON, 0, len(e.Hosts)),
	}
	if e.Marker != MarkerNone {
		m := string(e.Marker)
		j.Marker = &m
	}
	for _, ref := range e.Hosts {
		j.Hosts = append(j.Hosts, hostJSON{Host: ref.Host, Port: portJSON(ref.Port)})
	}
	j.Host, j.Port = j.Hosts[0].Host, j.Hosts[0].Port
	return j
}

func (h *GlobalHTTP) list(ctx context.Context, _ principal.Principal, _ *http.Request) (any, error) {
	entries, err := h.Store.GlobalList(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]entryJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, globalJSON(e))
	}
	return map[string]any{"entries": out}, nil
}

var errInvalidRequest = fault.New(fault.InvalidRequest, "Invalid request")

// readEntry decodes {"entry": …}. A body that is not a JSON object is an
// invalid request; an entry that is not text fails like Python's
// isinstance check.
func readEntry(r *http.Request) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxGlobalBody+1))
	if err != nil || len(raw) > maxGlobalBody {
		return "", errInvalidRequest
	}
	var body map[string]jsontext.Value
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return "", errInvalidRequest
	}
	var entry string
	if v, ok := body["entry"]; !ok || v.Kind() != '"' || json.Unmarshal(v, &entry) != nil {
		return "", errEntryNotText
	}
	return entry, nil
}

// add checks the entry before the grant is spent, so a typo does not cost
// a new confirmation.
func (h *GlobalHTTP) add(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	value, err := readEntry(r)
	if err != nil {
		return nil, err
	}
	if _, _, err := canonicalEntry(value); err != nil {
		return nil, err
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionHostKeyGlobalAdd, "global", r.Header.Get(StepUpHeader)); err != nil {
		return nil, err
	}
	entry, err := h.Store.GlobalAdd(ctx, value)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entry.Hosts))
	for i, ref := range entry.Hosts {
		names[i] = ref.Host
	}
	hosts := strings.Join(names, ",")
	marker := any(nil)
	if entry.Marker != MarkerNone {
		marker = string(entry.Marker)
	}
	h.audit("GLOBAL_SSH_HOST_KEY_ADDED", "admin", p.Username, "hosts", hosts, "algorithm", entry.Algorithm,
		"fingerprint", entry.Fingerprint, "marker", marker)
	return map[string]any{"entry": globalJSON(entry)}, nil
}

func (h *GlobalHTTP) delete(ctx context.Context, p principal.Principal, r *http.Request) (any, error) {
	id := r.PathValue("id")
	found, err := h.Store.GlobalHas(ctx, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errEntryNotFound
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionHostKeyGlobalDelete, id, r.Header.Get(StepUpHeader)); err != nil {
		return nil, err
	}
	if err := h.Store.GlobalDelete(ctx, id); err != nil {
		return nil, err
	}
	h.audit("GLOBAL_SSH_HOST_KEY_DELETED", "admin", p.Username, "entry_id", id)
	return map[string]any{"ok": true}, nil
}

func (h *GlobalHTTP) audit(event string, kv ...any) {
	if h.Audit != nil {
		h.Audit.Security(event, kv...)
		return
	}
	h.logger().Info(event, kv...)
}

func (h *GlobalHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}
