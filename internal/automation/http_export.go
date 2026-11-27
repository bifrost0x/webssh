package automation

import (
	"net/http"
)

func (h *HTTP) export(w http.ResponseWriter, r *http.Request) {
	p, err := h.gate(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	format := r.URL.Query().Get("format")
	if !r.URL.Query().Has("format") {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.fail(w, r, Fail("invalid_request"))
		return
	}
	run, err := h.Service.Run(r.Context(), p.UserID, r.PathValue("run_id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body, mime := ExportJSON(run), "application/json"
	if format == "csv" {
		body, mime = ExportCSV(run), "text/csv; charset=utf-8"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename="workflow-run.`+format+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
