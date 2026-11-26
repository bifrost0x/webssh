package httpapi

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"slices"
)

//go:embed pages/*.gohtml
var pageTemplates embed.FS

// Page names a server-rendered page.
type Page string

// The pages of the browser interface.
const (
	PageLogin          Page = "login"
	PageRegister       Page = "register"
	PageChangePassword Page = "change_password"
	PageSettings       Page = "security"
	PageWorkspace      Page = "index"
	PageError          Page = "error"
)

// Pages lists every page, for checks that render all of them.
var Pages = []Page{PageLogin, PageRegister, PageChangePassword, PageSettings, PageWorkspace, PageError}

// Renderer renders the pages. It is safe for concurrent use.
type Renderer struct {
	templates *template.Template
	assets    *Assets
}

// NewRenderer parses the page templates and checks that every page
// renders with the given assets, so that a missing asset or a broken
// template stops the start instead of failing the first request.
func NewRenderer(assets *Assets) (*Renderer, error) {
	t, err := template.New("pages").Funcs(pageFuncs).ParseFS(pageTemplates, "pages/*.gohtml")
	if err != nil {
		return nil, fmt.Errorf("parse page templates: %w", err)
	}
	r := &Renderer{templates: t, assets: assets}
	for _, p := range Pages {
		if err := r.Render(io.Discard, p, PageData{}); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Render writes one page. The page is rendered into a buffer first, so a
// failure never leaves a half-written page.
func (r *Renderer) Render(w io.Writer, page Page, data PageData) error {
	if !slices.Contains(Pages, page) {
		return fmt.Errorf("render page %q: unknown page", page)
	}
	if err := data.checkJSONBlocks(); err != nil {
		return fmt.Errorf("render page %q: %w", page, err)
	}
	var buf bytes.Buffer
	if err := r.templates.ExecuteTemplate(&buf, string(page), view{PageData: &data, assets: r.assets}); err != nil {
		return fmt.Errorf("render page %q: %w", page, err)
	}
	_, err := buf.WriteTo(w)
	return err
}

// checkJSONBlocks encodes the values that the pages embed as JSON script
// blocks. html/template replaces a value it cannot encode with a comment
// and null; a page must instead fail to render, so that the browser never
// sees a silently emptied inventory or layout.
func (d *PageData) checkJSONBlocks() error {
	if d.InitialInventory != nil {
		if _, err := json.Marshal(d.InitialInventory); err != nil {
			return fmt.Errorf("initial inventory: %w", err)
		}
	}
	if d.OverviewPreferences != nil {
		if _, err := json.Marshal(d.OverviewPreferences); err != nil {
			return fmt.Errorf("overview preferences: %w", err)
		}
	}
	return nil
}
