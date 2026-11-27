package hosts

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// The corpus is recorded from app/profile_exchange.py and its routes by
// testdata/exchange_oracle.py.
type exchangeCorpus struct {
	Previews []struct {
		Name    string         `json:"name"`
		Request jsontext.Value `json:"request"`
		Raw     *string        `json:"raw"`
		Status  int            `json:"status"`
		Body    jsontext.Value `json:"body"`
	} `json:"previews"`
	Imports []struct {
		Name     string           `json:"name"`
		Request  jsontext.Value   `json:"request"`
		Answers  []string         `json:"answers"`
		Status   int              `json:"status"`
		Body     jsontext.Value   `json:"body"`
		Payloads []jsontext.Value `json:"payloads"`
	} `json:"imports"`
	Exports []struct {
		Name      string           `json:"name"`
		Profiles  []jsontext.Value `json:"profiles"`
		JumpHosts []jsontext.Value `json:"jump_hosts"`
		Omitted   string           `json:"omitted"`
		Body      *string          `json:"body"`
		Entries   []struct {
			Name     string `json:"name"`
			Compress int    `json:"compress_type"`
			Data     string `json:"data"`
		} `json:"entries"`
	} `json:"exports"`
}

// Deliberate deviations: Go refuses JSON that Python's json module reads
// although no valid host document can contain it. NaN is not JSON, and
// nesting beyond pyjson.MaxDepth is refused before it is examined.
var exchangeDeviations = map[string]string{
	"json-nan-port": "Invalid JSON document.",
	"json-deep":     "Invalid JSON document.",
}

func readExchangeCorpus(t *testing.T) exchangeCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/exchange_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var c exchangeCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// selectorVariants checks gateway selectors with the rules of
// parse_selector; the real check lives in internal/ssh/gateway.
type selectorVariants struct{}

func (selectorVariants) GatewayEnabled(context.Context) error { return nil }
func (selectorVariants) GatewaySelector(u string) error {
	user, target, ok := strings.Cut(u, ":")
	if !ok || strings.HasPrefix(u, "ticket-") || strings.Contains(u, "#") || user == "" || target == "" ||
		user != strings.TrimSpace(user) || target != strings.TrimSpace(target) {
		return errors.New("invalid selector")
	}
	return nil
}
func (selectorVariants) TailscaleAccess(context.Context, string, int, string) error { return nil }

type fixedKeys []KeyRef

func (f fixedKeys) UsableKeys(context.Context, int64) ([]KeyRef, error) { return f, nil }

func exchangeFixture(t *testing.T) (*ExchangeHTTP, *http.ServeMux) {
	t.Helper()
	s := &Service{DB: storetest.Open(t, Schema()), Variants: selectorVariants{}, Limits: DefaultLimits}
	legacy := Legacy{JumpHosts: []jsontext.Value{v(`{"id":"jump-1","name":"bastion","host":"bastion.test","port":22,"username":"u","auth_type":"password","created_at":"x"}`)}}
	if err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, 3, legacy, DefaultLimits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h := &ExchangeHTTP{Service: s, Keys: fixedKeys{{ID: "key-1", Name: "Laptop"}, {ID: "key-3", Name: "Ü-Key"}}}
	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux
}

func call(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := principal.With(t.Context(), principal.Principal{UserID: 3, SessionID: "s", Username: "u"})
	req := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// semantic decodes JSON for a comparison that ignores member order.
func semantic(t *testing.T, raw []byte) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return out
}

func TestExchangePreviewMatchesPython(t *testing.T) {
	_, mux := exchangeFixture(t)
	for _, c := range readExchangeCorpus(t).Previews {
		t.Run(c.Name, func(t *testing.T) {
			body := string(c.Request)
			if c.Raw != nil {
				body = *c.Raw
			}
			rec := call(t, mux, "POST", "/api/profiles/exchange/preview", body)
			if want, deviates := exchangeDeviations[c.Name]; deviates {
				if rec.Code != 400 || !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("deviation: %d %s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != c.Status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.Status, rec.Body.String())
			}
			got, want := semantic(t, rec.Body.Bytes()), semantic(t, c.Body)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got  %s\nwant %s", rec.Body.String(), c.Body)
			}
		})
	}
}

func TestExchangeImportMatchesPython(t *testing.T) {
	h, mux := exchangeFixture(t)
	for _, c := range readExchangeCorpus(t).Imports {
		t.Run(c.Name, func(t *testing.T) {
			answers := append([]string(nil), c.Answers...)
			var payloads []payload
			h.importProfile = func(_ context.Context, _ int64, req protocol.HostsProfileSave) ImportOutcome {
				payloads = append(payloads, profilePayload(req))
				answer := "ok"
				if len(answers) > 0 {
					answer, answers = answers[0], answers[1:]
				}
				switch answer {
				case "ok":
					return ImportOutcome{ID: "new-" + strconv.Itoa(len(payloads))}
				case "Duplicate profile":
					return ImportOutcome{Duplicate: true}
				case "quota":
					return ImportOutcome{Err: fault.New(fault.QuotaExceeded, "Connection storage quota exceeded.")}
				}
				return ImportOutcome{Err: fault.New(fault.ValidationError, answer)}
			}
			rec := call(t, mux, "POST", "/api/profiles/exchange", string(c.Request))
			if rec.Code != c.Status || !reflect.DeepEqual(semantic(t, rec.Body.Bytes()), semantic(t, c.Body)) {
				t.Fatalf("got %d %s\nwant %d %s", rec.Code, rec.Body.String(), c.Status, c.Body)
			}
			if len(payloads) != len(c.Payloads) {
				t.Fatalf("%d saves, want %d", len(payloads), len(c.Payloads))
			}
			for i, p := range payloads {
				got, _ := json.Marshal(map[string]jsontext.Value(p))
				if !reflect.DeepEqual(semantic(t, got), semantic(t, c.Payloads[i])) {
					t.Fatalf("payload %d: got %s\nwant %s", i, got, c.Payloads[i])
				}
			}
		})
	}
}

func TestExchangeExportMatchesPython(t *testing.T) {
	for _, c := range readExchangeCorpus(t).Exports {
		t.Run(c.Name, func(t *testing.T) {
			parse := func(values []jsontext.Value) []record {
				out := make([]record, len(values))
				for i, raw := range values {
					r, err := parseRecord(raw)
					if err != nil {
						t.Fatal(err)
					}
					out[i] = r
				}
				return out
			}
			batches := exportBatches(parse(c.Profiles), parse(c.JumpHosts))
			omitted := 0
			for _, b := range batches {
				for _, row := range b {
					if v, _ := row.get("socks_route_omitted"); truthy(v) {
						omitted++
					}
				}
			}
			if strconv.Itoa(omitted) != c.Omitted {
				t.Fatalf("omitted %d, want %s", omitted, c.Omitted)
			}
			if c.Body != nil {
				if len(batches) != 1 {
					t.Fatalf("%d batches for a single document", len(batches))
				}
				if got := string(flaskJSON(exchangeDocument(batches[0]).encode())) + "\n"; got != *c.Body {
					t.Fatalf("document differs:\ngot  %s\nwant %s", got, *c.Body)
				}
				return
			}
			archive, err := exportArchive(batches, testNow)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
			if err != nil {
				t.Fatal(err)
			}
			if len(zr.File) != len(c.Entries) {
				t.Fatalf("%d entries, want %d", len(zr.File), len(c.Entries))
			}
			for i, f := range zr.File {
				want := c.Entries[i]
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				_, err = got.ReadFrom(rc)
				_ = rc.Close()
				data, _ := base64.StdEncoding.DecodeString(want.Data)
				if err != nil || f.Name != want.Name || int(f.Method) != want.Compress || !bytes.Equal(got.Bytes(), data) {
					t.Fatalf("entry %d %s (method %d) differs from %s:\ngot  %.200s\nwant %.200s", i, f.Name, f.Method, want.Name, got.Bytes(), data)
				}
			}
		})
	}
}

var testNow = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
