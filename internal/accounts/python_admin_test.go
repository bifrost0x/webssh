package accounts

import (
	json "encoding/json/v2"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// testdata/python_admin_vectors.json is produced by
// testdata/python_admin_vectors.py from the Flask application: every
// account action, the MFA reset and the recovery reset against plain,
// locked, administrator, LDAP-, GitHub- and ADMIN_USERS-managed targets.
// The Go handlers must give the same status, message and account state.

type pythonAdminVector struct {
	Name       string     `json:"name"`
	Accounts   [][]any    `json:"accounts"`
	AdminUsers []string   `json:"admin_users"`
	Method     string     `json:"method"`
	Target     string     `json:"target"`
	Path       string     `json:"path"`
	Body       any        `json:"body"`
	StepUp     []string   `json:"step_up"`
	Want       pythonWant `json:"want"`
}

type pythonState struct {
	IsAdmin    bool `json:"is_admin"`
	IsLocked   bool `json:"is_locked"`
	MFAEnabled bool `json:"mfa_enabled"`
}

type pythonWant struct {
	Status int             `json:"status"`
	Error  *string         `json:"error"`
	Codes  int             `json:"codes"`
	After  *pythonState    `json:"after"`
	User   map[string]bool `json:"user"`
}

func TestAdministrationMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_admin_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []pythonAdminVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 60 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			l := newLifecycle(t, v.AdminUsers...)
			l.s.Factors = &fakeFactors{}
			l.s.Recovery = &fakeRecovery{}
			ids := map[string]int64{}
			for i, a := range v.Accounts {
				id := int64(i + 1)
				name, _ := a[0].(string)
				admin, _ := a[1].(bool)
				locked, _ := a[2].(bool)
				managed, _ := a[3].(string)
				insertLegacy(t, l.s, id, name, admin, locked, Manager(managed), "2026-01-01T00:00:00")
				ids[name] = id
			}
			target, ok := ids[v.Target]
			if !ok {
				target = 99
			}
			step := &principaltest.StepUp{}
			actor := principaltest.Admin(ids["actor"])
			actor.Username = "actor"
			if v.StepUp != nil {
				step.Issue(actor, principal.Action(v.StepUp[0]), strings.ReplaceAll(v.StepUp[1], "{id}", strconv.FormatInt(target, 10)), "grant")
			}
			c := adminCase{h: &HTTP{Accounts: l.s, StepUp: step, Gates: fakeGates{"recovery": true}, Enabled: true}, step: step, l: l}
			body := ""
			if v.Body != nil {
				b, _ := json.Marshal(v.Body)
				body = string(b)
			}
			rec := c.do(t, &actor, strings.ToUpper(v.Method), strings.ReplaceAll(v.Path, "{id}", strconv.FormatInt(target, 10)), body, "grant")
			var got struct {
				Error *string        `json:"error"`
				Code  string         `json:"code"`
				Codes []string       `json:"codes"`
				User  map[string]any `json:"user"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body %q: %v", rec.Body, err)
			}
			if rec.Code != v.Want.Status {
				t.Errorf("status %d, Python %d (%s)", rec.Code, v.Want.Status, rec.Body)
			}
			wantErr := ""
			if v.Want.Error != nil {
				wantErr = *v.Want.Error
			}
			gotErr := ""
			if got.Error != nil {
				gotErr = *got.Error
			}
			if v.Want.Status == 403 {
				// The real step-up service answers with the Python text; the
				// test double sends the code's default text.
				if got.Code != string(fault.StepUpRequired) {
					t.Errorf("step-up refusal %s", rec.Body)
				}
			} else if gotErr != wantErr {
				t.Errorf("error %q, Python %q", gotErr, wantErr)
			}
			if len(got.Codes) != v.Want.Codes {
				t.Errorf("%d codes, Python %d", len(got.Codes), v.Want.Codes)
			}
			for k, want := range v.Want.User {
				if got.User[k] != want {
					t.Errorf("user.%s = %v, Python %v", k, got.User[k], want)
				}
			}
			acc, err := l.s.Get(t.Context(), target)
			switch {
			case v.Want.After == nil:
				if !fault.Is(err, fault.NotFound) {
					t.Errorf("account exists, Python removed it")
				}
			case err != nil:
				t.Errorf("account gone, Python kept it: %v", err)
			default:
				if acc.IsAdmin != v.Want.After.IsAdmin || acc.IsLocked != v.Want.After.IsLocked || acc.MFARequired != v.Want.After.MFAEnabled {
					t.Errorf("after %+v, Python %+v", acc, *v.Want.After)
				}
			}
		})
	}
}
