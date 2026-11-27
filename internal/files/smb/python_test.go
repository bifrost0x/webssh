package smb

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// testdata/python_vectors.json is produced by testdata/python_vectors.py
// from the unchanged Python modules; see the script for the command.

type pyOutcome struct {
	In    jsontext.Value `json:"in"`
	OK    bool           `json:"ok"`
	Value jsontext.Value `json:"value"`
	Code  *string        `json:"code"`
}

type pyFields struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Share    string `json:"share"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
}

type pyVectors struct {
	ShareNames   []pyOutcome `json:"share_names"`
	Paths        []pyOutcome `json:"paths"`
	SecretFields []struct {
		In     string `json:"in"`
		Secret bool   `json:"secret"`
	} `json:"secret_fields"`
	Payloads []struct {
		In        jsontext.Value `json:"in"`
		Validated *pyFields      `json:"validated"`
		Error     *string        `json:"error"`
	} `json:"payloads"`
	Records []struct {
		In    jsontext.Value `json:"in"`
		Valid bool           `json:"valid"`
	} `json:"records"`
	Connect  []pyOutcome `json:"connect"`
	Statuses []struct {
		Status   uint32  `json:"status"`
		Code     *string `json:"code"`
		NtStatus string  `json:"nt_status"`
	} `json:"statuses"`
	Allowlist []struct {
		Host    string   `json:"host"`
		Allowed []string `json:"allowed"`
		OK      bool     `json:"ok"`
		Value   string   `json:"value"`
	} `json:"allowlist"`
	Times []struct {
		UnixNS int64  `json:"unix_ns"`
		ISO    string `json:"iso"`
	} `json:"times"`
}

func loadVectors(t *testing.T) pyVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v pyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func text(t *testing.T, v jsontext.Value) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPythonPathRules(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.ShareNames {
		in := text(t, c.In)
		if got := ValidShareName(in); got != c.OK {
			t.Errorf("share %q: %v, Python %v", in, got, c.OK)
		}
	}
	for _, c := range v.Paths {
		in := text(t, c.In)
		parts, err := splitPath(in)
		if (err == nil) != c.OK {
			t.Errorf("path %q: err %v, Python ok %v", in, err, c.OK)
			continue
		}
		if c.OK {
			var want []string
			if err := json.Unmarshal(c.Value, &want); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(parts, want) && !(len(parts) == 0 && len(want) == 0) {
				t.Errorf("path %q: %q, Python %q", in, parts, want)
			}
		}
	}
}

// TestPythonConnectInput: the input rules of create_source, with one
// change: a name or password Python refused only when both were empty is
// refused on its own as well (the vectors already refuse each alone).
func TestPythonConnectInput(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Connect {
		var in struct {
			Host, Share, Username string
			Domain, Password      *string
		}
		if err := json.Unmarshal(c.In, &in, json.MatchCaseInsensitiveNames(true)); err != nil {
			// A null user name is refused by the decoder of the page's
			// request already; Python refuses it too.
			if c.OK {
				t.Errorf("%s: undecodable but accepted by Python", c.In)
			}
			continue
		}
		tg := Target{Host: in.Host, Share: in.Share, Username: in.Username}
		if in.Domain != nil {
			tg.Domain = *in.Domain
		}
		if in.Password == nil {
			if c.OK {
				t.Errorf("%s: no password but accepted", c.In)
			}
			continue
		}
		tg.Password = []byte(*in.Password)
		err := checkTarget(tg)
		if (err == nil) != c.OK {
			t.Errorf("%s: err %v, Python ok %v", c.In, err, c.OK)
		}
		if err != nil && fault.CodeOf(err) != fault.InvalidRequest {
			t.Errorf("%s: code %v", c.In, fault.CodeOf(err))
		}
	}
}

func TestPythonStatusMapping(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Statuses {
		got := StatusCode(c.Status)
		want := fault.OperationFailed
		if c.Code != nil {
			want = fault.Code(*c.Code)
		}
		if _, extra := extraStatusCodes[c.Status]; extra {
			if want != fault.OperationFailed {
				t.Errorf("0x%08X: listed as extra but Python maps it to %s", c.Status, want)
			}
			continue
		}
		if got != want {
			t.Errorf("0x%08X: %s, Python %s", c.Status, got, want)
		}
	}
	for _, c := range v.Statuses {
		err := classify(&protocol.ResponseError{Code: c.Status}, PhaseShareAccess)
		if d := DiagnosticOf(err); d.NtStatus != c.NtStatus || d.Phase != PhaseShareAccess || fault.CodeOf(err) != StatusCode(c.Status) {
			t.Errorf("0x%08X: diagnostic %+v, Python %s", c.Status, d, c.NtStatus)
		}
	}
}

// TestPythonAllowlist: SMB_ALLOWED_TARGETS compares exact canonical
// hosts as parse_smb_allowed_targets does. The address classes are those
// of the shared network policy (ADR 0010), not part of these vectors.
func TestPythonAllowlist(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Allowlist {
		var allowed []string
		for _, a := range c.Allowed {
			if h, err := netpolicy.CanonicalHost(a); err == nil {
				allowed = append(allowed, h)
			}
		}
		n := &countingNetwork{}
		cfg := Config{Network: n, AllowedTargets: allowed, ConnectTimeout: time.Second, IOIdleTimeout: time.Second,
			Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errTest }}
		_, err := Connect(t.Context(), cfg, Target{Host: c.Host, Share: "Data", Username: "u", Password: []byte("p")})
		refused := fault.CodeOf(err) == fault.SMBTargetNotAllowed
		if refused == c.OK {
			t.Errorf("host %q in %v: refused %v, Python ok %v (%v)", c.Host, c.Allowed, refused, c.OK, err)
		}
		if c.OK && n.host != c.Value {
			t.Errorf("host %q: admitted %q, Python %q", c.Host, n.host, c.Value)
		}
	}
}

// countingNetwork admits everything to 127.0.0.1 and records the host.
type countingNetwork struct {
	host  string
	port  int
	role  netpolicy.Role
	calls int
}

func (n *countingNetwork) Admit(_ context.Context, role netpolicy.Role, host string, port int) (netpolicy.Admitted, error) {
	n.calls++
	n.host, n.port, n.role = host, port, role
	return netpolicy.Admitted{Host: host, Addr: mustAddrPort("127.0.0.1", port)}, nil
}
