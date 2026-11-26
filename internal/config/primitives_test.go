package config

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

type primitiveCase struct {
	Fn     string `json:"fn"`
	Arg    string `json:"arg"`
	Result any    `json:"result"`
}

// goPrimitive evaluates fn like testdata/pyprobe.py does in Python. skip
// is true where Go knowingly answers differently.
func goPrimitive(fn, arg string) (result any, skip bool) {
	switch fn {
	case "int":
		if v, ok := pyInt(arg); ok {
			return v.String(), false
		}
		return nil, false
	case "strip":
		return pyStrip(arg), false
	case "lower":
		return pyLower(arg), false
	case "ip_address":
		if a, err := pyIPAddress(arg); err == nil {
			return a.String(), false
		}
		return nil, false
	case "ip_network":
		if n, err := pyIPNetwork(arg); err == nil {
			return n.String(), false
		}
		return nil, false
	case "repr":
		return pyRepr(arg), false
	case "path":
		return pyPath(arg), false
	case "urlsplit":
		u, err := pyURLSplit(arg)
		if err != nil {
			return nil, false
		}
		var port any = "error"
		if p, err := u.port(); err == nil {
			port = float64(p)
		}
		return []any{u.scheme, u.netloc, u.path, u.query, u.fragment, u.hostname(), u.hasCredentials(), port}, false
	case "tailscale":
		host, port, err := tailscaleTarget(arg)
		if err != nil {
			return nil, false
		}
		return []any{host, float64(port)}, false
	case "remote_dns":
		names, err := remoteDNSAllowlist(arg, "X")
		if err != nil {
			return nil, false
		}
		return toAny(names), false
	case "internal_networks":
		nets, err := internalNetworkAllowlist(arg)
		if err != nil {
			return nil, false
		}
		out := []any{}
		for _, n := range nets {
			out = append(out, n.String())
		}
		return out, false
	}
	panic("unknown primitive " + fn)
}

func toAny(v []string) []any {
	out := make([]any, 0, len(v))
	for _, s := range v {
		out = append(out, s)
	}
	return out
}

var primitiveAlphabets = map[string][]string{
	"int":               {"0", "1", "5", "9", "_", "+", "-", " ", "\t", "\n", "\x1c", "\u00a0", "\u2003", "\u0663", "\U0001D7D9", "\uff11", "x", "e", ".", "\u00b2", "\u2460"},
	"strip":             {"a", " ", "\t", "\x1c", "\x1f", "\u0085", "\u00a0", "\u1680", "\u200b", "\u2028", "\u3000", "\ufeff", "\u180e", "b"},
	"lower":             {"A", "z", "\u0130", "\u212a", "\u03a3", "\u00c4", "\u1e9e", "TRUE", "\u0049", "\u0131", "\u01c5", "\u2c6f"},
	"ip_address":        {"1", "0", "255", "256", "01", ".", ":", "::", "a", "F", "ffff", "%", "eth0", "1.2.3.4", "g", "00000"},
	"ip_network":        {"10.0.0.0", "/", "8", "08", "32", "33", "255.0.0.0", "0.255.255.255", "255.0.255.0", "fc00::", "fd00::1", "%a", "7", "128", "::ffff:10.0.0.0", "1", ".", ":"},
	"urlsplit":          {"https", "http", "ldap", "://", "//", ":", "@", "user", "pw", "[", "]", "::1", "v1.x", "host", ".", "443", "0", "65536", "/", "?", "#", "\t", " ", "\u2100", "\uff0f", "\u00e9", "a+b", "%25", "1"},
	"tailscale":         {"host", "a", "-", ".", ":", "22", "0", "65536", "[", "]", "::1", "1.2.3.4", "%", " ", "_", "x", "Host", "\u0663", "123456"},
	"remote_dns":        {"host", "a.example", ",", " ", "1.2.3.4", "::1", "[", "*", "-a", "b-", "..", "x:1", "A"},
	"internal_networks": {"10.0.0.0/8", "10.1.0.0/16", ",", " ", "192.168.1.1", "100.64.0.0/10", "fc00::/7", "fd00::%a/64", "fc00::%a/7", "8.8.8.8", "10.0.0.1/8", "172.16.0.0/255.240.0.0", "172.16.0.0/0.15.255.255", "fe80::1"},
	"repr":              {"a", "'", "\"", "\\", "\n", "\t", "\r", "\x00", "\x7f", "\u0085", "\u00a0", "\u200b", "\u2028", "\U0001F600", "\ue000", "\U000e0001", " "},
	"path":              {"/", "a", ".", "..", "//", "///", "b"},
}

var primitiveFixed = map[string][]string{
	"int":               {"", "0", "-0", "+0", "007", "1_000", "1__0", "_1", "1_", " 1 ", "\x1c1", "1\x1c", "\u00a01\u00a0", "\u0663", "- 1", "0x10", "1e3", strings.Repeat("9", 4300), strings.Repeat("9", 4301), "1_" + strings.Repeat("0", 4299)},
	"ip_network":        {"10.0.0.0/8", "10.0.0.0/255.0.0.0", "10.0.0.0/0.255.255.255", "10.0.0.0/08", "10.0.0.0/+8", "10.1.2.3", "fc00::/007", "fd00::1%a", "fc00::%a/7", "1::2:3:4:5:6:7", "1::2:3:4:5:6:7:8", "::ffff:10.0.0.1", "0:0:0:0:0:ffff:0a00:0001", "10.0.0.0/32", "10.0.0.0/33", "fd00::/ffff::"},
	"urlsplit":          {"https://localhost", "https://[::1]:443", "https://[v1.x]", "https://[1.2.3.4]", "https://a@b", "https://a:b@c", "http://h:65536", "http://h:0", "http://h:x", "\x00 https://a", "https://\u2100", "https://\u00e9", "ldap://h/", "ldaps://h:636", "1http://a", "h:/x"},
	"tailscale":         {"host", "host:22", "host:0", "[::1]:22", "[::1]", "[1.2.3.4]", "a..b", "a.", "-a", strings.Repeat("a", 64), strings.Repeat("a.", 127) + "a"},
	"internal_networks": {"", "10.0.0.0/8,10.0.0.0/8", "fd00::1%a,fd00::1", "8.8.8.8", "10.0.0.1/8"},
}

func primitiveCandidates(n int) []primitiveCase {
	r := rand.New(rand.NewPCG(26, 11))
	var out []primitiveCase
	fns := make([]string, 0, len(primitiveAlphabets))
	for fn := range primitiveAlphabets {
		fns = append(fns, fn)
	}
	slices.Sort(fns)
	for _, fn := range fns {
		for _, arg := range primitiveFixed[fn] {
			out = append(out, primitiveCase{Fn: fn, Arg: arg})
		}
		alphabet := primitiveAlphabets[fn]
		for range n {
			var b strings.Builder
			for range 1 + r.IntN(6) {
				b.WriteString(alphabet[r.IntN(len(alphabet))])
			}
			out = append(out, primitiveCase{Fn: fn, Arg: b.String()})
		}
	}
	return out
}

func checkPrimitive(t *testing.T, c primitiveCase) bool {
	t.Helper()
	got, skip := goPrimitive(c.Fn, c.Arg)
	if skip {
		return true
	}
	if canonicalJSON(got) != canonicalJSON(c.Result) {
		t.Errorf("%s(%q): Go %s, Python %s", c.Fn, c.Arg, canonicalJSON(got), canonicalJSON(c.Result))
		return false
	}
	return true
}

const primitiveVectors = "python_primitives.jsonl"

// TestPythonPrimitiveVectors compares the Python string, number, address
// and URL operations with the answers of CPython that are checked in.
func TestPythonPrimitiveVectors(t *testing.T) {
	if *update {
		o := requireOracle(t)
		cases := primitiveCandidates(150)
		for i := range cases {
			var resp struct{ Result any }
			o.ask(t, map[string]string{"fn": cases[i].Fn, "arg": cases[i].Arg}, &resp)
			cases[i].Result = resp.Result
		}
		writeJSONLines(t, primitiveVectors, cases)
	}
	cases := readJSONLines[primitiveCase](t, primitiveVectors)
	if len(cases) < 1000 {
		t.Fatalf("only %d vectors", len(cases))
	}
	failures := 0
	for _, c := range cases {
		if !checkPrimitive(t, c) {
			if failures++; failures > 30 {
				t.Fatal("too many mismatches")
			}
		}
	}
}

// TestPythonPrimitiveLive asks the oracle about many more random inputs.
func TestPythonPrimitiveLive(t *testing.T) {
	if testing.Short() {
		t.Skip("long differential run")
	}
	o := requireOracle(t)
	failures := 0
	for _, c := range primitiveCandidates(3000) {
		var resp struct{ Result any }
		o.ask(t, map[string]string{"fn": c.Fn, "arg": c.Arg}, &resp)
		c.Result = resp.Result
		if !checkPrimitive(t, c) {
			if failures++; failures > 30 {
				t.Fatal("too many mismatches")
			}
		}
	}
}
