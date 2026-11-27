package commands

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzChainSteps checks the chaining rules on arbitrary step text: no
// panic, and the separator never ends up inside a trailing comment of a
// step that has a command, so the next step still runs only after it.
func FuzzChainSteps(f *testing.F) {
	for _, s := range []string{"echo a", "echo a # c", "echo a;", "echo a &", "# c", "", "echo 'x # y'", "a\\\n#b", "\"\n#", "x\x1c#y"} {
		f.Add(s, "uptime", true)
	}
	f.Fuzz(func(t *testing.T, first, second string, sudo bool) {
		if !utf8.ValidString(first) || !utf8.ValidString(second) {
			t.Skip()
		}
		out := chainSteps([]string{first, second}, sudo)
		if !strings.Contains(out, "&&") {
			t.Fatalf("no separator in %q", out)
		}
		if !strings.HasSuffix(out, prepareStep(prefixIf(second, sudo))) {
			t.Fatalf("the last step changed: %q", out)
		}
	})
}

func prefixIf(s string, sudo bool) string {
	if sudo {
		return prefixSudo(s)
	}
	return s
}

// FuzzParameters checks that a value can never leave its argument: the
// resolved text of a valid one-step set is the program and the quoted
// value only.
func FuzzParameters(f *testing.F) {
	for _, s := range []string{"/tmp", "a'b", "$(id)", "`x`", "; rm -rf /", "", "ü ✓"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		text, msg := resolveArgv([][]string{{"ls", "{{p}}"}}, []string{"p"}, map[string]any{"p": value}, true, false)
		if msg != "" {
			if safeText(value, MaxArgRunes) {
				t.Fatalf("safe value %q refused: %s", value, msg)
			}
			return
		}
		quoted := strings.TrimPrefix(text, "'ls' ")
		if quoted == text || (quoted != shellQuote(value)) {
			t.Fatalf("%q resolved to %q", value, text)
		}
		if strings.ContainsAny(value, " ;$`'\"|&") && !strings.HasPrefix(quoted, "'") {
			t.Fatalf("unsafe value %q left unquoted: %q", value, quoted)
		}
	})
}
