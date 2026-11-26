package stepup

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
)

// FuzzRequestFields feeds arbitrary bodies to the request parsing: it never
// panics, accepts only catalog actions and binds only non-empty targets of
// at most the JSON text given.
func FuzzRequestFields(f *testing.F) {
	f.Add(`{"action":"key.delete","target":"k1"}`)
	f.Add(`{"action":"totp.delete","target":-0}`)
	f.Add(`{"action":"mfa.disable"}`)
	f.Add(`{"action":" key.upload ","target":1e3}`)
	f.Fuzz(func(t *testing.T, body string) {
		obj := auth.ObjectFrom([]byte(body))
		action, target, ok := readAction(obj)
		if !ok {
			return
		}
		if !principal.Action(action).Known() {
			t.Fatalf("unknown action %q accepted", action)
		}
		if _, present := obj["target"]; present && target == "" {
			t.Fatal("present target bound as empty")
		}
		if strings.HasPrefix(target, "-0") || len(target) > len(body) {
			t.Fatalf("target %q from %q", target, body)
		}
	})
}
