//go:build warpgate

// End to end through the composition root: terminal.open with a gateway
// selector, the realtime prompts and the readiness probe against a real
// Warpgate (internal/ssh/gateway/testdata/warpgate-up.sh). Run with
//
//	WEBSSH_WARPGATE_DIR=/tmp/webssh-warpgate go test -tags warpgate -run Warpgate ./cmd/webssh
package main

import (
	"encoding/hex"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func TestWarpgateTerminalThroughTheRealtimeTypes(t *testing.T) {
	dir := os.Getenv("WEBSSH_WARPGATE_DIR")
	if dir == "" {
		t.Fatal("set WEBSSH_WARPGATE_DIR")
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	key, err := hex.DecodeString(read("otp.hex"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := otp.TOTP(key, otp.Step(time.Now(), 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sys, v := gatewaySystem(t)
	setGateway(t, sys, true)
	user := principaltest.User(1)
	peer := protocoltest.NewPeer(t, user)
	routes := map[string]protocol.Route{}
	for _, r := range append(sys.terminal.Routes(), v.registry.Routes()...) {
		routes[r.Type] = r
	}
	call := func(typ string, payload any) {
		if _, perr := protocoltest.Call(t.Context(), routes[typ], peer, payload); perr != nil {
			t.Errorf("%s: %+v", typ, perr)
		}
	}
	type result struct {
		raw  []byte
		perr *protocol.Error
	}
	done := make(chan result, 1)
	go func() {
		raw, perr := protocoltest.Call(t.Context(), routes[protocol.TypeTerminalOpen], peer, protocol.TerminalOpen{
			Ch: 1, RequestID: "gateway_e2e", Rows: 24, Cols: 80,
			Target: protocol.OpenTarget{Host: "127.0.0.1", Port: 12222, Username: "bob:modern",
				AuthType: protocol.AuthPassword, Password: read("bob.password"), Interactive: true}})
		done <- result{raw, perr}
	}()
	trust := regexp.MustCompile(`(?i)trust this key\?`)
	seen, typed, output := 0, false, ""
	deadline := time.After(60 * time.Second)
	for {
		select {
		case r := <-done:
			if r.perr != nil {
				t.Fatalf("terminal.open: %+v; gateway output %q", r.perr, output)
			}
			var opened protocol.TerminalOpened
			if err := json.Unmarshal(r.raw, &opened); err != nil {
				t.Fatal(err)
			}
			if opened.Info.Username != "bob:modern" || !strings.Contains(output, "WEBSSH_READY_") {
				t.Fatalf("opened %+v, output %q", opened, output)
			}
			kinds := map[string]int{}
			for _, ev := range peer.Events() {
				kinds[ev.Type]++
			}
			t.Logf("events: %v", kinds)
			if kinds[protocol.TypePromptHostKey] != 1 || kinds[protocol.TypePromptInteractive] != 1 || kinds[protocol.TypeGatewaySetup] != 1 {
				t.Fatalf("events %v", kinds)
			}
			if v.registry.Pending() != 0 {
				t.Fatal("attempt left in the registry")
			}
			return
		case <-deadline:
			t.Fatalf("timed out; output %q", output)
		case <-time.After(20 * time.Millisecond):
		}
		events := peer.Events()
		for _, ev := range events[seen:] {
			switch ev.Type {
			case protocol.TypePromptHostKey:
				var q protocol.PromptHostKey
				_ = json.Unmarshal(ev.Payload, &q)
				call(protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: q.PromptID, Kind: protocol.PromptKindHostKey, Accepted: true})
			case protocol.TypePromptInteractive:
				var q protocol.PromptInteractive
				_ = json.Unmarshal(ev.Payload, &q)
				t.Logf("prompt %+v", q)
				call(protocol.TypePromptRespond, protocol.PromptRespond{RequestID: q.RequestID, PromptID: q.PromptID, Answers: []string{code}})
			case protocol.TypeGatewayOutput:
				var o protocol.GatewayOutput
				_ = json.Unmarshal(ev.Payload, &o)
				output += o.Data
				call(protocol.TypeGatewayAck, protocol.GatewayAck{RequestID: o.RequestID, Sequence: o.Sequence})
				if !typed && trust.MatchString(output) {
					typed = true
					call(protocol.TypeGatewayInput, protocol.GatewayInput{RequestID: o.RequestID, Data: "y"})
				}
			}
		}
		seen = len(events)
	}
}
