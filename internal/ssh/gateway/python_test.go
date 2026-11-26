package gateway

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// testdata/python_vectors.json is produced by testdata/python_vectors.py
// from the unchanged Python modules; see the script for the command.
type pyVectors struct {
	Python    string `json:"python"`
	Selectors []struct {
		In  string   `json:"in"`
		OK  bool     `json:"ok"`
		Out []string `json:"out"`
	} `json:"selectors"`
	Tmux []struct {
		UserID   int64  `json:"user_id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Selector string `json:"selector"`
		Prefix   string `json:"prefix"`
		Name     string `json:"name_without_uuid"`
	} `json:"tmux"`
	Auth []struct {
		Mode     string     `json:"mode"`
		User     string     `json:"user"`
		Password string     `json:"password"`
		Key      bool       `json:"key"`
		Answer   string     `json:"answer"`
		Outcome  string     `json:"outcome"`
		Used     []string   `json:"used"`
		Prompts  [][]string `json:"prompts"`
	} `json:"auth"`
	Answers []struct {
		Prompts         int      `json:"prompts"`
		Answers         []string `json:"answers"`
		OtherUser       bool     `json:"other_user"`
		OtherConnection bool     `json:"other_connection"`
		SameID          bool     `json:"same_id"`
		OK              bool     `json:"ok"`
		ReplayOK        *bool    `json:"replay_ok"`
	} `json:"answers"`
	Inputs []struct {
		Phase  string   `json:"phase"`
		Values []string `json:"values"`
		OK     []bool   `json:"ok"`
	} `json:"inputs"`
	Acks []struct {
		Sequence uint64 `json:"sequence"`
		OK       bool   `json:"ok"`
	} `json:"acks"`
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
	if len(v.Selectors) < 400 || len(v.Auth) < 100 || len(v.Tmux) < 10 {
		t.Fatalf("vector file is incomplete: %d selectors, %d auth scenarios", len(v.Selectors), len(v.Auth))
	}
	return v
}

func TestParseSelectorMatchesPython(t *testing.T) {
	for _, v := range loadVectors(t).Selectors {
		user, target, err := ParseSelector(v.In)
		if (err == nil) != v.OK {
			t.Errorf("%q: python ok=%v, go err=%v", v.In, v.OK, err)
			continue
		}
		if v.OK && (user != v.Out[0] || target != v.Out[1]) {
			t.Errorf("%q: python %v, go %q %q", v.In, v.Out, user, target)
		}
	}
	if _, _, err := ParseSelector("u:\xff"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

var tmuxPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,190}$`)

func TestTmuxNameMatchesPythonDigest(t *testing.T) {
	for _, v := range loadVectors(t).Tmux {
		name, err := TmuxName(v.Prefix, v.Host, v.Port, v.Selector, v.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(name, v.Name+"_") || len(name) != len(v.Name)+1+32 {
			t.Errorf("%+v: go %q", v, name)
		}
		// The reconnect path accepts stored names only in this form.
		if !tmuxPattern.MatchString(name) {
			t.Errorf("%q does not satisfy the reconnect pattern", name)
		}
	}
	a, _ := TmuxName("p", "h", 22, "u:t", 1)
	b, _ := TmuxName("p", "h", 22, "u:t", 1)
	if a == b {
		t.Fatal("names must differ per connection")
	}
	if _, err := TmuxName("p", "h", 22, "no-selector", 1); err == nil {
		t.Fatal("invalid selector accepted")
	}
}

// TestAuthStrategyMatchesPython runs every scenario of GatewayAuthStrategy
// (mode, username, saved password, stored key, browser answer) against an
// x/crypto server with the same behaviour and compares the outcome, the
// methods the server saw and the prompts the browser was shown.
func TestAuthStrategyMatchesPython(t *testing.T) {
	for _, v := range loadVectors(t).Auth {
		name := fmt.Sprintf("%s/%s/pw=%s/key=%v/%s", v.Mode, v.User, v.Password, v.Key, v.Answer)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g, key := newStandIn(t, v.Mode)
			b := newBrowser()
			b.answer = func(_ string, p []Prompt) []string {
				if len(p) == 1 && p[0].Label == "Password" {
					return []string{g.password}
				}
				out := make([]string, len(p))
				for i := range p {
					out[i] = map[string]string{"424242": g.otp}[v.Answer]
					if out[i] == "" {
						out[i] = v.Answer
					}
				}
				return out
			}
			var auth client.Auth
			switch v.Password {
			case "*":
				auth.Password = g.password
			case "wrong":
				auth.Password = "wrong-password"
			}
			if !v.Key {
				key = nil
			}
			a, ctx := begin(t, t.Context(), b, IsSelector(v.User))
			_, err := dialVia(ctx, t, g, v.User, auth, key, a, false, nil)
			outcome := "ok"
			if err != nil {
				outcome = "failed"
			}
			var prompts [][]string
			for _, p := range b.asked() {
				labels := []string{}
				for _, q := range p {
					labels = append(labels, q.Label)
				}
				prompts = append(prompts, labels)
			}
			used := g.used()
			if used == nil {
				used = []string{}
			}
			want := v
			if v.Mode == "password+otp" && v.Password == "" && !v.Key {
				// Deviation (fix): Python counts keyboard-interactive as
				// tried when the server did not offer it at the start, so
				// after the password typed in the browser it refuses the
				// one-time code the gateway asks for next. Go asks for it.
				want.Used = []string{"password", "keyboard-interactive"}
				want.Prompts = [][]string{{"Password"}, {"OTP: "}}
				want.Outcome = map[bool]string{true: "ok", false: "failed"}[v.Answer == "424242"]
			}
			if outcome != want.Outcome || !slices.Equal(used, want.Used) || !slices.EqualFunc(prompts, want.Prompts, slices.Equal) {
				t.Errorf("python %s %v %v; go %s %v %v (%v)", v.Outcome, v.Used, v.Prompts, outcome, used, prompts, err)
			}
		})
	}
}

func TestAnswerRulesMatchPython(t *testing.T) {
	for i, v := range loadVectors(t).Answers {
		ev := newEvents()
		a := newAttempt(owner, "req", ev, nil, time.Now())
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = a.Challenge(ctx, "target", "", "", make([]Prompt, v.Prompts))
		}()
		id := (<-ev.ch).payload.(protocol.PromptInteractive).PromptID
		if !v.SameID {
			id = "other"
		}
		who := owner
		if v.OtherUser {
			who.UserID++
		}
		if v.OtherConnection {
			who.Peer++
		}
		if got := a.Answer(who, id, v.Answers); got != v.OK {
			t.Errorf("case %d: python %v, go %v", i, v.OK, got)
		}
		if v.ReplayOK != nil {
			if got := a.Answer(who, id, v.Answers); got != *v.ReplayOK {
				t.Errorf("case %d replay: python %v, go %v", i, *v.ReplayOK, got)
			}
		}
		cancel()
		<-done
	}
}

func TestInputRulesMatchPython(t *testing.T) {
	for i, v := range loadVectors(t).Inputs {
		a := newAttempt(owner, "req", newEvents(), nil, time.Now())
		if v.Phase == "setup" {
			if err := a.StartSetup(); err != nil {
				t.Fatal(err)
			}
		}
		for j, value := range v.Values {
			if got := a.Input(owner, value); got != v.OK[j] {
				t.Errorf("case %d value %d (%d bytes): python %v, go %v", i, j, len(value), v.OK[j], got)
			}
		}
	}
}

func TestAckRulesMatchPython(t *testing.T) {
	a := newAttempt(owner, "req", newEvents(), nil, time.Now())
	a.unacked = map[uint64]struct{}{1: {}, 2: {}}
	for _, v := range loadVectors(t).Acks {
		if got := a.Ack(owner, v.Sequence); got != v.OK {
			t.Errorf("ack %d: python %v, go %v", v.Sequence, v.OK, got)
		}
	}
}
