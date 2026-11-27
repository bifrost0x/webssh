package terminal

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// testdata/prompt_oracle.json is produced by testdata/prompt_oracle.py
// from the functions of app/ssh_manager.py: sequences of output and input
// chunks and prompt_input_idle after each.
func TestPromptStateMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/prompt_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases [][]struct {
		Out  *string `json:"out"`
		In   *string `json:"in"`
		Idle bool    `json:"idle"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	idle := 0
	for i, steps := range cases {
		var p promptState
		for j, s := range steps {
			switch {
			case s.Out != nil:
				b, _ := base64.StdEncoding.DecodeString(*s.Out)
				p.output(b)
			case s.In != nil:
				b, _ := base64.StdEncoding.DecodeString(*s.In)
				p.input(b)
			}
			if got := p.inputIdle(); got != s.Idle {
				t.Fatalf("case %d step %d: idle %v, Python %v", i, j, got, s.Idle)
			}
			if s.Idle {
				idle++
			}
		}
	}
	if len(cases) < 100 || idle == 0 {
		t.Fatalf("oracle too small: %d cases, %d idle steps", len(cases), idle)
	}
}

// A mode sequence split across reads counts once, and typing leaves the
// prompt while a terminal reply does not.
func TestPromptStateAcrossReads(t *testing.T) {
	var p promptState
	p.output([]byte("$ \x1b[?20"))
	if p.inputIdle() {
		t.Fatal("idle before the sequence is complete")
	}
	p.output([]byte("04h"))
	if !p.inputIdle() {
		t.Fatal("split bracketed paste not seen")
	}
	p.input([]byte("\x1b[?1;2c"))
	if !p.inputIdle() {
		t.Fatal("a device attributes reply counted as typing")
	}
	p.output([]byte("\x1b[?1049h"))
	if p.inputIdle() {
		t.Fatal("idle on the alternate screen")
	}
	p.output([]byte("\x1b[?1049l"))
	p.input([]byte("l"))
	if p.inputIdle() {
		t.Fatal("idle after typing")
	}
}
