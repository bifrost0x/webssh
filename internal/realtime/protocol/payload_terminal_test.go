package protocol

import (
	"strings"
	"testing"
)

func TestTerminalOpenBoundsTheStartupMembers(t *testing.T) {
	base := func() TerminalOpen {
		return TerminalOpen{Ch: 1, RequestID: "r", Target: OpenTarget{Host: "h", AuthType: AuthPassword}}
	}
	long := strings.Repeat("x", MaxStartupBytes+1)
	ok := strings.Repeat("ü", MaxStartupBytes/2)
	r := base()
	r.Target.Startup = &Startup{Commands: ok, ParametersOverride: &ok}
	r.Target.DisplayName = ok
	if err := r.Validate(); err != nil {
		t.Fatalf("within the bounds: %v", err)
	}
	for name, set := range map[string]func(*OpenTarget){
		"commands":     func(o *OpenTarget) { o.Startup = &Startup{Commands: long} },
		"override":     func(o *OpenTarget) { o.Startup = &Startup{ParametersOverride: &long} },
		"command_id":   func(o *OpenTarget) { o.Startup = &Startup{CommandID: strings.Repeat("c", MaxIDLen+1)} },
		"set_id":       func(o *OpenTarget) { o.Startup = &Startup{CommandSetID: strings.Repeat("s", MaxIDLen+1)} },
		"mode":         func(o *OpenTarget) { o.Startup = &Startup{Mode: strings.Repeat("m", 33)} },
		"display_name": func(o *OpenTarget) { o.DisplayName = long },
	} {
		r := base()
		set(&r.Target)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: too long accepted", name)
		}
	}
}
