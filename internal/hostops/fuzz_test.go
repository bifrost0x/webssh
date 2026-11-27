package hostops

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
	"unicode/utf8"
)

// The parsers read output of a host that may be hostile. They must never
// panic, keep their bounds and let no control character through.

func clean(t *testing.T, what, s string, max int) {
	t.Helper()
	if hasControl(s) || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) {
		t.Fatalf("%s %q", what, s)
	}
}

func FuzzParseStats(f *testing.F) {
	for _, tc := range readOracleF(f).Stats {
		f.Add(tc.Input)
	}
	f.Fuzz(func(t *testing.T, text string) {
		st, err := ParseStats(text)
		if err != nil {
			return
		}
		clean(t, "os_name", st.OSName, 200)
		if st.Processes != nil {
			if len(st.Processes.TopCPU) > 5 || len(st.Processes.TopMemory) > 5 || st.Processes.Zombies > st.Processes.Total {
				t.Fatalf("processes %+v", st.Processes)
			}
			for _, p := range append(st.Processes.TopCPU, st.Processes.TopMemory...) {
				clean(t, "user", p.User, 64)
				clean(t, "command", p.Command, 128)
			}
		}
		if st.Memory != nil && st.Memory.AvailableKiB > st.Memory.TotalKiB {
			t.Fatalf("memory %+v", st.Memory)
		}
	})
}

func FuzzParseInventory(f *testing.F) {
	for _, tc := range readOracleF(f).Inventory {
		f.Add(tc.Input)
	}
	f.Fuzz(func(t *testing.T, text string) {
		inv, err := ParseInventory(text)
		if err != nil {
			return
		}
		if s := inv.Systemd; s != nil {
			if len(s.Services) > maxSystemdServices || s.Active+s.Failed > s.Total {
				t.Fatalf("systemd %+v", s)
			}
			for _, svc := range s.Services {
				if !unitNamePattern.MatchString(svc.Unit) {
					t.Fatalf("unit %q", svc.Unit)
				}
				clean(t, "sub", svc.Sub, 64)
				clean(t, "description", svc.Description, 240)
			}
		}
		if d := inv.Docker; d != nil {
			if len(d.Containers) > maxDockerContainers || d.Running > d.Total {
				t.Fatalf("docker %+v", d)
			}
			for _, c := range d.Containers {
				if !containerNamePattern.MatchString(c.Name) {
					t.Fatalf("name %q", c.Name)
				}
				clean(t, "status", c.Status, 160)
			}
		}
	})
}

func FuzzHerdrSnapshot(f *testing.F) {
	for _, tc := range readOracleF(f).Herdr {
		raw, _ := hexDecode(tc.Input)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		agents, _, err := parseHerdrSnapshot(payload)
		if err != nil {
			return
		}
		if len(agents) > herdrMaxAgents {
			t.Fatalf("%d agents", len(agents))
		}
		for _, a := range agents {
			if !herdrAgentID.MatchString(a.ID) {
				t.Fatalf("id %q", a.ID)
			}
			for _, s := range []string{a.Kind, a.Label, a.CWD} {
				if strings.ContainsFunc(s, herdrRemoved) || utf8.RuneCountInString(s) > herdrMaxPath {
					t.Fatalf("text %q", s)
				}
			}
		}
		_ = herdrFailure(1, payload)
	})
}

func FuzzProcessList(f *testing.F) {
	for _, tc := range readOracleF(f).Processes {
		f.Add(tc.Input)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rows, err := parseProcessList(text)
		if err != nil {
			return
		}
		seen := map[int]bool{}
		for _, r := range rows {
			if r.PID < 1 || r.PID > maxPID || seen[r.PID] {
				t.Fatalf("row %+v", r)
			}
			seen[r.PID] = true
		}
		_, _ = newestContainerLogs(text, text)
		_ = displayText([]byte(text))
	})
}

// shellMeta are the characters that could start a second command or an
// expansion; the fixed command text uses none of them outside quotes.
const shellMeta = ";&|$`<>()\\\n\r*?~!#"

func FuzzBuildCommand(f *testing.F) {
	for _, tc := range readOracleF(f).Commands {
		f.Add(tc.Action, string(tc.Target), string(tc.Sudo))
	}
	f.Fuzz(func(t *testing.T, action, target, sudo string) {
		req := opRequest{"action": jsontext.Value(quoteJSON(action)), "target": jsontext.Value(target), "use_sudo": jsontext.Value(sudo)}
		_, c, err := req.command(append(append([]string(nil), readActions...), writeActions...))
		if err != nil {
			return
		}
		line := c.Line
		if i := strings.Index(line, "'"+containerInspectTemplate+"'"); i >= 0 {
			line = line[:i] + line[i+len(containerInspectTemplate)+2:]
		}
		line = strings.Replace(line, "sh -c '"+systemInspectLine+"'", "", 1)
		line = strings.Replace(line, systemInspectLine, "", 1)
		if strings.ContainsAny(line, shellMeta+"'\"") {
			t.Fatalf("line %q", c.Line)
		}
	})
}

func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[r>>4])
			b.WriteByte("0123456789abcdef"[r&15])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
