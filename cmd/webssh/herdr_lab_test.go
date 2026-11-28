//go:build herdr

// Herdr against a real, pinned Herdr release (tests/integration/herdr):
// the session mode of terminal.open and the snapshot of the overview,
// through the composition root, as tests/integration/test_herdr_openssh.py
// checks the Python release. Run with
//
//	tests/integration/herdr/run-go-lab.sh
//
// which starts a disposable host, sets WEBSSH_HERDR_* and removes the host
// afterwards. The tests fail, not skip, without it.
package main

import (
	json "encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The binary sits outside the exec PATH; the fixed lookup finds it.
func TestHerdrLabBinaryOutsideTheExecPath(t *testing.T) {
	agent := readHerdrLab(t).side(t, "agentuser")
	if status, _ := agent.run(`command -v herdr`); status == 0 {
		t.Fatal("herdr is on the exec PATH; the lab no longer checks the lookup")
	}
	agent.must(herdrProbeLine)
	if v := agent.must(labHerdr + ` --version`); v != "herdr 0.9.5" {
		t.Fatalf("version %q", v)
	}
}

// The overview never starts Herdr; with a server it reports the agents,
// cleaned to the Python shape.
func TestHerdrLabOverviewAsksAndNeverStarts(t *testing.T) {
	lab := readHerdrLab(t)
	agent := lab.side(t, "agentuser")
	agent.stopHerdr()
	t.Cleanup(agent.stopHerdr)
	h := newHerdrSystem(t, lab)
	term := h.open(h.saveHost("agentuser", true, false), false)
	if !term.opened.Info.Herdr || term.opened.Info.UseHerdr {
		t.Fatalf("flags %+v", term.opened.Info)
	}
	if r := reason(term.snapshot()); r != "no_server" {
		t.Fatalf("without a server: %q", r)
	}
	if n := agent.count(); n != "0" {
		t.Fatalf("the snapshot started %s Herdr processes", n)
	}
	if status, _ := agent.run(`test -e "$HOME/.config/herdr"`); status == 0 {
		t.Fatal("the snapshot created Herdr state")
	}

	agent.startServer()
	agent.must(labHerdr + ` workspace create --label lab --no-focus >/dev/null`)
	if got := term.snapshotAfterPacing(); !got.Success || len(got.Agents) != 0 || got.Truncated || got.Reason != nil {
		t.Fatalf("empty server: %+v", got)
	}
	agent.must(labHerdr + ` pane rename w1:p1 build >/dev/null`)
	// Herdr 0.9.5 drops a reported agent after about half a second when
	// no agent process runs in the pane, so the report comes right before
	// each attempt.
	var res protocol.HerdrResult
	for range 4 {
		term.awaitPacing()
		agent.must(labHerdr + ` pane report-agent w1:p1 --source lab --agent builder --state blocked >/dev/null`)
		if res = term.snapshot(); len(res.Agents) > 0 {
			break
		}
	}
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"success":true,"agents":[{"id":"w1:p1","kind":"builder","label":"build","cwd":"/home/agentuser","status":"blocked"}],"truncated":false,"reason":null}`
	if string(got) != want {
		t.Fatalf("snapshot\n got %s\nwant %s", got, want)
	}
}

// Session mode starts Herdr on the first connection, a second one attaches
// to the same server, and closing WebSSH sessions only detaches.
func TestHerdrLabSessionModeStartsAttachesAndDetaches(t *testing.T) {
	lab := readHerdrLab(t)
	agent := lab.side(t, "agentuser")
	agent.stopHerdr()
	t.Cleanup(agent.stopHerdr)
	h := newHerdrSystem(t, lab)
	host := h.saveHost("agentuser", true, true)

	first := h.open(host, true)
	if !first.opened.Info.Herdr || !first.opened.Info.UseHerdr || first.opened.Info.UseTmux {
		t.Fatalf("flags %+v", first.opened.Info)
	}
	first.waitOutput("\x1b[?1049h")
	agent.waitFor(labServerAnswer, "session mode did not start a Herdr server")
	if got := first.snapshot(); !got.Success {
		t.Fatalf("snapshot of the session's own server: %+v", got)
	}
	list, err := h.sys.terminal.Restorable(t.Context(), h.owner)
	if err != nil || len(list) != 1 || list[0].SessionID != first.opened.SessionID || !list[0].UseHerdr {
		t.Fatalf("restorable %+v %v", list, err)
	}
	if offer, err := h.sys.terminal.Persistent(t.Context(), h.owner); err != nil || len(offer) != 0 {
		t.Fatalf("Herdr offered as a persistent tmux session: %+v %v", offer, err)
	}
	// A reload detaches the page and attaches the same session again; the
	// replay holds Herdr's screen.
	first = first.reattach()
	first.waitOutput("\x1b[?1049h")

	const marker = "attachmark"
	agent.must(labHerdr + ` workspace create --label ` + marker + ` --no-focus >/dev/null`)
	workspaces := strings.Count(agent.must(herdrSnapshotLine), `"workspace_id"`)
	second := h.open(host, true)
	if !second.opened.Info.UseHerdr {
		t.Fatalf("second flags %+v", second.opened.Info)
	}
	second.waitOutput(marker)
	if n := strings.Count(agent.must(herdrSnapshotLine), `"workspace_id"`); n != workspaces {
		t.Fatalf("the second connection changed the workspaces: %d, was %d", n, workspaces)
	}

	first.close()
	second.close()
	time.Sleep(time.Second)
	if status, _ := agent.run(labServerAnswer); status != 0 {
		t.Fatal("closing the WebSSH sessions stopped the Herdr server")
	}
	if list, _ := h.sys.terminal.Restorable(t.Context(), h.owner); len(list) != 0 {
		t.Fatalf("closed sessions still restorable: %+v", list)
	}
}

// Session mode needs both host options; without use_herdr on the saved
// host the request is a normal shell.
func TestHerdrLabSessionModeNeedsTheHostOption(t *testing.T) {
	lab := readHerdrLab(t)
	agent := lab.side(t, "agentuser")
	agent.stopHerdr()
	t.Cleanup(agent.stopHerdr)
	h := newHerdrSystem(t, lab)
	term := h.open(h.saveHost("agentuser", true, false), true)
	if term.opened.Info.UseHerdr {
		t.Fatalf("session mode without the host option: %+v", term.opened.Info)
	}
	term.input(1, "printf 'shell%s\\n' ready\r")
	term.waitOutput("shellready")
	if n := agent.count(); n != "0" {
		t.Fatalf("%s Herdr processes without session mode", n)
	}
}

// A host without Herdr falls back to a normal shell and reports
// not_installed.
func TestHerdrLabHostWithoutHerdr(t *testing.T) {
	lab := readHerdrLab(t)
	h := newHerdrSystem(t, lab)
	term := h.open(h.saveHost("testuser", true, true), true)
	if !term.opened.Info.Herdr || term.opened.Info.UseHerdr {
		t.Fatalf("flags %+v", term.opened.Info)
	}
	term.input(1, "printf 'shell%s\\n' ready\r")
	term.waitOutput("shellready")
	if r := reason(term.snapshot()); r != "not_installed" {
		t.Fatalf("reason %q", r)
	}
}

// A snapshot that hangs is answered with timeout after its three-second
// budget, as in Python, the session is then paced, and the stuck process
// ends on the host: by the signal and close of its channel or, on a host
// that ignores both, by the host-side limit of the snapshot command. Only
// the channel ends; the terminal on the same connection keeps working
// (RC0-1).
func TestHerdrLabStuckSnapshotIsEndedOnTheHost(t *testing.T) {
	lab := readHerdrLab(t)
	plain := lab.side(t, "testuser")
	plain.must(`mkdir -p "$HOME/.local/bin" && printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > ` + labHerdr + ` && chmod +x ` + labHerdr)
	t.Cleanup(func() {
		plain.run(`pkill -x herdr; rm -f "$HOME/.local/bin/herdr"; rmdir "$HOME/.local/bin" "$HOME/.local" 2>/dev/null`)
	})
	h := newHerdrSystem(t, lab)
	term := h.open(h.saveHost("testuser", true, false), false)
	started := time.Now()
	if r := reason(term.snapshot()); r != "timeout" {
		t.Fatalf("reason %q", r)
	}
	d := time.Since(started)
	t.Logf("timeout answered after %v", d)
	if d < 3*time.Second || d > 3500*time.Millisecond {
		t.Fatalf("timeout after %v", d)
	}
	if r := reason(term.snapshot()); r != "busy" {
		t.Fatalf("reason after a timeout %q", r)
	}
	deadline := started.Add(10 * time.Second)
	for plain.count() != "0" {
		if time.Now().After(deadline) {
			t.Fatal("stuck Herdr call survived the host limit")
		}
		time.Sleep(250 * time.Millisecond)
	}
	// The session's connection survived the stuck call.
	term.input(1, "printf 'still%s\\n' alive\r")
	term.waitOutput("stillalive")
}

// The integration switch and the host option are read at every snapshot.
func TestHerdrLabSnapshotFollowsTheSwitch(t *testing.T) {
	lab := readHerdrLab(t)
	h := newHerdrSystem(t, lab)
	term := h.open(h.saveHost("testuser", true, false), false)
	setHerdrSwitch(t, h.sys, false)
	if r := reason(term.snapshot()); r != "disabled" {
		t.Fatalf("switch off: %q", r)
	}
	setHerdrSwitch(t, h.sys, true)
	if r := reason(term.snapshot()); !slices.Contains([]string{"not_installed"}, r) {
		t.Fatalf("switch on: %q", r)
	}
	plainHost := h.open(h.saveHost("testuser", false, false), false)
	if plainHost.opened.Info.Herdr {
		t.Fatalf("overview without the host option: %+v", plainHost.opened.Info)
	}
	if r := reason(plainHost.snapshot()); r != "not_enabled" {
		t.Fatalf("host without the option: %q", r)
	}
}

// The snapshot command passes the CLI's exit status through, so the
// reasons above come from Herdr itself.
func TestHerdrLabSnapshotCommandExitStatus(t *testing.T) {
	lab := readHerdrLab(t)
	agent := lab.side(t, "agentuser")
	agent.stopHerdr()
	t.Cleanup(agent.stopHerdr)
	if status, _ := agent.run(herdrSnapshotLine); status != 1 {
		t.Fatalf("without a server: exit %d", status)
	}
	if status, _ := lab.side(t, "testuser").run(herdrSnapshotLine); status != 127 {
		t.Fatalf("without Herdr: exit %d", status)
	}
	agent.startServer()
	status, out := agent.run(herdrSnapshotLine)
	if status != 0 || !strings.Contains(out, `"session_snapshot"`) {
		t.Fatalf("with a server: exit %d, %.200q", status, out)
	}
}

// The probe the Go release sends is the Python text.
func TestHerdrLabProbeIsThePythonText(t *testing.T) {
	if hostops.HerdrProbeCommand != herdrProbeLine {
		t.Fatalf("probe %q", hostops.HerdrProbeCommand)
	}
}
