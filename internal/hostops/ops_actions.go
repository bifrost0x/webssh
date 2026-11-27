package hostops

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Server operation actions (app/server_operations.py). Reads are open to
// the owner of a session; writes need the server_operations_enabled
// switch, an intent, the confirmation and a step-up.
var (
	readActions = []string{"container.inspect", "container.logs", "process.inspect", "process.list", "service.logs", "system.inspect"}
	// writeActions are sorted, as the capabilities answer lists them.
	writeActions = []string{
		"container.restart", "container.start", "container.stop",
		"process.terminate",
		"service.restart", "service.start", "service.stop",
		"system.reboot",
	}
)

var (
	opUnitPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,254}\.service$`)
	opContainerID      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opContainerName    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	opStartTimePattern = regexp.MustCompile(`^[0-9]{1,20}$`)
)

const maxPID = 4194304

// opCommand is what an action runs: a fixed command line with the
// validated target as plain tokens, and for the process actions a fixed
// Python program on stdin. Text is what the review shows.
type opCommand struct {
	Line  string
	Stdin string
}

// Text is the command as the review shows it: the line, and a program
// that travels on stdin as a here-document after it.
func (c opCommand) Text() string {
	if c.Stdin == "" {
		return c.Line
	}
	return c.Line + " <<'EOF'\n" + c.Stdin + "EOF"
}

// The programs of the process actions, unchanged from the Python release
// except that they are read from stdin ("python3 -") instead of "-c", so
// the command line stays one line of fixed text.
const (
	processInspectProgram = "import json,os,signal,sys\np=int(sys.argv[1])\nsupported=False\n" +
		"if hasattr(os,\"pidfd_open\") and hasattr(signal,\"pidfd_send_signal\"):\n" +
		" try:\n" +
		"  fd=os.pidfd_open(p)\n" +
		"  try: signal.pidfd_send_signal(fd,0); supported=True\n" +
		"  finally: os.close(fd)\n" +
		" except OSError: pass\n" +
		"s=open(\"/proc/%d/stat\"%p).read()\n" +
		"print(json.dumps({\"pid\":p,\"start_time\":s[s.rfind(\")\")+2:].split()[19]," +
		"\"command\":open(\"/proc/%d/cmdline\"%p,\"rb\").read(8192).replace(b\"\\0\",b\" \").decode(\"utf-8\",\"replace\")," +
		"\"pidfd_supported\":supported}))\n"
	processTerminateProgram = "import os,signal,sys\n" +
		"if not hasattr(os,\"pidfd_open\") or not hasattr(signal,\"pidfd_send_signal\"): sys.exit(78)\n" +
		"p=int(sys.argv[1]); fd=os.pidfd_open(p)\n" +
		"try:\n" +
		" s=open(\"/proc/%d/stat\"%p).read()\n" +
		" if s[s.rfind(\")\")+2:].split()[19]!=sys.argv[2]: sys.exit(75)\n" +
		" signal.pidfd_send_signal(fd,signal.SIGTERM)\n" +
		"finally: os.close(fd)\n"
	containerInspectTemplate = `{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State.Status}},"image":{{json .Config.Image}}}`
	systemInspectLine        = "uname -a; uptime; df -hP; free -m"
)

// opTarget is the target object of a request; members are kept raw so
// their JSON types can be checked as Python did.
type opTarget map[string]jsontext.Value

func (t opTarget) str(name string) (string, bool) {
	raw, ok := t[name]
	if !ok || raw.Kind() != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// integer is a JSON integer (type(x) is int: no bool, no float).
func (t opTarget) integer(name string) (int64, bool) {
	raw, ok := t[name]
	if !ok || raw.Kind() != '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil
}

// token checks a validated target value once more: only bytes of the
// remotecmd alphabet, starting with a letter or a digit, so no value with
// a shell meaning can reach a command line even if a pattern above were
// widened. The token is written without quotes, as shlex.quote left these
// values.
func token(s string) (string, error) {
	if !remotecmd.Inert(s) || !isAlnum(s[0]) {
		return "", opErr("invalid_target")
	}
	return s, nil
}

func isAlnum(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// buildCommand is build_command: the fixed command of an action on a
// validated target.
func buildCommand(action string, target opTarget, sudo bool) (opCommand, error) {
	if !slices.Contains(readActions, action) && !slices.Contains(writeActions, action) {
		return opCommand{}, opErr("invalid_action")
	}
	if target == nil {
		return opCommand{}, opErr("invalid_target")
	}
	verb := action[strings.IndexByte(action, '.')+1:]
	var c opCommand
	switch {
	case strings.HasPrefix(action, "service."):
		unit, ok := target.str("unit")
		if !ok || !opUnitPattern.MatchString(unit) {
			return opCommand{}, opErr("invalid_target")
		}
		unit, err := token(unit)
		if err != nil {
			return opCommand{}, err
		}
		if action == "service.logs" {
			c.Line = "journalctl --no-pager --reverse --lines=100 --output=short-iso --unit=" + unit
		} else {
			c.Line = "systemctl " + verb + " -- " + unit
		}
	case action == "container.inspect":
		name, ok := target.str("name")
		if !ok || !opContainerName.MatchString(name) {
			return opCommand{}, opErr("invalid_target")
		}
		name, err := token(name)
		if err != nil {
			return opCommand{}, err
		}
		c.Line = "docker inspect --type container --format '" + containerInspectTemplate + "' -- " + name
	case strings.HasPrefix(action, "container."):
		id, ok := target.str("container")
		if !ok || !opContainerID.MatchString(id) {
			return opCommand{}, opErr("invalid_target")
		}
		option := ""
		switch verb {
		case "logs":
			option = "--timestamps --tail 100 "
		case "stop", "restart":
			option = "--time 10 "
		}
		c.Line = "docker " + verb + " " + option + "-- " + id
	case action == "process.list":
		c.Line = "env LC_ALL=C ps -e -o pid=,user:32=,pcpu=,pmem=,comm= --sort=pid"
	case action == "process.inspect":
		pid, err := processPID(target)
		if err != nil {
			return opCommand{}, err
		}
		c = opCommand{Line: "python3 - " + strconv.FormatInt(pid, 10), Stdin: processInspectProgram}
	case action == "process.terminate":
		pid, err := processPID(target)
		if err != nil {
			return opCommand{}, err
		}
		start, ok := target.str("start_time")
		if !ok || !opStartTimePattern.MatchString(start) {
			return opCommand{}, opErr("invalid_target")
		}
		c = opCommand{Line: "python3 - " + strconv.FormatInt(pid, 10) + " " + start, Stdin: processTerminateProgram}
	case action == "system.reboot":
		c.Line = "systemctl reboot"
	default: // system.inspect
		c.Line = systemInspectLine
		if sudo {
			c.Line = "sh -c '" + systemInspectLine + "'"
		}
	}
	if sudo {
		c.Line = "sudo -n -- " + c.Line
	}
	return c, nil
}

func processPID(target opTarget) (int64, error) {
	pid, ok := target.integer("pid")
	if !ok || pid <= 1 || pid > maxPID {
		return 0, opErr("invalid_target")
	}
	return pid, nil
}
