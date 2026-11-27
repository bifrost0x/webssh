package hosts

import (
	"fmt"
	"regexp"
	"strings"
)

// Catalog values end up unquoted inside the probe's shell text; quoting
// them all would make the probe longer than it needs to be. They are fixed
// strings, but a later edit must never be able to bring in shell syntax,
// so every one must be a plain literal word: no quotes, expansions, globs,
// tilde, '=' or whitespace, no leading '-', and no reserved word.
var shellWordPattern = regexp.MustCompile(`^[A-Za-z0-9/][A-Za-z0-9@_.:/+-]*$`)

var reservedWords = set("if", "then", "else", "elif", "fi", "do", "done", "case", "esac",
	"while", "until", "for", "in", "function", "select", "time")

func shellWord(value string) (string, error) {
	if !shellWordPattern.MatchString(value) || reservedWords[value] {
		return "", fmt.Errorf("hosts: unsafe value in the identity probe: %q", value)
	}
	return value, nil
}

func shellPath(value string) (string, error) {
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("hosts: unsafe path in the identity probe: %q", value)
	}
	return shellWord(value)
}

// identityScript is _identity_command: identityTemplate with the catalog's
// units, unit templates, paths, snaps and the container engines filled in.
func identityScript(units, templates, paths, snaps [][2]string) (string, error) {
	words := func(pairs [][2]string, key, value func(string) (string, error)) error {
		for _, p := range pairs {
			if _, err := key(p[0]); err != nil {
				return err
			}
			if _, err := value(p[1]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, check := range []error{
		words(units, shellWord, shellWord), words(templates, shellWord, shellWord),
		words(paths, shellPath, shellWord), words(snaps, shellWord, shellWord),
	} {
		if check != nil {
			return "", check
		}
	}
	unitCase := ""
	if len(units) > 0 {
		names := make([]string, len(units))
		for i, u := range units {
			names[i] = u[0]
		}
		unitCase = "        " + strings.Join(names, "|") + `) printf 'unit=%s\n' "$name" ;;`
	}
	templateLines := make([]string, len(templates))
	for i, t := range templates {
		templateLines[i] = "        " + t[0] + "@*) found " + t[1] + " ;;"
	}
	// One test per service, in the order the services first appear.
	var order []string
	byService := map[string][]string{}
	for _, p := range paths {
		if _, seen := byService[p[1]]; !seen {
			order = append(order, p[1])
		}
		byService[p[1]] = append(byService[p[1]], "[ -e "+p[0]+" ]")
	}
	pathLines := make([]string, len(order))
	for i, service := range order {
		pathLines[i] = "if " + strings.Join(byService[service], " || ") + "; then found " + service + "; fi"
	}
	snapLines := make([]string, len(snaps))
	for i, s := range snaps {
		snapLines[i] = "[ -d /snap/" + s[0] + " ] && echo snap=" + s[0]
	}
	return strings.NewReplacer(
		"@UNITCASE@", unitCase,
		"@TEMPLATECASE@", strings.Join(templateLines, "\n"),
		"@PATHS@", strings.Join(pathLines, "\n"),
		"@SNAPS@", strings.Join(snapLines, "\n"),
		"@ENGINES@", dockerBlock+"\n"+podmanBlock,
	).Replace(identityTemplate), nil
}

// IdentityScript is the one read-only probe for everything the host
// identity needs: os-release, kernel, board model, platform markers,
// virtualization, systemd target, guest count, known services and, where
// the SSH user may already talk to a Docker or Podman daemon (no sudo), the
// names of running images. Nothing is installed, changed or sourced; every
// file read is bounded. It is IDENTITY_SCRIPT of the Python release, which
// sent it joined into one exec line; here it travels on stdin
// (remotecmd.Script), which needs no quoting for the login shell.
var IdentityScript = mustIdentityScript()

func mustIdentityScript() string {
	s, err := identityScript(serviceUnits, serviceUnitTemplates, servicePaths, serviceSnaps)
	if err != nil {
		panic(err)
	}
	return s
}

// MaintenanceScript is the read-only update and restart probe that an
// automation step must run unchanged for its output to reach the overview.
const MaintenanceScript = maintenanceScript

// RebootHintScript rereads only the restart marker.
const RebootHintScript = rebootHintScript
