package main

import (
	"path/filepath"
	"slices"
)

// ldapHelperPath is the script the ldap-tools service of
// docker-compose.ldap.yml runs with "python" (invariant I-21).
const ldapHelperPath = "/app/deployment/ldap_secret_cli.py"

// pythonNames are the names under which the image links the binary as
// the Python interpreter, so that the Compose file keeps working without
// any change (ADR 0011).
var pythonNames = []string{"python", "python3"}

func isPythonShim(argv0 string) bool {
	return slices.Contains(pythonNames, filepath.Base(argv0))
}

// runPythonShim accepts exactly "python /app/deployment/ldap_secret_cli.py
// <command> …" and runs `webssh ldap-secret <command> …` with the usage
// lines of the Python script. Every other argument vector is refused: the
// image has no Python.
func runPythonShim(args []string, s streams) int {
	if len(args) == 0 || args[0] != ldapHelperPath {
		write(s.stderr, "webssh: this image has no Python; \"python\" only accepts \""+ldapHelperPath+
			" <command>\" (use \"/app/webssh ldap-secret <command>\")\n")
		return 2
	}
	write(s.stderr, "webssh: the form \"python "+ldapHelperPath+"\" is deprecated and will be removed in the next "+
		"major release; use \"/app/webssh ldap-secret\".\n")
	return runLDAPSecretAs("ldap_secret_cli.py", args[1:], s)
}
