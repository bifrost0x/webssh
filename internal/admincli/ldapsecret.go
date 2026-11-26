package admincli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Files of the LDAP secret volume (invariant I-21). The server reads them
// from LDAP_BIND_PASSWORD_FILE and LDAP_CA_CERT_FILE.
const (
	ldapPasswordFile = "ldap_bind_password" // #nosec G101 -- a file name, not a credential
	ldapCAFile       = "ldap_ca.pem"
	// DefaultLDAPSecretDir is the mount point of the secret volume in
	// docker-compose.ldap.yml.
	DefaultLDAPSecretDir = "/run/webssh-auth" // #nosec G101 -- a mount point, not a credential
	maxLDAPPassword      = 16 * 1024
	maxLDAPCA            = 1024 * 1024
)

const ldapGroupHelp = `Usage: %s [OPTIONS] COMMAND [ARGS]...

  Manage LDAP files in WebSSH's dedicated secret volume.

Options:
  --secret-dir PATH  [default: /run/webssh-auth]
  --help             Show this message and exit.

Commands:
  install-ca    Validate and install the CA bundle used to verify LDAP TLS.
  remove        Remove only the two LDAP files from the dedicated volume.
  set-password  Set the least-privilege LDAP search-account password.
  status        Show whether the required files exist without reading...
`

var ldapSubcommands = map[string]struct {
	help    string
	options []option
	args    string
	maxArgs int
	run     func(dir string, p parsed, o IO) error
}{
	"set-password": {
		help:    "  Set the least-privilege LDAP search-account password.\n\nOptions:\n  --stdin  Read from standard input.\n  --help   Show this message and exit.\n",
		options: []option{{name: "--stdin", flag: true}},
		run:     ldapSetPassword,
	},
	"install-ca": {
		help:    "  Validate and install the CA bundle used to verify LDAP TLS.\n\nOptions:\n  --stdin  Read PEM from standard input.\n  --help   Show this message and exit.\n",
		options: []option{{name: "--stdin", flag: true}},
		args:    "[PEM_FILE]",
		maxArgs: 1,
		run:     ldapInstallCA,
	},
	"status": {
		help: "  Show whether the required files exist without reading their content.\n\nOptions:\n  --help  Show this message and exit.\n",
		run:  ldapStatus,
	},
	"remove": {
		help:    "  Remove only the two LDAP files from the dedicated volume.\n\nOptions:\n  --yes   Skip the destructive confirmation.\n  --help  Show this message and exit.\n",
		options: []option{{name: "--yes", flag: true}},
		run:     ldapRemove,
	},
}

// LDAPSecret is `webssh ldap-secret`, the helper of
// deployment/ldap_secret_cli.py with the same commands, options, files,
// modes, exit codes and messages. prog names the program in usage lines:
// "ldap_secret_cli.py" under the deprecated form, "webssh ldap-secret"
// otherwise.
func LDAPSecret(prog string, args []string, o IO) int {
	group := &command{prog: prog, usageArgs: "COMMAND [ARGS]...", help: fmt.Sprintf(ldapGroupHelp, prog),
		options: []option{{name: "--secret-dir", metavar: "PATH"}}}
	p := parsed{values: map[string]string{}, flags: map[string]bool{}}
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		n, err := group.parseOption(&p, arg, args[i+1:])
		if err != nil {
			return group.report(o, err)
		}
		i += n
	}
	if p.help {
		_, _ = io.WriteString(o.Stdout, group.help)
		return ExitOK
	}
	switch {
	case len(args) == 0:
		// Click shows the help of a group called without arguments and
		// exits with 2.
		_, _ = io.WriteString(o.Stderr, group.help)
		return ExitUsage
	case i >= len(args):
		return group.report(o, &usageError{msg: "Missing command.", withUsage: true})
	}
	name := args[i]
	sub, ok := ldapSubcommands[name]
	if !ok {
		return group.report(o, &usageError{msg: fmt.Sprintf("No such command '%s'.", name), withUsage: true})
	}
	dir := DefaultLDAPSecretDir
	if v, ok := p.value("--secret-dir"); ok {
		dir = v
	}
	// As in Click, the group callback prepares the directory before the
	// command parses its own arguments.
	dir, err := ldapSecretDir(dir)
	if err != nil {
		return group.report(o, err)
	}
	c := &command{prog: prog, path: name, usageArgs: sub.args, options: sub.options, maxArgs: sub.maxArgs}
	c.help = c.usageLine() + "\n\n" + sub.help
	return c.run(o, args[i+1:], func(p parsed) error { return sub.run(dir, p, o) })
}

// ldapSecretDir creates the directory with mode 0700 if needed and
// restricts it to 0700; a link or anything else than a directory is
// refused.
func ldapSecretDir(dir string) (string, error) {
	if dir == "" {
		dir = "." // pathlib.Path("") is the current directory
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if _, lerr := os.Lstat(dir); lerr == nil {
			return "", fail("Secret directory must be a real directory")
		}
		return "", fail("Cannot create the secret directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return "", fail("Secret directory must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the search bit
		return "", fail("Cannot secure the secret directory")
	}
	return dir, nil
}

func ldapSetPassword(dir string, p parsed, o IO) error {
	var raw []byte
	if p.flags["--stdin"] {
		data, err := readLimited(o.Stdin, maxLDAPPassword)
		if err != nil {
			return err
		}
		raw = bytes.TrimRight(data, "\r\n")
	} else {
		pr := newPrompter(o)
		first, err := pr.getpass("LDAP bind password: ")
		if err == nil {
			var second string
			if second, err = pr.getpass("Repeat LDAP bind password: "); err == nil && first != second {
				return fail("Passwords do not match")
			}
		}
		if err != nil {
			// Click's main turns the EOFError of getpass into Abort after
			// a line break on stderr.
			writeLine(o.Stderr, "")
			return errAbort
		}
		raw = []byte(first)
	}
	if len(raw) == 0 || len(raw) > maxLDAPPassword || bytes.IndexByte(raw, 0) >= 0 {
		return fail("Password is empty or invalid")
	}
	if !utf8.Valid(raw) {
		return fail("Password must be valid UTF-8")
	}
	if err := atomicWrite(dir, ldapPasswordFile, raw); err != nil {
		return err
	}
	writeLine(o.Stdout, "LDAP bind password stored securely.")
	return nil
}

func ldapInstallCA(dir string, p parsed, o IO) error {
	fromStdin := p.flags["--stdin"]
	var pemFile string
	if len(p.args) > 0 {
		pemFile = p.args[0]
		if _, err := os.Stat(pemFile); err != nil {
			return &usageError{msg: fmt.Sprintf("Invalid value for '[PEM_FILE]': Path '%s' does not exist.", pemFile), withUsage: true}
		}
	}
	if fromStdin == (len(p.args) > 0) {
		return fail("Use exactly one of --stdin or PEM_FILE")
	}
	var raw []byte
	var err error
	if fromStdin {
		raw, err = readLimited(o.Stdin, maxLDAPCA)
	} else {
		raw, err = readCAFile(pemFile)
	}
	if err != nil {
		return err
	}
	if !validCABundle(raw) {
		return fail("CA bundle is not valid PEM certificate data")
	}
	if err := atomicWrite(dir, ldapCAFile, raw); err != nil {
		return err
	}
	writeLine(o.Stdout, "LDAP CA bundle installed securely.")
	return nil
}

func readCAFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fail("Could not read the CA bundle")
	}
	if info.Size() > maxLDAPCA {
		return nil, fail("CA bundle exceeds the supported size limit")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- an administrator names the file on the command line
	if err != nil || len(raw) > maxLDAPCA {
		return nil, fail("Could not read the CA bundle")
	}
	return raw, nil
}

// validCABundle accepts what ssl.create_default_context(cadata=…) accepts
// for an ASCII PEM bundle: at least one certificate, and every
// certificate block parses. Text around the blocks and other block types
// are ignored, as OpenSSL does when it reads certificates.
func validCABundle(raw []byte) bool {
	for _, c := range raw {
		if c > 0x7f {
			return false
		}
	}
	found := false
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return found
		}
		if block.Type != "CERTIFICATE" && block.Type != "X509 CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		found = true
	}
}

func ldapStatus(dir string, _ parsed, o IO) error {
	for _, name := range []string{ldapPasswordFile, ldapCAFile} {
		state := "missing"
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
			state = "present"
		}
		writeLine(o.Stdout, name+": "+state)
	}
	return nil
}

func ldapRemove(dir string, p parsed, o IO) error {
	if !p.flags["--yes"] {
		ok, err := newPrompter(o).confirm("Remove LDAP bind password and CA bundle? [y/N]: ")
		if err != nil || !ok {
			return errAbort
		}
	}
	for _, name := range []string{ldapPasswordFile, ldapCAFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail("Could not remove %s", name)
		}
	}
	writeLine(o.Stdout, "LDAP secret files removed.")
	return nil
}

// confirm is click.confirm with the default "no": the prompt goes to
// stdout, "y" or "yes" confirm, "n", "no" or an empty line decline, and
// anything else asks again.
func (p *prompter) confirm(prompt string) (bool, error) {
	for {
		_, _ = io.WriteString(p.io.Stdout, prompt)
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		}
		writeLine(p.io.Stdout, "Error: invalid input")
	}
}

func readLimited(r io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fail("Could not read standard input")
	}
	if len(data) > limit {
		return nil, fail("Input exceeds the supported size limit")
	}
	return data, nil
}

// atomicWrite replaces dir/name with content, mode 0600: a temporary file
// in the same directory is written, synced and renamed, then the
// directory is synced.
func atomicWrite(dir, name string, content []byte) error {
	failed := fail("Could not write %s", name)
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return failed
	}
	tmpName := tmp.Name()
	err = errors.Join(tmp.Chmod(0o600), write(tmp, content), tmp.Sync(), tmp.Close())
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	if err == nil {
		err = errors.Join(os.Chmod(filepath.Join(dir, name), 0o600), syncDir(dir))
	}
	if err != nil {
		_ = os.Remove(tmpName)
		return failed
	}
	return nil
}

// syncDir makes a rename in dir durable. Windows cannot sync a
// directory, and Python skipped it there too.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) // #nosec G304 -- the secret directory
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func write(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
