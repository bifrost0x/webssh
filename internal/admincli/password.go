package admincli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

// Terminal is the controlling terminal: prompts are written to it and
// ReadPassword reads one line with echo turned off.
type Terminal interface {
	io.Writer
	ReadPassword() ([]byte, error)
	Close() error
}

// readPasswordFile reads a password from a file given with
// --password-file, with the checks of app/cli.py _read_password_file: the
// path must be a regular file and no symbolic link, it must not change
// while it is opened, it must hold valid UTF-8 within max bytes, and one
// trailing "\n" or "\r\n" is removed.
func readPasswordFile(path string, max int) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fail("Password file does not exist or is not readable.")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fail("Password file must not be a symbolic link.")
	}
	if !info.Mode().IsRegular() {
		return "", fail("Password file must be a regular file.")
	}
	f, err := os.Open(path) // #nosec G304 -- an administrator names the file on the command line
	if err != nil {
		return "", fail("Password file could not be read.")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", fail("Password file could not be read.")
	}
	if !opened.Mode().IsRegular() {
		return "", fail("Password file must be a regular file.")
	}
	if !os.SameFile(info, opened) {
		return "", fail("Password file changed while it was being opened.")
	}
	// Python reads max+3 bytes and refuses only when more follow; a
	// longer password is then refused by the password rule.
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+4))
	if err != nil {
		return "", fail("Password file could not be read.")
	}
	if len(data) > max+3 {
		return "", fail("Password must not exceed %d bytes when encoded as UTF-8.", max)
	}
	if !utf8.Valid(data) {
		return "", fail("Password file must contain valid UTF-8.")
	}
	s := string(data)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
		if len(s) > 0 && s[len(s)-1] == '\r' {
			s = s[:len(s)-1]
		}
	}
	return s, nil
}

// prompter asks for hidden input like Python's getpass.getpass: on the
// controlling terminal with echo off, or, without one, on standard input
// after the warning that the input may be echoed. Standard input is read
// with universal newlines, as Python's text-mode stdin does.
type prompter struct {
	io    IO
	stdin *bufio.Reader
}

func newPrompter(o IO) *prompter {
	return &prompter{io: o, stdin: bufio.NewReader(o.Stdin)}
}

// getpass asks once. io.EOF means the input ended before a line.
func (p *prompter) getpass(prompt string) (string, error) {
	if p.io.Terminal != nil {
		if t, err := p.io.Terminal(); err == nil {
			defer t.Close()
			if _, err := io.WriteString(t, prompt); err != nil {
				return "", err
			}
			b, err := t.ReadPassword()
			if err != nil {
				return "", err
			}
			_, err = io.WriteString(t, "\n")
			return string(b), err
		}
	}
	fmt.Fprintf(p.io.Stderr, "Warning: Password input may be echoed.\n%s", prompt)
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	_, err = io.WriteString(p.io.Stderr, "\n")
	return line, err
}

// readLine reads one line of standard input without its line end ("\n",
// "\r\n" or "\r"). A last line without a line end counts; io.EOF means
// nothing was left.
func (p *prompter) readLine() (string, error) {
	var b []byte
	for {
		c, err := p.stdin.ReadByte()
		switch {
		case errors.Is(err, io.EOF) && len(b) > 0:
			return string(b), nil
		case err != nil:
			return "", err
		case c == '\n':
			return string(b), nil
		case c == '\r':
			if next, err := p.stdin.Peek(1); err == nil && next[0] == '\n' {
				_, _ = p.stdin.ReadByte()
			}
			return string(b), nil
		}
		b = append(b, c)
	}
}

// clickPassword is click.prompt(text, hide_input=True,
// confirmation_prompt=True): empty input asks again, a mismatch prints
// "Error: The two entered values do not match." on stdout and starts over,
// and the end of the input aborts after a line break on stdout.
func (p *prompter) clickPassword(text string) (string, error) {
	for {
		first, err := p.nonEmpty(text + ": ")
		if err != nil {
			return "", err
		}
		second, err := p.nonEmpty("Repeat for confirmation: ")
		if err != nil {
			return "", err
		}
		if first == second {
			return first, nil
		}
		writeLine(p.io.Stdout, "Error: The two entered values do not match.")
	}
}

func (p *prompter) nonEmpty(prompt string) (string, error) {
	for {
		v, err := p.getpass(prompt)
		if err != nil {
			writeLine(p.io.Stdout, "")
			return "", errAbort
		}
		if v != "" {
			return v, nil
		}
	}
}
