package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DotenvName is the file the Python release loads from its installation
// directory (config.py: load_dotenv(BASE_DIR / '.env')).
const DotenvName = ".env"

// maxDotenvSize bounds the .env file. python-dotenv reads any size; a
// larger file stops the start instead of filling the memory.
const maxDotenvSize = 4 << 20

// DotenvFile is the .env file of this installation: next to the binary,
// where the Python release kept it next to config.py. In the image that is
// /app/.env, in a source installation the checkout the binary was built
// into.
func DotenvFile() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("config: locate the binary for %s: %w", DotenvName, err)
	}
	return filepath.Join(filepath.Dir(exe), DotenvName), nil
}

// dotenvDisabled is python-dotenv's PYTHON_DOTENV_DISABLED check: the
// casefolded value is 1, true, t, yes or y. U+017F (long s) is the only
// code point outside ASCII that casefolds into one of them.
func dotenvDisabled(lookup LookupFunc) bool {
	v, ok := lookup("PYTHON_DOTENV_DISABLED")
	if !ok {
		return false
	}
	v = strings.ReplaceAll(v, "ſ", "s")
	if !isASCII(v) {
		return false
	}
	switch strings.ToLower(v) {
	case "1", "true", "t", "yes", "y":
		return true
	}
	return false
}

// ReadDotenv reads path as load_dotenv(path) does with override=False and
// returns the variables it adds to the environment lookup describes: a
// variable that is set, even to an empty value, keeps its value. A missing
// file, or one that is neither a regular file nor a FIFO, adds nothing.
// Statements python-dotenv cannot parse are skipped and reported. The
// file stops the start where the Python release stops: invalid UTF-8, a
// file that cannot be read, or a name or value the environment refuses.
func ReadDotenv(path string, lookup LookupFunc) ([]EnvAssignment, []Warning, error) {
	if dotenvDisabled(lookup) {
		return nil, nil, nil
	}
	data, err := readDotenvFile(path)
	if err != nil || data == nil {
		return nil, nil, err
	}
	out, bad, err := parseDotenv(data, lookup)
	var warns []Warning
	for _, line := range bad {
		warns = append(warns, Warning{Kind: WarnDotenv, Message: fmt.Sprintf("%s: the statement starting at line %d cannot be parsed and is ignored", path, line)})
	}
	if err != nil {
		return nil, warns, configError("", fmt.Sprintf("CONFIGURATION ERROR: %s: %v", path, err))
	}
	if len(out) > 0 {
		warns = append(warns, Warning{Kind: WarnDotenv, Message: fmt.Sprintf("%d variables were read from %s; variables set in the environment take precedence", len(out), path)})
	}
	return out, warns, nil
}

func readDotenvFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() && info.Mode()&fs.ModeNamedPipe == 0 {
		// _is_file_or_fifo: anything else counts as no file.
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- the .env file of the installation
	if err != nil {
		return nil, configError("", fmt.Sprintf("CONFIGURATION ERROR: %s cannot be read: %v", path, err))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDotenvSize+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, configError("", fmt.Sprintf("CONFIGURATION ERROR: %s cannot be read: %v", path, err))
	}
	if len(data) > maxDotenvSize {
		return nil, configError("", fmt.Sprintf("CONFIGURATION ERROR: %s is larger than %d bytes", path, maxDotenvSize))
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// LoadDotenv applies ReadDotenv to the process environment, so every
// later lookup sees the file. It runs once at process start, before any
// other goroutine reads the environment.
func LoadDotenv(path string) ([]Warning, error) {
	add, warns, err := ReadDotenv(path, os.LookupEnv)
	if err != nil {
		return warns, err
	}
	for _, a := range add {
		if err := os.Setenv(a.Name, a.Value); err != nil {
			return warns, configError(a.Name, fmt.Sprintf("CONFIGURATION ERROR: %s: %s cannot be set: %v", path, a.Name, err))
		}
	}
	return warns, nil
}
