package config

import (
	"errors"
	"strings"
)

// The interpolation of python-dotenv (dotenv/variables.py and
// resolve_variables in dotenv/main.py).

// maxDotenvExpansion bounds the sum of the interpolated values of a .env
// file. A value may name earlier values more than once, so a file of a
// few hundred bytes could otherwise expand to gigabytes (RS8-04).
// python-dotenv has no bound; a file that reaches it stops the start.
const maxDotenvExpansion = maxDotenvSize

var errDotenvExpansion = errors.New("the interpolated values are larger than 4 MiB")

// interpolateDotenv is resolve_variables with override=False: ${NAME} and
// ${NAME:-default} take the environment first, then the values of earlier
// statements. A statement without "=" defines NAME without a value, which
// then expands to "" without its default, as in python-dotenv. budget is
// what the values of the file may still add up to; interpolateDotenv
// takes the length of the result from it.
func interpolateDotenv(value string, env LookupFunc, earlier map[string]*string, budget *int) (string, error) {
	if !strings.Contains(value, "${") {
		return value, spend(budget, len(value))
	}
	s := []rune(value)
	next := newDotenvScan(s)
	var b strings.Builder
	for i := 0; i < len(s); {
		name, def, hasDef, end, ok := next.variable(i)
		if !ok {
			b.WriteRune(s[i])
			i++
			continue
		}
		var add string
		switch v, set := env(name); {
		case set:
			add = v
		default:
			if p, defined := earlier[name]; defined {
				if p != nil {
					add = *p
				}
			} else if hasDef {
				add = def
			}
		}
		if b.Len()+len(add) > *budget {
			return "", errDotenvExpansion
		}
		b.WriteString(add)
		i = end
	}
	return b.String(), spend(budget, b.Len())
}

func spend(budget *int, n int) error {
	if n > *budget {
		return errDotenvExpansion
	}
	*budget -= n
	return nil
}

// dotenvScan finds the variables of one value. next[i] is the position of
// the first '}' at or after i and stop[i] that of the first '}' or ':',
// len(s) for none, so that a match costs constant time and a value full of
// unclosed "${" is scanned once instead of once per "${".
type dotenvScan struct {
	s          []rune
	next, stop []int
}

func newDotenvScan(s []rune) dotenvScan {
	n := len(s)
	next := make([]int, n+1)
	stop := make([]int, n+1)
	next[n], stop[n] = n, n
	for i := n - 1; i >= 0; i-- {
		next[i], stop[i] = next[i+1], stop[i+1]
		switch s[i] {
		case '}':
			next[i], stop[i] = i, i
		case ':':
			stop[i] = i
		}
	}
	return dotenvScan{s: s, next: next, stop: stop}
}

// variable matches \$\{(?P<name>[^\}:]*)(?::-(?P<default>[^\}]*))?\} at
// position i.
func (d dotenvScan) variable(i int) (name, def string, hasDef bool, end int, ok bool) {
	s := d.s
	if i+1 >= len(s) || s[i] != '$' || s[i+1] != '{' {
		return "", "", false, 0, false
	}
	// The name is copied only once the match is certain: copying it first
	// made every unclosed "${" cost the rest of the value.
	j := d.stop[i+2]
	if j < len(s) && s[j] == '}' {
		return string(s[i+2 : j]), "", false, j + 1, true
	}
	if j+1 >= len(s) || s[j] != ':' || s[j+1] != '-' {
		return "", "", false, 0, false
	}
	k := d.next[j+2]
	if k >= len(s) {
		return "", "", false, 0, false
	}
	return string(s[i+2 : j]), string(s[j+2 : k]), true, k + 1, true
}
