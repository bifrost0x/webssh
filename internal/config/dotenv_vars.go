package config

import "strings"

// The interpolation of python-dotenv (dotenv/variables.py and
// resolve_variables in dotenv/main.py).

// interpolateDotenv is resolve_variables with override=False: ${NAME} and
// ${NAME:-default} take the environment first, then the values of earlier
// statements. A statement without "=" defines NAME without a value, which
// then expands to "" without its default, as in python-dotenv.
func interpolateDotenv(value string, env LookupFunc, earlier map[string]*string) string {
	s := []rune(value)
	var b strings.Builder
	for i := 0; i < len(s); {
		name, def, hasDef, end, ok := dotenvVariable(s, i)
		if !ok {
			b.WriteRune(s[i])
			i++
			continue
		}
		switch v, set := env(name); {
		case set:
			b.WriteString(v)
		default:
			if p, defined := earlier[name]; defined {
				if p != nil {
					b.WriteString(*p)
				}
			} else if hasDef {
				b.WriteString(def)
			}
		}
		i = end
	}
	return b.String()
}

// dotenvVariable matches \$\{(?P<name>[^\}:]*)(?::-(?P<default>[^\}]*))?\}
// at position i.
func dotenvVariable(s []rune, i int) (name, def string, hasDef bool, end int, ok bool) {
	if i+1 >= len(s) || s[i] != '$' || s[i+1] != '{' {
		return "", "", false, 0, false
	}
	j := i + 2
	for j < len(s) && s[j] != '}' && s[j] != ':' {
		j++
	}
	name = string(s[i+2 : j])
	if j < len(s) && s[j] == '}' {
		return name, "", false, j + 1, true
	}
	if j+1 >= len(s) || s[j] != ':' || s[j+1] != '-' {
		return "", "", false, 0, false
	}
	k := j + 2
	for k < len(s) && s[k] != '}' {
		k++
	}
	if k >= len(s) {
		return "", "", false, 0, false
	}
	return name, string(s[j+2 : k]), true, k + 1, true
}
