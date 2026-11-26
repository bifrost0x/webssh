package config

import (
	"fmt"
	"math"
	"math/big"
	"slices"
)

// parser reads variables in the order config.py does. The first error
// stops it, as the first raise stops the Python import; later calls are
// no-ops that return zero values.
type parser struct {
	get   LookupFunc
	err   error
	warns []Warning
	// view records every value under the name of its Python constant, so
	// the differential tests can compare it with config.py.
	view map[string]any
}

func newParser(get LookupFunc) *parser {
	return &parser{get: get, view: map[string]any{}}
}

func (p *parser) failed() bool { return p.err != nil }

func (p *parser) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

func (p *parser) warn(kind WarningKind, variable, format string, args ...any) {
	p.warns = append(p.warns, Warning{Kind: kind, Variable: variable, Message: fmt.Sprintf(format, args...)})
}

func (p *parser) record(constant string, v any) {
	if !p.failed() {
		p.view[constant] = v
	}
}

// raw is os.environ.get(name, def).
func (p *parser) raw(name, def string) string {
	if v, ok := p.get(name); ok {
		return v
	}
	return def
}

func (p *parser) present(name string) bool {
	_, ok := p.get(name)
	return ok
}

// flag is os.environ.get(name, def).lower() == 'true', recorded as
// constant. A value other than true or false keeps its Python meaning
// (false) and is reported.
func (p *parser) flag(constant, name, def string) bool {
	if p.failed() {
		return false
	}
	v, ok := p.get(name)
	if !ok {
		v = def
	}
	result := pyIsTrue(v)
	// An empty value (Compose "X=${X:-}") is worth a warning only where
	// it turns a default of true into false.
	if ok && !result && pyLower(v) != "false" && (v != "" || pyIsTrue(def)) {
		p.warn(WarnQuirk, name, "the value %q counts as false, as in the Python release; write true or false", v)
	}
	p.record(constant, result)
	return result
}

// adminSwitch is _admin_switch_env: blank means not supplied.
func (p *parser) adminSwitch(name string, def bool) Switch {
	if p.failed() {
		return Switch{}
	}
	v := pyStrip(p.raw(name, ""))
	s := Switch{Value: def}
	if v != "" {
		s = Switch{Value: pyLower(v) == "true", Locked: true}
		if !s.Value && pyLower(v) != "false" {
			p.warn(WarnQuirk, name, "the value %q counts as false, as in the Python release; write true or false", v)
		}
	}
	p.record(name, s.Value)
	return s
}

// str is os.environ.get(name, def), optionally stripped.
func (p *parser) str(constant, name, def string, strip bool) string {
	if p.failed() {
		return ""
	}
	v := p.raw(name, def)
	if strip {
		v = pyStrip(v)
	}
	p.record(constant, v)
	return v
}

// integer is _parse_int_env: Python's int() on the value (or on the
// default when absent), then valid. The error text is the Python one.
// Python integers have no size limit, so the value stays a big.Int here.
func (p *parser) integer(constant, name string, def *big.Int, requirement string, valid func(*big.Int) bool) *big.Int {
	if p.failed() {
		return new(big.Int)
	}
	raw, ok := p.get(name)
	if !ok {
		raw = def.String()
	}
	v, parsed := pyInt(raw)
	if !parsed || valid != nil && !valid(v) {
		p.fail(configError(name, fmt.Sprintf("CONFIGURATION ERROR: %s must be %s", name, requirement)))
		return new(big.Int)
	}
	if ok && !canonicalInt(raw, v) {
		p.warn(WarnQuirk, name, "the value %q is read as %s, as in the Python release", raw, v)
	}
	p.record(constant, v.String())
	return v
}

// saturate converts a Python integer for use in Go. Every limit the
// preview acts on is bounded far below the int64 range.
func saturate(v *big.Int) int64 {
	switch {
	case v.IsInt64():
		return v.Int64()
	case v.Sign() > 0:
		return math.MaxInt64
	default:
		return math.MinInt64
	}
}

func isPositive(v *big.Int) bool { return v.Sign() > 0 }

func (p *parser) positiveBig(name string, def *big.Int) *big.Int {
	return p.integer(name, name, def, "a positive integer", isPositive)
}

func (p *parser) positive(name string, def int64) int64 {
	return saturate(p.positiveBig(name, big.NewInt(def)))
}

func (p *parser) nonNegative(name string, def int64) int64 {
	return saturate(p.integer(name, name, big.NewInt(def), "a non-negative integer", func(v *big.Int) bool { return v.Sign() >= 0 }))
}

// anyInt is _int_env: any integer keeps its meaning.
func (p *parser) anyInt(name string, def int64) int64 {
	return saturate(p.integer(name, name, big.NewInt(def), "an integer number of bytes", nil))
}

func (p *parser) boundedBig(name string, def, minimum, maximum *big.Int) *big.Int {
	return p.integer(name, name, def, fmt.Sprintf("between %s and %s", minimum, maximum), func(v *big.Int) bool {
		return v.Cmp(minimum) >= 0 && v.Cmp(maximum) <= 0
	})
}

func (p *parser) bounded(name string, def, minimum, maximum int64) int64 {
	return saturate(p.boundedBig(name, big.NewInt(def), big.NewInt(minimum), big.NewInt(maximum)))
}

// csvSet is _csv_env (a frozenset of stripped, non-empty entries).
func (p *parser) csvSet(constant, name string, normalize func(string) string) []string {
	if p.failed() {
		return nil
	}
	v := pyCSVSet(p.raw(name, ""), normalize)
	p.record(constant, setView(v))
	return v
}

// csvList is a tuple or list of stripped, non-empty entries, duplicates
// kept.
func (p *parser) csvList(constant, name string) []string {
	if p.failed() {
		return nil
	}
	v := pyCSV(p.raw(name, ""))
	p.record(constant, listView(v))
	return v
}

// setView and listView give the differential tests the form the Python
// oracle writes: a set is {"$set": sorted entries}.
func setView(v []string) map[string]any {
	sorted := slices.Clone(v)
	slices.Sort(sorted)
	return map[string]any{"$set": listView(sorted)}
}

func listView(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
