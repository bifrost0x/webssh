package legacy

import (
	"context"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// Group places a step in the dependency order of section 5.2 step 7.
// Steps run group by group, and in registration order within a group.
type Group int

// Groups in dependency order.
const (
	GroupAccounts Group = iota
	GroupFactors
	GroupSettings
	GroupKeys
	GroupHosts
	GroupHostTrust
	GroupCommands
	GroupHostContext
	GroupAutomation
	GroupTerminal
	// GroupInventory holds steps that only account for legacy paths left
	// in place.
	GroupInventory
)

// Entities are the entity IDs of the migration specification, section 3:
// E01 to E41 and A01 to A13.
var Entities = func() []string {
	ids := make([]string, 0, 54)
	for i := 1; i <= 41; i++ {
		ids = append(ids, fmt.Sprintf("E%02d", i))
	}
	for i := 1; i <= 13; i++ {
		ids = append(ids, fmt.Sprintf("A%02d", i))
	}
	return ids
}()

// Registry holds the migration steps and the entities kept in place. A
// run creates fresh steps from the factories, so a registry can serve a
// dry run and a migration one after the other.
type Registry struct {
	steps   []registered
	pending []pendingEntity
	schemas []store.Schema
}

type registered struct {
	group   Group
	entity  string
	version int
	newStep func() Step
}

type pendingEntity struct {
	entity, phase string
	count         func(ctx context.Context, src *Source) (int, error)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Add registers a step. newStep is called once per run. An entity can be
// registered only once, as a step or as pending.
func (r *Registry) Add(g Group, newStep func() Step) error {
	s := newStep()
	if err := r.claim(s.Entity()); err != nil {
		return err
	}
	r.steps = append(r.steps, registered{group: g, entity: s.Entity(), version: s.Version(), newStep: newStep})
	return nil
}

// KeepInPlace registers an entity that this build leaves in the legacy
// data (KEEP-IN-PLACE) and that phase will migrate. count reports how
// many records the legacy source holds; the report names the entity with
// that number.
func (r *Registry) KeepInPlace(entity, phase string, count func(ctx context.Context, src *Source) (int, error)) error {
	if phase == "" || count == nil {
		return fmt.Errorf("legacy: pending entity %s needs a phase and a count", entity)
	}
	if err := r.claim(entity); err != nil {
		return err
	}
	r.pending = append(r.pending, pendingEntity{entity: entity, phase: phase, count: count})
	return nil
}

func (r *Registry) claim(entity string) error {
	if !slices.Contains(Entities, entity) {
		return fmt.Errorf("legacy: %q is not an entity of the migration specification", entity)
	}
	if slices.Contains(r.Covered(), entity) {
		return fmt.Errorf("legacy: entity %s is registered twice", entity)
	}
	return nil
}

// Schemas registers capability schemas that the staging database needs
// before the steps write. A schema registered twice is applied once.
func (r *Registry) Schemas(schemas ...store.Schema) {
	for _, s := range schemas {
		if !slices.ContainsFunc(r.schemas, func(o store.Schema) bool { return o.Owner == s.Owner }) {
			r.schemas = append(r.schemas, s)
		}
	}
}

// Covered lists the entities registered as a step or as pending.
func (r *Registry) Covered() []string {
	var out []string
	for _, s := range r.steps {
		out = append(out, s.entity)
	}
	for _, p := range r.pending {
		out = append(out, p.entity)
	}
	return out
}

// Uncovered lists the entities of the specification that are neither a
// step nor pending, for completeness tests of a build's registry.
func (r *Registry) Uncovered() []string {
	covered := r.Covered()
	var out []string
	for _, e := range Entities {
		if !slices.Contains(covered, e) {
			out = append(out, e)
		}
	}
	return out
}

// coverage is the coverage list of the migration record.
func (r *Registry) coverage() []Coverage {
	out := []Coverage{}
	for _, s := range r.ordered() {
		out = append(out, Coverage{Entity: s.entity, Version: s.version, Kind: CoverStep})
	}
	for _, p := range r.pending {
		out = append(out, Coverage{Entity: p.entity, Kind: CoverPending})
	}
	return out
}

// ordered returns the steps in dependency order.
func (r *Registry) ordered() []registered {
	out := slices.Clone(r.steps)
	slices.SortStableFunc(out, func(a, b registered) int { return int(a.group) - int(b.group) })
	return out
}

// instantiate creates the steps of one run in dependency order and checks
// that every factory returns the entity and version it was registered
// with.
func (r *Registry) instantiate() ([]Step, error) {
	var steps []Step
	for _, reg := range r.ordered() {
		s := reg.newStep()
		if s.Entity() != reg.entity || s.Version() != reg.version {
			return nil, fmt.Errorf("legacy: step factory for %s returned %s version %d", reg.entity, s.Entity(), s.Version())
		}
		steps = append(steps, s)
	}
	return steps, nil
}

// countPending counts the records of every pending entity.
func (r *Registry) countPending(ctx context.Context, src *Source) ([]Pending, error) {
	out := []Pending{}
	for _, p := range r.pending {
		n, err := p.count(ctx, src)
		if err != nil {
			return nil, &StopError{Code: CodeStepFailed, Entity: p.entity, Message: "the legacy records kept in place could not be counted", Err: err}
		}
		out = append(out, Pending{Entity: p.entity, Phase: p.phase, Count: n})
	}
	return out, nil
}
