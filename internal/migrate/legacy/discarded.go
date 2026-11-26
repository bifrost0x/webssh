package legacy

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// discardDef is an entity the migration does not import (DISCARD,
// decided in D-02): runtime and sign-in state that every user recreates
// by signing in once. The step only counts it for the report.
type discardDef struct {
	entity string
	note   string
	count  func(ctx context.Context, src *Source) (perUser map[int64]int, total int, err error)
}

var discardedEntities = []discardDef{
	{entity: "E09", note: "unfinished TOTP enrolments are not taken over; the users restart enrolment",
		count: perUserTables("totp_enrollments")},
	{entity: "E12", note: "browser sign-ins are not taken over; every user signs in once",
		count: perUserTables("authentication_sessions")},
	{entity: "E14", note: "connection records are not taken over; persistent tmux sessions are entity A01",
		count: func(ctx context.Context, src *Source) (map[int64]int, int, error) {
			per, total, err := perUserTables("socket_sessions")(ctx, src)
			if err != nil {
				return nil, 0, err
			}
			_, other, err := src.PersistentSessions(ctx)
			return per, total + other, err
		}},
	{entity: "E36", note: "pending access revocations are completed, because no session is taken over",
		count: func(_ context.Context, src *Source) (map[int64]int, int, error) {
			return nil, countRuntimeFiles(src, ".access-revocations"), nil
		}},
	{entity: "E38", note: "transfer temp files are ignored, as Python sweeps them at start",
		count: func(_ context.Context, src *Source) (map[int64]int, int, error) {
			return nil, countRuntimeFiles(src, "tmp"), nil
		}},
	{entity: "A03", note: "known sign-in devices lose their rate-limit exemption once",
		count: func(context.Context, *Source) (map[int64]int, int, error) { return nil, 0, nil }},
}

// perUserTables counts the rows of tables per user.
func perUserTables(tables ...string) func(context.Context, *Source) (map[int64]int, int, error) {
	return func(ctx context.Context, src *Source) (map[int64]int, int, error) {
		out, total := map[int64]int{}, 0
		for _, t := range tables {
			per, err := countPerUser(ctx, src, t)
			if err != nil {
				return nil, 0, err
			}
			for id, n := range per {
				out[id] += n
				total += n
			}
		}
		return out, total, nil
	}
}

type discardStep struct {
	def     discardDef
	perUser map[int64]int
	total   int
}

func (s *discardStep) Entity() string { return s.def.entity }

func (*discardStep) Version() int { return 1 }

func (s *discardStep) Read(ctx context.Context, src *Source) error {
	var err error
	s.perUser, s.total, err = s.def.count(ctx, src)
	return err
}

func (*discardStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*discardStep) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *discardStep) Report() StepReport {
	r := StepReport{Entity: s.def.entity, Version: 1, Read: s.total, Discarded: s.total, Notes: []string{s.def.note}}
	for _, id := range slices.Sorted(maps.Keys(s.perUser)) {
		r.Notes = append(r.Notes, fmt.Sprintf("user %d: %d discarded", id, s.perUser[id]))
	}
	return r
}
