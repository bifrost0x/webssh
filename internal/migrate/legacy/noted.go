package legacy

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// notedDef is an entity that needs no data step in this build: it is
// derived at run time, lives in the browser, is configuration, or is
// handled by the framework or by another step. The step records why in
// the report, and lists legacy paths it leaves in place.
type notedDef struct {
	entity string
	note   string
	kept   func(src *Source) ([]KeptPath, error)
}

var notedEntities = []notedDef{
	{entity: "E34", note: "application and audit logs stay in logs/; Go appends to the same files in the same line format",
		kept: func(src *Source) ([]KeptPath, error) {
			// An unreadable log directory does not stop the migration.
			files, _ := src.LogFiles()
			out := make([]KeptPath, 0, len(files))
			for _, f := range files {
				out = append(out, KeptPath{Path: f, Reason: "log"})
			}
			return out, nil
		}},
	{entity: "E40", note: "exported profile files are not part of DATA_DIR; importing them stays a feature of the host list"},
	{entity: "E41", note: "deployment configuration is read at every start, not migrated"},
	{entity: "A02", note: "SECRET_KEY is read only; it was checked against the stored secrets before anything was written"},
	{entity: "A08", note: "interrupted key deletions are reconciled with entity E23; .bak and .tmp files in keys/ stay in place"},
	{entity: "A09", note: "ADMIN_USERS is applied at run time (variant B); the start-up rules were applied with entity E01"},
	{entity: "A12", note: "favourites, scrollback and topology layout stay in the browser; entity A04 keeps their namespace"},
	{entity: "A13", note: "discovery and reachability rights are written with the derived settings (materialised_settings)"},
}

type notedStep struct {
	def  notedDef
	kept []KeptPath
}

func (s *notedStep) Entity() string { return s.def.entity }

func (*notedStep) Version() int { return 1 }

func (s *notedStep) Read(_ context.Context, src *Source) error {
	if s.def.kept == nil {
		return nil
	}
	var err error
	s.kept, err = s.def.kept(src)
	return err
}

func (*notedStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*notedStep) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *notedStep) Report() StepReport {
	return StepReport{Entity: s.def.entity, Version: 1, Read: len(s.kept), Notes: []string{s.def.note}, KeptInPlace: s.kept}
}
