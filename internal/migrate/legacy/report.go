package legacy

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Report is the migration report (migration specification, section 5.5):
// JSON, UTF-8, mode 0600, also stored in the migration record. It holds
// no secret value, plaintext, password, token or code hash.
type Report struct {
	Format               string                `json:"format"`
	Version              int                   `json:"version"`
	GoRelease            string                `json:"go_release"`
	StartedAt            string                `json:"started_at"`
	FinishedAt           string                `json:"finished_at"`
	Result               string                `json:"result"`
	Source               ReportSource          `json:"source"`
	LegacyUntouched      Untouched             `json:"legacy_untouched"`
	Entities             []StepReport          `json:"entities"`
	Coverage             []Coverage            `json:"coverage"`
	Pending              []Pending             `json:"pending"`
	MaterialisedSettings []MaterialisedSetting `json:"materialised_settings"`
	KeptInPlace          []KeptPath            `json:"kept_in_place"`
	PendingUserActions   []UserAction          `json:"pending_user_actions"`
	Warnings             []Warning             `json:"warnings"`
	ReplacedDatabase     string                `json:"replaced_database,omitzero"`
	Error                *ReportError          `json:"error"`
}

// Results of a report.
const (
	ResultCompleted = "completed"
	ResultFailed    = "failed"
	ResultDryRun    = "dry-run"
)

// ReportSource describes the legacy source.
type ReportSource struct {
	DataDir         string           `json:"data_dir"`
	Digest          string           `json:"digest"`
	Files           int              `json:"files"`
	SchemaShape     SchemaShape      `json:"schema_shape"`
	Tables          map[string]int64 `json:"tables"`
	SecretKeySource string           `json:"secret_key_source"`
	SecretChecked   bool             `json:"secret_key_checked"`
}

// SchemaShape is the detected shape of app.db (section 5.2 step 3).
type SchemaShape struct {
	Tables             []string `json:"tables"`
	MissingUserColumns []string `json:"missing_user_columns,omitzero"`
	Indexes            int      `json:"indexes"`
	Triggers           []string `json:"triggers,omitzero"`
	Views              []string `json:"views,omitzero"`
	Other              []string `json:"other,omitzero"`
}

func shapeOf(sc Schema) SchemaShape {
	shape := SchemaShape{Indexes: len(sc.Indexes), Triggers: sc.Triggers, Views: sc.Views, Other: sc.Other,
		MissingUserColumns: sc.MissingUserColumns()}
	for name := range sc.Tables {
		shape.Tables = append(shape.Tables, name)
	}
	slices.Sort(shape.Tables)
	return shape
}

// Untouched is the proof that the legacy source did not change.
type Untouched struct {
	DigestBefore string `json:"digest_before"`
	DigestAfter  string `json:"digest_after"`
	Equal        bool   `json:"equal"`
}

// Coverage is one entity the migration accounts for, with the version of
// its step (section 2.2 of the M1 contracts).
type Coverage struct {
	Entity  string `json:"entity"`
	Version int    `json:"version,omitzero"`
	Kind    string `json:"kind"`
}

// Coverage kinds.
const (
	CoverStep    = "step"
	CoverPending = "keep_in_place_pending"
)

// ReportError is the error of a failed migration.
type ReportError struct {
	Entity  string `json:"entity,omitzero"`
	UserID  int64  `json:"user_id,omitzero"`
	Record  string `json:"record_id,omitzero"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newReport(release string, started time.Time, dataDir string) Report {
	return Report{
		Format: "webssh-migration-report", Version: 1, GoRelease: release,
		StartedAt: utcText(started), Source: ReportSource{DataDir: dataDir},
		Entities: []StepReport{}, Coverage: []Coverage{}, Pending: []Pending{},
		MaterialisedSettings: []MaterialisedSetting{}, KeptInPlace: []KeptPath{},
		PendingUserActions: []UserAction{}, Warnings: []Warning{},
	}
}

// add takes a step's report into the entity list and the summary lists.
func (r *Report) add(sr StepReport) {
	r.Entities = append(r.Entities, sr)
	r.MaterialisedSettings = append(r.MaterialisedSettings, sr.Settings...)
	r.KeptInPlace = append(r.KeptInPlace, sr.KeptInPlace...)
	r.PendingUserActions = append(r.PendingUserActions, sr.UserActions...)
	r.Warnings = append(r.Warnings, sr.Warnings...)
}

func (r *Report) fail(e *StopError) {
	r.Result = ResultFailed
	r.Error = &ReportError{Entity: e.Entity, UserID: e.UserID, Record: e.Record, Code: e.Code, Message: e.Message}
}

func utcText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// writeReportFile writes the report as <dir>/migration-report-<UTC>.json
// with mode 0600 and returns its path. The file is created exclusively and
// fsynced; a failure removes it.
func writeReportFile(dir string, r Report, now time.Time) (string, error) {
	data, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return "", fmt.Errorf("legacy: encode the report: %w", err)
	}
	path := filepath.Join(dir, reportPrefix+now.UTC().Format(utcStamp)+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a Go-owned file in the Go directory
	if err != nil {
		return "", fmt.Errorf("legacy: create the report: %w", err)
	}
	_, werr := f.Write(append(data, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return "", errors.Join(fmt.Errorf("legacy: write the report: %w", err), os.Remove(path))
	}
	return path, syncDir(dir)
}
