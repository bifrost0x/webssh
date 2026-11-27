package hostops

import (
	"context"
	_ "embed"
	json "encoding/json/v2"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// The fixed collector programs, byte for byte those of the Python release
// (app/session_insights.py, app/runtime_inventory.py; the differential
// test compares them). They travel on stdin and are run by sh.
var (
	//go:embed scripts/insights_stats.sh
	insightsStatsProgram string
	//go:embed scripts/insights_diagnostics.sh
	insightsDiagnosticsProgram string
	//go:embed scripts/runtime_inventory.sh
	inventoryProgram string
)

// Limits and rates of the collectors (REQUEST_RATE_LIMIT, DEFAULT_TIMEOUT
// of the Python modules).
const (
	insightsTimeout  = 2 * time.Second
	inventoryTimeout = 2 * time.Second
	insightsPerMin   = 30
	inventoryPerMin  = 10
	maxSampleID      = 128
)

// Diagnostics serves session insights (C-OPS-01), the runtime inventory
// (C-OPS-02) and the Herdr snapshot (C-OPS-09) of the caller's connected
// sessions on the realtime endpoint. Every sample runs a fixed program on
// a separate channel of the session's connection; nothing the browser
// sends reaches a command line.
type Diagnostics struct {
	Sessions Sessions
	Switches Switches
	Herdr    HerdrOverview
	Log      *slog.Logger
	// HerdrPerMinute is the snapshot budget of one account
	// (max(30, MAX_SOCKET_CONNECTIONS_PER_USER * 12)); 30 when zero.
	HerdrPerMinute int
	now            func() time.Time

	insightsRate, inventoryRate, herdrRate rateWindow
	insightsBusy, inventoryBusy            busySet
	herdr                                  herdrState
}

func (d *Diagnostics) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func (d *Diagnostics) init() {
	d.insightsRate.limit, d.insightsRate.window = insightsPerMin, time.Minute
	d.inventoryRate.limit, d.inventoryRate.window = inventoryPerMin, time.Minute
	d.herdrRate.limit, d.herdrRate.window = max(30, d.HerdrPerMinute), time.Minute
}

// Routes are insights.sample, inventory.sample and herdr.snapshot.
func (d *Diagnostics) Routes() []protocol.Route {
	d.init()
	spec := protocol.Spec{Async: true, MaxPayload: protocol.SessionSampleMaxPayload, Timeout: 20 * time.Second}
	return []protocol.Route{
		protocol.Handle(protocol.TypeInsightsSample, spec, d.handleInsights),
		protocol.Handle(protocol.TypeInventorySample, spec, d.handleInventory),
		protocol.Handle(protocol.TypeHerdrSnapshot, spec, d.handleHerdr),
	}
}

func validSampleID(s string) bool { return s != "" && len(s) <= maxSampleID }

func (d *Diagnostics) handleInsights(ctx context.Context, _ protocol.Peer, req protocol.InsightsSample) (protocol.InsightsResult, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.InsightsResult{}, err
	}
	fail := protocol.InsightsResult{Error: "Session insights unavailable"}
	if !validSampleID(req.SessionID) || !validSampleID(req.RequestID) {
		return fail, nil
	}
	fail.SessionID, fail.RequestID = req.SessionID, req.RequestID
	if !d.insightsRate.allow(p.UserID, d.clock()) {
		return fail, nil
	}
	live, ok := d.Sessions.Live(p.UserID, req.SessionID)
	if !ok {
		d.log().Warn("Unauthorized session insights request", "user_id", p.UserID)
		return fail, nil
	}
	stats, reason := d.collectStats(ctx, req.SessionID, live, req.IncludeDiagnostics)
	if reason != "" {
		fail.Reason = reason
		return fail, nil
	}
	raw, err := json.Marshal(stats)
	if err != nil {
		return protocol.InsightsResult{}, err
	}
	return protocol.InsightsResult{Success: true, SessionID: req.SessionID, RequestID: req.RequestID, Stats: raw}, nil
}

// collectStats is collect_linux_stats: one sample or the reason it is
// missing (busy, transient, unsupported, resource_shortage). A sample cut
// by the deadline is parsed as far as it got.
func (d *Diagnostics) collectStats(ctx context.Context, sessionID string, live Live, diagnostics bool) (Stats, string) {
	if !d.insightsBusy.take(sessionID) {
		return Stats{}, "busy"
	}
	defer d.insightsBusy.release(sessionID)
	program := insightsStatsProgram
	if diagnostics {
		program = insightsDiagnosticsProgram
	}
	cmd, err := remotecmd.Program(program)
	if err != nil || live.Exec == nil {
		return Stats{}, "transient"
	}
	cmd.Timeout, cmd.MaxOutput = insightsTimeout, insightsMaxBytes+1
	sctx, cancel := sessionContext(ctx, live.Done, nil)
	defer cancel()
	res, err := remotecmd.Run(sctx, live.Exec, cmd)
	switch {
	case err == nil:
		if res.ExitStatus != 0 {
			return Stats{}, "unsupported"
		}
	case fault.Is(err, fault.Timeout) && len(res.Stdout) > 0:
	case fault.Is(err, fault.ChannelRejected):
		d.log().Info("Diagnostics temporarily unavailable because the remote SSH server reported insufficient capacity for an additional channel", "session_id", sessionID)
		return Stats{}, "resource_shortage"
	default:
		return Stats{}, "transient"
	}
	if res.Truncated || len(res.Stdout) > insightsMaxBytes || !utf8.Valid(res.Stdout) {
		return Stats{}, "unsupported"
	}
	stats, err := ParseStats(string(res.Stdout))
	if err != nil {
		return Stats{}, "unsupported"
	}
	return stats, ""
}

func (d *Diagnostics) handleInventory(ctx context.Context, _ protocol.Peer, req protocol.InventorySample) (protocol.InventoryResult, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.InventoryResult{}, err
	}
	fail := protocol.InventoryResult{Error: "Runtime inventory unavailable"}
	if !validSampleID(req.SessionID) || !validSampleID(req.RequestID) {
		return fail, nil
	}
	fail.SessionID, fail.RequestID = req.SessionID, req.RequestID
	if !d.inventoryRate.allow(p.UserID, d.clock()) {
		return fail, nil
	}
	live, ok := d.Sessions.Live(p.UserID, req.SessionID)
	if !ok {
		d.log().Warn("Unauthorized runtime inventory request", "user_id", p.UserID)
		return fail, nil
	}
	inv, ok := d.collectInventory(ctx, req.SessionID, live)
	if !ok {
		return fail, nil
	}
	out := protocol.InventoryResult{Success: true, SessionID: req.SessionID, RequestID: req.RequestID,
		SampledAt: d.clock().Unix(), PermissionDenied: inv.PermissionDenied}
	if inv.Systemd != nil {
		out.Systemd, _ = json.Marshal(inv.Systemd)
	}
	if inv.Docker != nil {
		out.Docker, _ = json.Marshal(inv.Docker)
	}
	return out, nil
}

// collectInventory is collect_runtime_inventory: any failure, stderr
// output or more than 64 KiB in both streams is "unavailable".
func (d *Diagnostics) collectInventory(ctx context.Context, sessionID string, live Live) (RuntimeInventory, bool) {
	if !d.inventoryBusy.take(sessionID) {
		return RuntimeInventory{}, false
	}
	defer d.inventoryBusy.release(sessionID)
	cmd, err := remotecmd.Program(inventoryProgram)
	if err != nil || live.Exec == nil {
		return RuntimeInventory{}, false
	}
	cmd.Timeout, cmd.MaxOutput, cmd.MaxStderr = inventoryTimeout, inventoryMaxBytes+1, inventoryMaxBytes+1
	sctx, cancel := sessionContext(ctx, live.Done, nil)
	defer cancel()
	res, err := remotecmd.Run(sctx, live.Exec, cmd)
	if err != nil || res.ExitStatus != 0 || len(res.Stderr) > 0 ||
		len(res.Stdout)+len(res.Stderr) > inventoryMaxBytes || !utf8.Valid(res.Stdout) {
		return RuntimeInventory{}, false
	}
	inv, err := ParseInventory(string(res.Stdout))
	return inv, err == nil
}

func (d *Diagnostics) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}
