package hostops

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Pacing and limits of discovery (discovery_routes.py). A scan opens one
// TCP connection per address and port, under the same network policy as
// SSH, never sends data, reads only the greeting an SSH server sends on its
// own and closes the socket. New attempts are paced (about three per
// second, three in flight) so a scan does not flood the network; it is not
// hidden from monitoring.
const (
	scanStartInterval   = 300 * time.Millisecond
	scanInFlight        = 3
	scanConnectTimeout  = 1500 * time.Millisecond
	scanBannerTimeout   = 2 * time.Second
	scanReverseTimeout  = time.Second
	scanBannerLimit     = 255
	maxRunningScans     = 2
	scanResultRetention = 15 * time.Minute
)

// ReverseResolver names an address (net.Resolver provides it).
type ReverseResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Found is one SSH server a scan reached.
type Found struct {
	Address  string  `json:"address"`
	Port     int     `json:"port"`
	Software string  `json:"software"`
	Comment  string  `json:"comment"`
	Platform *string `json:"platform"`
	Name     *string `json:"name"`
	Known    bool    `json:"known"`
}

// ScanView is what the page polls.
type ScanView struct {
	ID         string   `json:"id"`
	Network    string   `json:"network"`
	State      string   `json:"state"` // running, done, cancelled
	Total      int      `json:"total"`
	Checked    int      `json:"checked"`
	Blocked    int      `json:"blocked"`
	Found      []Found  `json:"found"`
	StartedAt  float64  `json:"started_at"`
	FinishedAt *float64 `json:"finished_at"`
}

type target struct {
	addr netip.Addr
	port int
}

type scan struct {
	id, network string
	owner       int64
	sessionID   string
	targets     []target
	known       map[string]bool
	checked     int
	blocked     int
	found       []Found
	state       string
	started     time.Time
	finished    time.Time
	revoked     bool
	cancel      context.CancelFunc
}

// Scanner owns the discovery scans of the process. Results live in memory
// for 15 minutes after a scan ends and belong to the account that started
// the scan; other accounts get the answer as for no scan.
type Scanner struct {
	Dialer   TCPProber
	Resolver ReverseResolver
	Audit    Auditor
	Log      *slog.Logger
	now      func() time.Time
	interval time.Duration

	mu     sync.Mutex
	scans  map[string]*scan
	closed bool
	wg     sync.WaitGroup
}

func (s *Scanner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func unix(t time.Time) float64 { return float64(t.UnixMicro()) / 1e6 }

func (sc *scan) view() ScanView {
	v := ScanView{ID: sc.id, Network: sc.network, State: sc.state, Total: len(sc.targets), Checked: sc.checked,
		Blocked: sc.blocked, Found: slices.Clone(sc.found), StartedAt: unix(sc.started)}
	if v.Found == nil {
		v.Found = []Found{}
	}
	if !sc.finished.IsZero() {
		f := unix(sc.finished)
		v.FinishedAt = &f
	}
	return v
}

func newScanID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start begins a scan of the addresses and ports for p. known holds the
// saved endpoints of the account as "address|port" (lower case). The scan
// runs until it is done, cancelled, revoked or ctx ends.
func (s *Scanner) Start(ctx context.Context, p principal.Principal, network netip.Prefix, addrs []netip.Addr, ports []int, known map[string]bool) (ScanView, error) {
	sc := &scan{id: newScanID(), network: network.String(), owner: p.UserID, sessionID: p.SessionID,
		known: known, state: "running", started: s.clock()}
	for _, a := range addrs {
		for _, port := range ports {
			sc.targets = append(sc.targets, target{a, port})
		}
	}
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sc.cancel = cancel
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return ScanView{}, errNoWork
	}
	s.prune()
	running := 0
	for _, other := range s.scans {
		if !other.finished.IsZero() {
			continue
		}
		// A cancelled scan counts until its in-flight probes have ended.
		if other.owner == p.UserID {
			s.mu.Unlock()
			cancel()
			return ScanView{}, errScanRunning
		}
		running++
	}
	if running >= maxRunningScans {
		s.mu.Unlock()
		cancel()
		return ScanView{}, errScanBusy
	}
	if s.scans == nil {
		s.scans = map[string]*scan{}
	}
	s.scans[sc.id] = sc
	view := sc.view()
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer cancel()
		s.run(rctx, sc)
	}()
	if s.Audit != nil {
		s.Audit.Security("HOST_DISCOVERY_STARTED", "user_id", p.UserID, "network", sc.network,
			"addresses", len(addrs), "ports", ports)
	}
	return view, nil
}

func (s *Scanner) prune() {
	cutoff := s.clock().Add(-scanResultRetention)
	for id, sc := range s.scans {
		if !sc.finished.IsZero() && sc.finished.Before(cutoff) {
			delete(s.scans, id)
		}
	}
}

func (s *Scanner) run(ctx context.Context, sc *scan) {
	interval := s.interval
	if interval == 0 {
		interval = scanStartInterval
	}
	slots := make(chan struct{}, scanInFlight)
	var probes sync.WaitGroup
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for i, t := range sc.targets {
		if i > 0 {
			// Pacing: never start more than one attempt per interval.
			select {
			case <-ctx.Done():
			case <-ticker.C:
			}
		}
		if ctx.Err() != nil {
			break
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		probes.Go(func() {
			defer func() { <-slots }()
			s.record(ctx, sc, t, s.probe(ctx, t))
		})
	}
	probes.Wait()
	s.mu.Lock()
	if sc.state == "running" {
		sc.state = "done"
		if ctx.Err() != nil {
			sc.state = "cancelled"
		}
	}
	sc.finished = s.clock()
	state, checked, found, blocked := sc.state, sc.checked, len(sc.found), sc.blocked
	s.mu.Unlock()
	if s.Audit != nil {
		s.Audit.Security("HOST_DISCOVERY_FINISHED", "user_id", sc.owner, "network", sc.network, "state", state,
			"checked", checked, "found", found, "blocked", blocked)
	}
}

type probeOutcome struct {
	state  string // ssh, closed, blocked
	banner Banner
}

// probe connects under the network policy, reads the greeting and closes.
// It never sends anything.
func (s *Scanner) probe(ctx context.Context, t target) probeOutcome {
	dctx, cancel := context.WithTimeout(ctx, scanConnectTimeout)
	conn, err := s.Dialer.DialProbe(dctx, t.addr.String(), t.port)
	cancel()
	if err != nil {
		if refusedByPolicy(err) {
			return probeOutcome{state: "blocked"}
		}
		return probeOutcome{state: "closed"}
	}
	raw := readGreeting(ctx, conn, scanBannerLimit, scanBannerTimeout, func(b []byte) bool {
		return slices.Contains(b, '\n')
	})
	if b, ok := DescribeBanner(raw); ok {
		// Only SSH servers are results; other listeners are not reported.
		return probeOutcome{state: "ssh", banner: b}
	}
	return probeOutcome{state: "closed"}
}

func refusedByPolicy(err error) bool {
	code := fault.CodeOf(err)
	return code == fault.TargetBlocked || code == fault.TailnetRouteRestricted || code == fault.InvalidValue
}

var reverseName = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

func (s *Scanner) name(ctx context.Context, addr netip.Addr) *string {
	if s.Resolver == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, scanReverseTimeout)
	defer cancel()
	names, err := s.Resolver.LookupAddr(rctx, addr.String())
	if err != nil || len(names) == 0 {
		return nil
	}
	name := strings.TrimRight(names[0], ".")
	if !reverseName.MatchString(name) {
		return nil
	}
	return &name
}

func (s *Scanner) record(ctx context.Context, sc *scan, t target, out probeOutcome) {
	var entry *Found
	if out.state == "ssh" {
		address := t.addr.String()
		entry = &Found{Address: address, Port: t.port, Software: out.banner.Software, Comment: out.banner.Comment,
			Name: s.name(ctx, t.addr), Known: sc.known[knownKey(address, t.port)]}
		if out.banner.Platform != "" {
			entry.Platform = &out.banner.Platform
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc.checked++
	if out.state == "blocked" {
		sc.blocked++
	}
	if entry != nil && !sc.revoked {
		sc.found = append(sc.found, *entry)
		slices.SortFunc(sc.found, func(a, b Found) int {
			if c := netip.MustParseAddr(a.Address).Compare(netip.MustParseAddr(b.Address)); c != 0 {
				return c
			}
			return a.Port - b.Port
		})
	}
}

// knownKey is the form of a saved endpoint for Found.Known.
func knownKey(host string, port int) string {
	return strings.ToLower(host) + "|" + strconv.Itoa(port)
}

// View returns the scan id of p, or not_found.
func (s *Scanner) View(p principal.Principal, id string) (ScanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.scans[id]
	if sc == nil || sc.owner != p.UserID || sc.revoked {
		return ScanView{}, errScanGone
	}
	return sc.view(), nil
}

// Cancel stops the scan id of p and returns its view.
func (s *Scanner) Cancel(p principal.Principal, id string) (ScanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.scans[id]
	if sc == nil || sc.owner != p.UserID || sc.revoked {
		return ScanView{}, errScanGone
	}
	sc.cancel()
	if sc.state == "running" {
		sc.state = "cancelled"
	}
	return sc.view(), nil
}

// Revoked stops the scans of a revoked browser session and forgets their
// results; an account-wide revocation stops every scan of the account
// (cancel_for_authentication_sessions, cancel_for_user). Revoked scans stay
// counted until their probes have ended.
func (s *Scanner) Revoked(rev principal.Revocation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scans {
		if sc.owner != rev.UserID || (rev.SessionID != "" && sc.sessionID != rev.SessionID) {
			continue
		}
		sc.cancel()
		sc.revoked = true
		sc.found = nil
		if sc.state == "running" {
			sc.state = "cancelled"
		}
	}
}

// Shutdown stops every scan and waits until their probes have ended.
func (s *Scanner) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	for _, sc := range s.scans {
		sc.cancel()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
