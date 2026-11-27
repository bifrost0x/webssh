package e2eseed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Options configure one harness run. The entry file reads them from the
// WEBSSH_E2E_* variables; this package does not read the environment.
type Options struct {
	SeedPath string
	Port     int
	// FastHashing selects cheap password hashing for the seeded accounts
	// (WEBSSH_E2E_FAST_HASHING=1). It only lowers test cost.
	FastHashing bool
	// Environ is the process environment the configuration starts from.
	Environ []string
	// TempDir is the parent of the scratch tree ("" for the system one).
	TempDir string
	Log     *slog.Logger
}

// Env is what the wiring gets to build the backend.
type Env struct {
	// Config is the configuration the backend loads, in place of the
	// process environment.
	Config      map[string]string
	DataDir     string
	BackupDir   string
	TransferDir string
	FastHashing bool
	// Dialer replaces the network dialer of the SSH client when the seed
	// enables outbound_ssh_guard; nil otherwise.
	Dialer *GuardDialer
}

// Lookup reads one configuration variable, like os.LookupEnv.
func (e Env) Lookup(name string) (string, bool) {
	v, ok := e.Config[name]
	return v, ok
}

// Backend is a wired backend that has not started serving.
type Backend struct {
	Stores Stores
	Hooks  Hooks
	// Serve answers requests on ln until ctx ends, with the hook routes
	// registered next to the real ones. It returns nil after ctx ended.
	Serve func(ctx context.Context, ln net.Listener, routes []protocol.Route) error
	// Close releases the backend (databases, background work); may be nil.
	Close func() error
}

// Wire builds the backend from the run's environment.
type Wire func(ctx context.Context, env Env) (*Backend, error)

// Run is the backend start of the end-to-end suite (tests/e2e/README.md):
// a fresh private scratch tree, the seed applied in full before the port
// is opened, then serving on 127.0.0.1 until ctx ends. Every failure
// before serving stops the start; the scratch tree is removed on return.
func Run(ctx context.Context, o Options, wire Wire) (err error) {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("e2e: port %d is invalid", o.Port)
	}
	seed, err := Load(o.SeedPath)
	if err != nil {
		return err
	}
	sc, err := NewScratch(o.TempDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, sc.Remove()) }()
	if err := sc.WriteDataFiles(seed.DataFiles); err != nil {
		return err
	}
	peer, err := seed.StartAutomationPeer()
	if err != nil {
		return err
	}
	if peer != nil {
		seed.peer = peer
		defer func() { err = errors.Join(err, peer.Close()) }()
	}
	env := Env{
		Config:      seed.Config(o.Environ, o.Port, sc),
		DataDir:     sc.DataDir,
		BackupDir:   sc.BackupDir,
		TransferDir: sc.TransferDir,
		FastHashing: o.FastHashing,
		Dialer:      seed.Guard().Allow(peer),
	}
	b, err := wire(ctx, env)
	if err != nil {
		return fmt.Errorf("e2e: wire backend: %w", err)
	}
	if b == nil || b.Serve == nil {
		return errors.New("e2e: the backend cannot serve")
	}
	if b.Close != nil {
		defer func() { err = errors.Join(err, b.Close()) }()
	}
	if b.Hooks.HerdrSnapshot == "" {
		b.Hooks.HerdrSnapshot = herdrSnapshotPath(o.SeedPath)
	}
	routes, err := seed.Routes(b.Hooks)
	if err != nil {
		return err
	}
	if _, err := Apply(ctx, seed, b.Stores, o.Log); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return fmt.Errorf("e2e: listen: %w", err)
	}
	// Serve owns the listener; closing it again here is harmless.
	defer func() { _ = ln.Close() }()
	o.Log.Info("e2e backend ready", "addr", ln.Addr().String(), "seed", o.SeedPath, "data_dir", sc.DataDir)
	if err := b.Serve(ctx, ln, routes); err != nil && ctx.Err() == nil {
		return fmt.Errorf("e2e: serve: %w", err)
	}
	return nil
}
