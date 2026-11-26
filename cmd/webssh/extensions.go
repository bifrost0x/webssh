package main

import (
	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// capabilitySchemas are the stores of the capabilities this file wires.
func capabilitySchemas() []store.Schema {
	return []store.Schema{
		accounts.Schema(), local.Schema(), auth.Schema(), session.Schema(), stepup.Schema(), totp.Schema(),
		operations.Schema(), settings.Schema(), hosts.Schema(), hostops.Schema(), vault.Schema(), hostkey.Schema(),
		terminal.Schema(),
	}
}

// extension is a capability that joins the composition root from its own
// file through register, so that packages built in parallel (passkeys,
// tmux) plug in without changes here. Each hook is optional.
//
//   - schemas are applied with the capability schemas.
//   - prepare runs after the core services exist and before the HTTP
//     routes, the realtime routes and the terminal are built; it may set
//     the optional dependencies in sys.optional.
//   - wire runs after the core routes are registered and before the HTTP
//     edge and the realtime endpoint are finished; it registers routes.
type extension struct {
	name    string
	schemas []store.Schema
	prepare func(sys *system) error
	wire    func(sys *system) error
}

// extensions holds the registered extensions in registration order.
var extensions []extension

// register adds an extension; it is called from init functions.
//
//lint:ignore U1000 the extension point of capabilities built in parallel (passkeys)
func register(e extension) {
	if e.name == "" {
		panic("webssh: extension without a name")
	}
	for _, have := range extensions {
		if have.name == e.name {
			panic("webssh: extension registered twice: " + e.name)
		}
	}
	extensions = append(extensions, e)
}

// migrationRegistrar registers the migration steps of this build. The
// migration steps of a release replace it from their own file (init), so
// that they plug in without changes here. Until every entity of the
// specification is covered, the server refuses to migrate legacy data
// (legacy.Options.RequireCoverage) instead of activating a database
// without it.
var migrationRegistrar = func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
	return legacy.AddSingleUserStores(r)
}

// migrationRegistry builds the registry of this build's migration steps.
// The staging database gets every schema the steps may write to.
func migrationRegistry(cfg config.Config, lookup config.LookupFunc) (*legacy.Registry, error) {
	r := legacy.NewRegistry()
	r.Schemas(schemas()...)
	if err := migrationRegistrar(r, cfg, lookup); err != nil {
		return nil, err
	}
	return r, nil
}
