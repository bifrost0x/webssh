package admincli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// ConnectionStores is the recovery part of internal/hosts.
type ConnectionStores interface {
	RecoverySummaries(ctx context.Context, owner int64, k hosts.RecoveryKind, lim hosts.RecoveryLimits) ([]hosts.RecoverySummary, error)
	DeleteRecovery(ctx context.Context, owner int64, k hosts.RecoveryKind, selector string, lim hosts.RecoveryLimits) error
}

// StoreAdmin holds what connection-store needs.
type StoreAdmin struct {
	Accounts interface {
		ByUsername(ctx context.Context, name string) (accounts.Account, error)
	}
	Stores ConnectionStores
	Limits hosts.RecoveryLimits
	Audit  Auditor
}

// StoreOpener prepares the dependencies after the arguments were parsed.
type StoreOpener func(ctx context.Context) (s *StoreAdmin, close func() error, err error)

const connectionStoreGroupHelp = `Usage: %s connection-store [OPTIONS] COMMAND [ARGS]...

  Inspect or reduce quarantined legacy connection stores offline.

Options:
  --help  Show this message and exit.

Commands:
  delete  Delete one exact legacy record while WebSSH is stopped.
  list    List bounded, non-secret record summaries for offline recovery.
`

const connectionStoreListHelp = `Usage: %s connection-store list [OPTIONS]

  List bounded, non-secret record summaries for offline recovery.

Options:
  --username NAME                 [required]
  --kind [profiles|jump-hosts|socks-proxies]
                                  [required]
  --confirm-offline
  --help                          Show this message and exit.
`

const connectionStoreDeleteHelp = `Usage: %s connection-store delete [OPTIONS]

  Delete one exact legacy record while WebSSH is stopped.

Options:
  --username NAME                 [required]
  --kind [profiles|jump-hosts|socks-proxies]
                                  [required]
  --selector SELECTOR             [required]
  --confirm-offline
  --help                          Show this message and exit.
`

// errNotOffline is _require_offline_confirmation of app/cli.py.
var errNotOffline = fail("Stop every WebSSH application process first, then repeat with --confirm-offline.")

// requireOffline is the --confirm-offline check of the offline commands.
func requireOffline(p parsed) error {
	if !p.flags["--confirm-offline"] {
		return errNotOffline
	}
	return nil
}

func storeKinds() []string {
	var out []string
	for _, k := range hosts.RecoveryKinds() {
		out = append(out, string(k))
	}
	return out
}

// ConnectionStore is `webssh connection-store list|delete`: offline
// recovery of a connection store that grew beyond its limits
// (app/cli.py). prog is the program name in usage lines.
func ConnectionStore(ctx context.Context, prog string, args []string, o IO, open StoreOpener) int {
	group := &command{prog: prog, path: "connection-store", usageArgs: "COMMAND [ARGS]...",
		help: fmt.Sprintf(connectionStoreGroupHelp, prog)}
	p := parsed{values: map[string]string{}, flags: map[string]bool{}}
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		n, err := group.parseOption(&p, arg, args[i+1:])
		if err != nil {
			return group.report(o, err)
		}
		i += n
	}
	switch {
	case p.help:
		_, _ = io.WriteString(o.Stdout, group.help)
		return ExitOK
	case len(args) == 0:
		_, _ = io.WriteString(o.Stderr, group.help)
		return ExitUsage
	case i >= len(args):
		return group.report(o, &usageError{msg: "Missing command.", withUsage: true})
	}
	name := args[i]
	opts := []option{
		{name: "--username", metavar: "NAME", required: true},
		{name: "--kind", required: true, choices: storeKinds()},
	}
	var help string
	switch name {
	case "list":
		help = connectionStoreListHelp
	case "delete":
		help = connectionStoreDeleteHelp
		opts = append(opts, option{name: "--selector", metavar: "SELECTOR", required: true})
	default:
		return group.report(o, &usageError{msg: fmt.Sprintf("No such command '%s'.", name), withUsage: true})
	}
	opts = append(opts, option{name: "--confirm-offline", flag: true})
	c := &command{prog: prog, path: "connection-store " + name, options: opts, help: fmt.Sprintf(help, prog)}
	return c.run(o, args[i+1:], func(p parsed) error {
		if err := requireOffline(p); err != nil {
			return err
		}
		s, closeFn, err := open(ctx)
		if err != nil {
			return err
		}
		if name == "list" {
			err = s.list(ctx, p, o)
		} else {
			err = s.delete(ctx, p, o)
		}
		return errors.Join(err, closeFn())
	})
}

func (s *StoreAdmin) owner(ctx context.Context, p parsed) (accounts.Account, hosts.RecoveryKind, error) {
	username, _ := p.value("--username")
	kind, _ := p.value("--kind")
	acc, err := s.Accounts.ByUsername(ctx, username)
	if fault.Is(err, fault.NotFound) {
		return acc, "", fail("Account not found.")
	}
	return acc, hosts.RecoveryKind(kind), err
}

// storeFailure turns the refusals of internal/hosts into the message the
// Python command printed.
func storeFailure(err error) error {
	if fe, ok := fault.From(err); ok && fe.Message != "" {
		return fail("%s", fe.Message)
	}
	return err
}

func (s *StoreAdmin) list(ctx context.Context, p parsed, o IO) error {
	acc, kind, err := s.owner(ctx, p)
	if err != nil {
		return err
	}
	records, err := s.Stores.RecoverySummaries(ctx, acc.ID, kind, s.Limits)
	if err != nil {
		return storeFailure(err)
	}
	writeLine(o.Stdout, recoveryJSON(kind, records))
	return nil
}

// recoveryJSON is json.dumps(..., ensure_ascii=True, sort_keys=True) of
// the list result.
func recoveryJSON(kind hosts.RecoveryKind, records []hosts.RecoverySummary) string {
	var b strings.Builder
	b.WriteString(`{"count": ` + strconv.Itoa(len(records)) + `, "kind": ` + pyjson.Quote(string(kind)) + `, "records": [`)
	for i, r := range records {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(`{"host": ` + pyjson.Quote(r.Host) + `, "id": ` + pyjson.Quote(r.ID) + `, "name": ` +
			pyjson.Quote(r.Name) + `, "selector": ` + pyjson.Quote(r.Selector) + `}`)
	}
	b.WriteString("]}")
	return b.String()
}

func (s *StoreAdmin) delete(ctx context.Context, p parsed, o IO) error {
	acc, kind, err := s.owner(ctx, p)
	if err != nil {
		return err
	}
	selector, _ := p.value("--selector")
	if err := s.Stores.DeleteRecovery(ctx, acc.ID, kind, selector, s.Limits); err != nil {
		return storeFailure(err)
	}
	if s.Audit != nil {
		s.Audit.Security("CONNECTION_STORE_RECOVERY_DELETE", "user", acc.Username, "kind", string(kind), "selector", selector)
	}
	label := map[hosts.RecoveryKind]string{hosts.RecoverProfiles: "profile", hosts.RecoverJumpHosts: "jump-host",
		hosts.RecoverSOCKSProxies: "SOCKS-proxy"}[kind]
	writeLine(o.Stdout, "Deleted one "+label+" recovery record.")
	return nil
}
