package architecture

import (
	"fmt"
	"slices"
	"strings"
)

// kind is the layer a package belongs to. See ADR 0003.
type kind string

const (
	// foundation packages implement formats, protocols and shared mechanisms.
	// They import only the standard library, allowlisted modules and other
	// foundation packages.
	foundation kind = "foundation"
	// capability packages implement one product capability. They may import
	// foundation packages, their own ancestors and the capabilities listed in
	// uses, but never an edge package.
	capability kind = "capability"
	// edge packages own transports and cross-capability workflows: the HTTP
	// server, the realtime endpoint, background jobs, the administrator CLI
	// and the one-time migration of legacy data.
	edge kind = "edge"
	// entry packages are the commands under cmd/. They wire everything.
	entry kind = "entry"
)

// role describes one package of the package map.
type role struct {
	kind kind
	// uses lists the module-relative paths of capability or edge packages
	// that this package may import beyond what its kind allows.
	uses []string
}

// packageMap is the machine-readable package map. Every package of the
// module, commands included, must be listed. It must match the
// "Packages" table in docs/architecture/go-package-map.md. Packages that do
// not exist yet are listed so that the map is reviewed once, up front.
var packageMap = map[string]role{
	"cmd/webssh":                 {kind: entry},
	"internal/architecture":      {kind: foundation},
	"internal/buildinfo":         {kind: foundation},
	"internal/config":            {kind: foundation},
	"internal/store":             {kind: foundation},
	"internal/fault":             {kind: foundation},
	"internal/fernet":            {kind: foundation},
	"internal/keyring":           {kind: foundation},
	"internal/realtime/protocol": {kind: foundation},
	"internal/principal":         {kind: foundation},
	// Test support packages hold test doubles; only test files import
	// them (isTestSupport).
	"internal/principal/principaltest":        {kind: foundation},
	"internal/realtime/protocol/protocoltest": {kind: foundation},
	"internal/store/storetest":                {kind: foundation},
	"internal/otp":                            {kind: foundation},
	"internal/cron":                           {kind: foundation},
	"internal/qrcode":                         {kind: foundation},
	"internal/ldapproto":                      {kind: foundation},
	"internal/platform":                       {kind: foundation},
	"internal/pyjson":                         {kind: foundation},
	"internal/session":                        {kind: capability},
	"internal/audit":                          {kind: capability},
	"internal/quota":                          {kind: capability},
	"internal/netpolicy":                      {kind: capability},
	"internal/ssh/client":                     {kind: capability, uses: []string{"internal/netpolicy"}},
	"internal/ssh/hostkey":                    {kind: capability},
	"internal/terminal":                       {kind: capability, uses: []string{"internal/ssh/client", "internal/ssh/hostkey", "internal/ssh/remotecmd"}},
	"internal/ssh/remotecmd":                  {kind: capability, uses: []string{"internal/ssh/client"}},
	"internal/hosts":                          {kind: capability, uses: []string{"internal/ssh/client", "internal/ssh/remotecmd"}},
	"internal/hostops":                        {kind: capability, uses: []string{"internal/ssh/client", "internal/ssh/remotecmd"}},
	"internal/files":                          {kind: capability},
	"internal/files/sftp":                     {kind: capability, uses: []string{"internal/ssh/client"}},
	"internal/files/smb":                      {kind: capability, uses: []string{"internal/netpolicy"}},
	"internal/transfer":                       {kind: capability, uses: []string{"internal/files"}},
	"internal/ssh/gateway":                    {kind: capability, uses: []string{"internal/ssh/client", "internal/ssh/hostkey"}},
	"internal/ssh/tailscale":                  {kind: capability, uses: []string{"internal/ssh/client"}},
	"internal/vault":                          {kind: capability},
	"internal/commands":                       {kind: capability},
	"internal/settings":                       {kind: capability},
	"internal/automation":                     {kind: capability, uses: []string{"internal/ssh/client", "internal/ssh/remotecmd", "internal/vault"}},
	"internal/operations":                     {kind: capability},
	"internal/accounts":                       {kind: capability, uses: []string{"internal/session"}},
	"internal/auth":                           {kind: capability, uses: []string{"internal/session", "internal/accounts"}},
	"internal/auth/stepup":                    {kind: capability, uses: []string{"internal/session"}},
	"internal/auth/local":                     {kind: capability},
	"internal/auth/ldap":                      {kind: capability},
	"internal/auth/oidc":                      {kind: capability},
	"internal/auth/github":                    {kind: capability},
	"internal/auth/totp":                      {kind: capability},
	"internal/auth/webauthn":                  {kind: capability},
	"internal/backup":                         {kind: capability},
	"internal/migrate/legacy":                 {kind: edge},
	"internal/httpapi":                        {kind: edge},
	"internal/realtime":                       {kind: edge},
	"internal/jobs":                           {kind: edge},
	"internal/admincli":                       {kind: edge},
	"internal/e2eseed":                        {kind: edge},
	// M2 (docs/architecture/m2-contracts.md).
	"internal/idna2003":        {kind: foundation},
	"internal/files/filestest": {kind: capability},
	"internal/vault/vaulttest": {kind: capability},
}

// roleOf returns the role of a module-relative package path. Commands
// under cmd/ are mapped like every other package.
func roleOf(rel string) (role, bool) {
	r, ok := packageMap[rel]
	return r, ok
}

// isAncestor reports whether parent is a strict path ancestor of child.
func isAncestor(parent, child string) bool {
	return strings.HasPrefix(child, parent+"/")
}

// mayImport reports whether package from may import package to, both given
// as module-relative paths.
func mayImport(from string, fromRole role, to string, toRole role) bool {
	switch fromRole.kind {
	case entry:
		return toRole.kind != entry
	case foundation:
		return toRole.kind == foundation
	case capability:
		switch toRole.kind {
		case foundation:
			return true
		case capability:
			return isAncestor(to, from) || slices.Contains(fromRole.uses, to)
		}
		return false
	case edge:
		switch toRole.kind {
		case foundation, capability:
			return true
		case edge:
			return slices.Contains(fromRole.uses, to)
		}
	}
	return false
}

// mapViolations checks the package map itself for entries that would
// weaken the layering.
func mapViolations(m map[string]role) []string {
	var problems []string
	for path, r := range m {
		isCommand := strings.HasPrefix(path, "cmd/")
		switch {
		case !isCommand && !strings.HasPrefix(path, "internal/"):
			problems = append(problems, fmt.Sprintf("%s: package map entries must be under internal/ or cmd/", path))
		case isCommand && r.kind != entry:
			problems = append(problems, fmt.Sprintf("%s: packages under cmd/ are entry packages", path))
		case !isCommand && r.kind == entry:
			problems = append(problems, fmt.Sprintf("%s: entry packages live under cmd/", path))
		}
		switch r.kind {
		case foundation, capability, edge, entry:
		default:
			problems = append(problems, fmt.Sprintf("%s: unknown kind %q", path, r.kind))
		}
		if r.kind == foundation && len(r.uses) > 0 {
			problems = append(problems, fmt.Sprintf("%s: foundation packages declare no uses", path))
		}
		for _, used := range r.uses {
			target, ok := m[used]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: uses unknown package %s", path, used))
			case used == path:
				problems = append(problems, fmt.Sprintf("%s: uses itself", path))
			case target.kind == foundation:
				problems = append(problems, fmt.Sprintf("%s: uses lists foundation package %s, which is always allowed", path, used))
			case r.kind == capability && target.kind != capability:
				problems = append(problems, fmt.Sprintf("%s: capability packages must not use %s package %s", path, target.kind, used))
			}
		}
	}
	slices.Sort(problems)
	return problems
}
