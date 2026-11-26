// Package architecture enforces the module's structural rules as tests.
//
// It holds no production code. The tests check, for every Go package of the
// module, the package map and import rules, the file size limit, forbidden
// package names and the allowlist of external modules. The rules and their
// reasons are documented in docs/adr/0003-package-structure-and-modularity.md
// and docs/architecture/go-package-map.md.
package architecture
