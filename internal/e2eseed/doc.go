// Package e2eseed applies the language-neutral end-to-end seed
// (tests/e2e/seed.json) to the Go stores and provides the test-only hooks
// of the end-to-end suite. It fails closed on an unknown seed version or
// hook.
//
// The package is compiled and tested like every other package, but only
// cmd/webssh/e2e.go, built with the tag "e2e", imports it. The architecture
// tests check that the release build of cmd/webssh does not depend on it.
package e2eseed
