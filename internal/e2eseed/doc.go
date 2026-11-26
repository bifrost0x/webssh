// Package e2eseed applies the language-neutral end-to-end seed
// (tests/e2e/seed.json) to the Go stores and provides the test-only hooks
// of the end-to-end suite. It fails closed on an unknown seed version,
// member or hook: a seed that cannot be applied in full does not start a
// backend.
//
// Run is the whole backend start of the suite: scratch tree, seed, hooks,
// loopback listener. The stores and hook providers are consumer interfaces
// declared here; cmd/webssh/e2e.go adapts the real capabilities to them.
// Seed parts of capabilities outside the build are logged and skipped.
//
// The hooks are the counterparts of the Python fixtures:
//
//   - outbound_ssh_guard: GuardDialer replaces the SSH client's network
//     dialer and refuses every connection with the seed's text.
//   - socket_output_load: OutputLoadRoute, a synthetic output load through
//     the real terminal output flow.
//   - socket_workspace_restore: WorkspaceRestoreRoute, restorable fixture
//     sessions of the caller.
//   - automation_ssh_peer and socket_herdr_sessions belong to automation
//     and Herdr, which the preview does not contain; they are accepted and
//     skipped.
//
// The package is compiled and tested like every other package, but only
// cmd/webssh/e2e.go, built with the tag "e2e", imports it. The architecture
// tests check that the release build of cmd/webssh does not depend on it.
package e2eseed
