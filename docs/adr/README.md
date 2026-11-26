# Architecture decision records

Decisions that shape the Go backend and are expensive to reverse. One file
per decision, numbered in sequence. A changed decision gets a new record
that supersedes the old one; old records are kept.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-go-for-the-backend.md) | Go for the backend | Accepted |
| [0002](0002-parallel-build-with-one-time-migration.md) | Parallel clean build with one-time migration on first start | Accepted |
| [0003](0003-package-structure-and-modularity.md) | Package structure and modularity rules | Accepted |
| [0004](0004-dependency-policy.md) | Dependency policy in tiers A, B and C | Accepted |
| [0005](0005-native-websocket-realtime-transport.md) | Native WebSocket with a versioned message schema | Accepted |
| [0006](0006-capability-driven-redesign.md) | Capability-driven redesign, not a port | Accepted |
| [0007](0007-legacy-data-migration.md) | Legacy data migration | Accepted |
| [0008](0008-keyring-for-secrets-at-rest.md) | Keyring for secrets at rest | Accepted |
| [0009](0009-password-hashing.md) | Password hashing with Argon2id and transparent rehash | Accepted |
| [0010](0010-outbound-network-policy.md) | One outbound network policy and one SSH dialer | Accepted |
| [0011](0011-http-api-and-cli-surface.md) | Stable HTTP and CLI surface, internal API | Accepted |

The package map that applies these decisions is
[docs/architecture/go-package-map.md](../architecture/go-package-map.md).

Template: Status, Date, Context, Decision, Alternatives considered,
Consequences.
