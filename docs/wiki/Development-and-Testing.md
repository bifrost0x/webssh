# Development and Testing

WebSSH is one Go program (`cmd/webssh`, packages in `internal/`). The
frontend is vanilla JavaScript and CSS with locally vendored dependencies,
embedded into the binary. Python is used only for the repository tools in
`scripts/` and their tests in `tests/`. The last Python release (3.3) is
maintained on the branch `release/3.3`; a worktree of it is the reference for
re-recording the difference tests and for the lab migration tests.

## Go server

The Go version is the `go` line in `go.mod`. Build and run as described in
[Installation from Source](Installation-from-Source); the program lives in
`cmd/webssh`, the packages in `internal/`. Every build and test needs the web
assets staged first, or the `devfs` build tag:

```bash
scripts/stage-webassets.sh
GO_PACKAGES='./cmd/... ./internal/...'
gofmt -l cmd internal
go vet $GO_PACKAGES
go fix -diff $GO_PACKAGES
staticcheck $GO_PACKAGES
gosec -quiet $GO_PACKAGES
govulncheck ./...
go mod tidy -diff && go mod verify
go test -race -count=1 -timeout 30m $GO_PACKAGES
```

Gates run on `./cmd/... ./internal/...` rather than `./...`, because
`node_modules` can contain Go files. `go test ./internal/architecture` checks
the [package map](https://github.com/bifrost0x/webssh/blob/main/docs/architecture/go-package-map.md),
the import rules, the size limit of production files and that
`THIRD-PARTY-NOTICES` covers every linked module. `.github/workflows/go.yml`
runs the same gates in CI.

- Lab tests (`-tags lab`) run against the containers of the test lab
  (`tests/lab/up.sh`); `go test -tags lab -run Lab ./cmd/... ./internal/...`.
- The end-to-end build (`-tags e2e`) adds the seeded test backend of the
  browser suite; see [JavaScript and E2E tests](#javascript-and-e2e-tests).
- `go run -tags devfs ./cmd/webssh serve` serves `static/` directly while
  working on the frontend.

## Development setup

```bash
scripts/stage-webassets.sh
go build -o .test-run.tmp/webssh ./cmd/webssh
export DEBUG=True
export DATA_DIR="$PWD/dev-data"
.test-run.tmp/webssh serve
```

With frontend work, `go run -tags devfs ./cmd/webssh serve` instead picks up
changes below `static/` after a page reload.

`DEBUG=True` selects development defaults, as in
[Installation from Source](Installation-from-Source): a temporary
`SECRET_KEY` when none is configured, cookies without the `Secure` flag for
`http://127.0.0.1:5000`, and open registration. Never use it for a reachable
instance. Do not reuse production `DATA_DIR`, credentials, or secrets for
development and tests.

## Difference tests against 3.3

Difference tests compare Go with answers of the 3.3 release that are
recorded under `testdata/` (`internal/oracletest`). They need no Python and
run in every `go test`.

Re-recording the answers, `WEBSSH_PYTHON_ORACLE=live` and the lab migration
tests need the 3.3 release itself: a worktree of the tag `v3.3.1` (until the
tag exists, commit `7d883135`) with its own virtual environment:

```bash
git worktree add ../webssh-3.3 v3.3.1        # until the tag exists: 7d883135
python3 -m venv ../webssh-3.3/.venv
../webssh-3.3/.venv/bin/python -m pip install --require-hashes \
  -r ../webssh-3.3/requirements-test.txt
export WEBSSH_PYTHON_ROOT="$PWD/../webssh-3.3"
export WEBSSH_PYTHON="$WEBSSH_PYTHON_ROOT/.venv/bin/python"
```

- `PYTHON="$WEBSSH_PYTHON" scripts/record-python-oracles.sh` records every
  answer again; `PYTHON="$WEBSSH_PYTHON" scripts/check-python-oracles.sh`
  checks that the recordings still match the release and runs the
  difference tests against it. Each recording names the interpreter and
  the commit of the 3.3 sources in its header.
- `WEBSSH_PYTHON_ORACLE=live go test …` asks the release instead of the
  recordings and requires the recordings; it fails when no interpreter is
  found.
- The lab migration tests let 3.3 write a data directory and start Go on it:
  `WEBSSH_LAB_JSON="$PWD/tests/lab/runtime/lab.json" go test -tags lab -run TestLabMigrated ./cmd/webssh`.
  They fail, not skip, when the lab or the 3.3 environment is missing.

## Repository tool tests

`scripts/*.py` (CI, release and repository checks) and their tests in
`tests/` use Python 3 with pytest; `requirements-test.txt` holds only pytest
and ruff, hash-locked:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-test.txt
.venv/bin/python -m pytest tests -q
.venv/bin/python -m ruff check .
```

`ruff.toml` holds the selected rules. `scripts/lock_requirements.ps1`
regenerates the hash-locked files from `requirements-test.in` and
`requirements-graph.in` (the website code graph) with the uv version pinned
in `uv.toml`; `-Check` verifies them without changes, `-Upgrade` refreshes
all allowed resolutions. Do not hand-edit generated lock files.

### Herdr lab

The Go server runs the Herdr browser spec and the Go Herdr lab tests
against a disposable Herdr host, with a password and host keys made for
the run, and removes it afterwards:

```bash
go build -o .test-run.tmp/webssh ./cmd/webssh
tests/integration/herdr/run-go-lab.sh                 # Go lab tests, build tag herdr
PYTHON="$WEBSSH_PYTHON" \
WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh serve' \
WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh' \
tests/integration/herdr/run-go-browser.sh             # browser spec
```

The spec's probe (`tests/integration/herdr_lab_probe.py`) needs paramiko;
`PYTHON` names an interpreter that has it, such as the one of the 3.3
worktree above.

## Frontend dependencies

Pinned browser libraries are declared in `package.json` and copied into the repository through the vendor workflow. Current contracts include xterm.js, fit/search addons, highlight.js, and Material Icons.

```bash
npm ci
npm run vendor
npm run vendor:check
```

Do not add runtime CDN scripts, fonts, or styles. The application must remain offline-capable and satisfy CSP and vendor-integrity tests. Run `scripts/stage-webassets.sh` again before a build so the binary embeds the new files.

## JavaScript and E2E tests

```bash
npm run lint:js
npm run test:js
npm run test:e2e
node tests/e2e/run-go-suite.js --with passkeys,e2e_hooks
```

Playwright starts the seeded Go test backend (build tag `e2e`) for every run;
[tests/e2e/README.md](https://github.com/bifrost0x/webssh/blob/main/tests/e2e/README.md)
describes the backend contract, the seed and the variables.
`run-go-suite.js` runs the specs listed in `tests/e2e/go-suite.json`; every
test it leaves out names its reason. CI uses eight runner groups with four
isolated WebSSH servers per group. Each server keeps one worker and receives one of
32 disjoint partitions, assigned by recorded duration:

```bash
node scripts/run-e2e-ci-parallel.js --group=1/8 --lanes=4
# Repeat groups 2/8 through 8/8 for the complete CI browser gate.
# Individual partitions can still be reproduced directly:
npm run test:e2e:ci -- --shard=1/32
```

The runner discovers the current suite before partitioning it. Every discovered
test belongs to exactly one shard; new tests receive a fallback weight. Test
identity is based on file and full title, so moving source lines does not change
assignment. Groups interleave the 32 partitions so the heaviest terminal-load
cases run on different runners. Shared account and session fixtures require one
worker per server; increasing workers without isolating that state can invalidate
results. The group
runner gives each server a separate port, data directory, temporary namespace
and artifact directory. It waits for every partition and fails if any child fails;
interrupts terminate only its owned process trees. Fixture password hashing is
reduced only in the explicit isolated test process; application hashing is unchanged.
The parallel launcher supports Linux and Windows. On other platforms, use the
individual sequential partition command above.
Firefox and WebKit font regressions run in parallel on separate ports in one
mandatory job; both process results must succeed.
The two 20-terminal transport-load cases reserve their runner before its other
cases start. Their partitions are calculated from the current discovery and
weights. Only those cases run exclusively; all four lanes then run their remaining
cases in parallel, with separate output and timing files for each phase. All
remaining cases still run even when one fails.
Font tests use Ubuntu hosted runners with the locked Playwright browsers. Both
browser runtimes must pass their installation and launch checks.

The `browser-e2e` and `all-tests` aggregate checks retain all required
partitions and font browsers. The runtime target is two to three minutes for the entire required gate, including
`all-tests` and `security-scan / image-security`;
queueing, cold dependency installation and runner capacity still require measured
GitHub validation at the published revision. No test is dropped to meet that target.
Chromium installs the headless shell used by these tests and must pass a real launch probe; missing
system libraries trigger dependency installation and a second mandatory probe.
Firefox and WebKit also probe their installed runtime before requesting system
packages. On GitHub-hosted runners, the recognized default APT mirror list
prefers its existing official HTTPS archive and retains Azure as a fallback.
Unknown mirror lists are left unchanged. Pull requests build scan images with the native Docker builder on AMD64 and
ARM64 runners, avoiding a separate Buildx daemon and remote cache export.
Base images are pulled and OS package refresh inputs remain unique per run.
The SPDX SBOM, both Trivy scans and their required aggregate remain mandatory.
Other events retain the existing Buildx cache path.

CI uploads `test-results/e2e-timing-*.json` from each shard, including failed runs.
Download reports from a representative successful run into `test-results/` and
refresh the checked-in duration baseline with:

```bash
npm run test:e2e:timings:refresh
# Or pass the downloaded report paths explicitly:
npm run test:e2e:timings:refresh -- path/to/shard-1.json path/to/shard-2.json
```

Include both phase reports for split shards and every other shard report. The
import rejects missing or duplicate phases and overlapping test identities.
Review the baseline diff alongside the suite change. Do not mix reports from
different revisions when refreshing it. Timing weights affect scheduling only;
they do not decide which tests run.

Success screenshots and animation frames are opt-in:

```bash
npm run test:captures
```

This sets `WEBSSH_CAPTURE_ASSETS=1` for the capture suites. Their functional,
accessibility and geometry assertions also run in normal CI. Failure screenshots
and traces remain available without the flag. Captures used by the README or
product site update their declared files below `assets/`; additional QA captures
are written to the ignored `.test-run.tmp/captures/` directory.

To refresh only the README stills and tour frames, use the focused capture suite:

```bash
WEBSSH_CAPTURE_ASSETS=1 npx playwright test tests/e2e/product-captures.spec.js --forbid-only
# Optional authoring dependency; not needed by WebSSH or normal tests.
python -m pip install Pillow
python scripts/build-product-gifs.py
```

The encoder uses those captures for the three looping product GIFs. Review every
still and animation before publishing: use synthetic `.example` hosts, keep
credentials and personal data out of frame, and retain the capture assertions.

Playwright assumptions must be updated when a default frontend state changes.
Test both the new default and the user's explicit override.

## Container and runtime gates

`tests/image/check.sh` builds the `release` and `debug` targets of the
`Dockerfile` and checks them (`BUILD=0` checks existing `webssh:local` and
`webssh:local-debug` images, `TRIVY=1` adds the Trivy scan). Relevant release
validation includes:

- container build and startup without a shell, under the restrictions of
  `docker-compose.hardened.yml`;
- runtime identities: the default user, a custom UID and the shipped Unraid
  template;
- the Unraid template's ports, paths and variables against
  `docker-compose.yml` (`tests/test_unraid_template.py`);
- the Compose files, the 3.3 health checks and command forms;
- `/health` and `/ready` behavior;
- offline backup and restore, graceful shutdown;
- AMD64 and ARM64 images;
- SPDX SBOM and provenance;
- Trivy results for fixable High/Critical findings;
- CodeQL for the languages in the repository and for Actions.

A new or changed setting, port or volume in `docker-compose.yml` must reach
`unraid/webssh.xml` in the same change; the template test fails otherwise.

Always associate CI evidence with the exact commit under review. A green run from an older SHA is not evidence for a newer change.

## Immutable image publication

Main pushes and version tags call the complete `Tests` workflow once, with the
exact source SHA. `Tests` has no separate main-push trigger. PRs still test their
own merge revision, and manual exact-SHA runs remain available, including the
Dependabot vendor refresh workflow. Every required job must finish successfully;
missing, skipped, cancelled, or failed jobs prevent publication.

At the same time, independent native AMD64 and ARM64 jobs build digest-only
candidates on `ubuntu-24.04` and `ubuntu-24.04-arm`. They retain package refreshes,
SBOM and provenance, verify source and platform identity, scan the exact runtime
digests for fixable High/Critical findings, and run compatible plus opt-in
hardened startup, backup/restore and shutdown checks. PR image scans also use
native runners. Superseded PR scans are cancelled; release runs remain separate.

Each platform uploads its candidate identity only after its scan and runtime
checks pass. The handoff is bound to repository, source SHA and workflow run.
Retrying failed jobs can reuse a successful platform from an earlier attempt of
the same run; a successfully rebuilt platform replaces its own handoff. Different
runs, revisions, future attempts and mismatched registry evidence are rejected.

The publication job waits for both platform jobs and the full test gate. It
rechecks the immutable candidates and assembles their complete manifest
descriptors, including attestations, under a run-specific `candidate-*` tag.
Only the validated combined index is copied to the existing branch/version tags
(`main`, `latest`, or the version and major.minor series). Every destination tag
must resolve to that original index digest. Promotion never rebuilds the image.

Successful platform handoffs are retained for 14 days. Per-platform scan evidence
and the successful `image-release.json` are retained for 90 days; the release
record contains the tested revision, index digest, platform digests and verified
tags. A retry after handoff expiration needs fresh platform builds.

Registry tag writes are not transactional: a registry/network failure can leave
some tags updated, so a failed promotion requires checking all tags against the
candidate digest before retrying. Publisher jobs are serialized, with up to 100
pending jobs queued. Queue arrival follows validation completion, so a main push
also rechecks the current remote main SHA immediately before promotion.
Superseded main candidates fail without updating release tags; version-tag
releases remain eligible independently of the current main SHA.

PRs also exercise the promotion helper against a disposable loopback-only local
registry, using tiny synthetic platform images with attestation payloads:

```bash
python scripts/check_release_promotion.py
```

This requires Docker and Buildx. It verifies native candidate assembly,
whole-index preservation at each destination tag, and rejection of a different
source SHA. It creates a uniquely named registry container and removes only that
container and its anonymous volume after verifying its ownership label. This
contract does not replace the real candidate scans or application runtime checks.

### Test selection and required checks

The protected PR checks are `all-tests` and `security-scan / image-security`.
They always report a result. The first requires the complete test job set,
including the release contract and the Go gates (`go-gates`, which calls
`.github/workflows/go.yml`; a failed Go job fails `go-gates` and with it
`all-tests`); the second requires both native image scans. Missing, failed or cancelled jobs block their aggregate. Successful older
runs cannot satisfy a newer revision.

| Change or trigger | Tests | Container scans and publication |
|---|---|---|
| Code, tests, dependencies, workflow or mixed PR | Go gates (build, vet, staticcheck, race tests, security scanners, network namespace and SSH protocol checks); repository tool tests; JavaScript, vendor and lint checks; all 32 browser partitions; Firefox/WebKit fonts; image and release contracts | Native AMD64 and ARM64 scans; no publication |
| Documentation-only PR | Exact-revision classification, documentation contracts, the `lint` job and both required aggregates | Both image scans deliberately skipped; no publication |
| Main push or version tag | Complete reusable Tests workflow once | Native candidates build alongside tests; publish only after all gates pass |
| Manual exact-SHA test run | Full tests, regardless of changed paths | No publication from the Tests workflow |
| Scheduled or manual Container Security run | Independent image validation | Both native architecture scans; no publication |

`scripts/ci_change_scope.py` owns the documentation allowlist: `README.md`,
Markdown files below `docs/`, and documentation media below `docs/media/`.
Runtime assets under `static/`, tests, scripts, workflows, locks and unknown
paths always select the full path. The classifier checks the exact checkout,
compares the PR base to the tested merge revision, and includes deleted paths
and both sides of renames. It reads the complete Git diff, without an API file
limit. Missing history, an empty diff or uncertain Docker exclusions select
full validation. Workflow summaries record the decision and its reason.

The existing documentation contracts run in the initial test job through
`python -m unittest discover -s tests -p test_documentation_surface.py -v`.
The checks cover Wiki links, page coverage, README structure, documentation
media, LDAP and Command Set instructions, the Go toolchain reference and
production Compose commands without installing any dependencies. Keep every
test that reads README or allowed documentation paths in this module,
including contracts that compare documentation with runtime or workflow files.

The same initial job runs `python scripts/check_repository_hygiene.py` against
the complete tracked tree. This blocks local agent instructions, internal review
artifacts, transient development output, workstation-specific AI-tool paths and
unreferenced files below `assets/`, including files force-added despite ignore
rules. Run it locally before opening or updating a pull request.

Only a successful `docs` classification permits the named expensive jobs to
be skipped. An unexpected result, a missing job or a missing scope fails the
aggregate. Workflow-level path filters are intentionally avoided so required
checks cannot remain pending merely because documentation changed.

The `lint` job runs ruff, ESLint, the vendor check and the JavaScript unit tests
(including the sign-in translation check) for every change scope. It starts
without waiting for the classification, and `all-tests` requires its success
in both scopes. Every job that runs steps declares a `timeout-minutes` limit above its
usual duration, so a stalled runner fails instead of blocking the gate.

Main and tag pushes always run the full release pipeline, including docs merges.
Every published image therefore belongs to its fully tested source revision.
This also preserves the current-main promotion guard when a documentation merge
arrives during an earlier code release. Pages, Wiki publication and CodeQL retain
their own triggers and do not use the PR documentation shortcut.

When adding a new test job, add it to `all-tests.needs` and the corresponding
required set in `scripts/check_release_gates.py`. Keep selection conditions in
sync and test both full and documentation modes. Do not solve a failing aggregate
by accepting arbitrary skipped jobs or by removing a required check.

## Storage and concurrency rules

When changing persistence:

- go through `internal/store`: one SQLite database, changes in transactions,
  versioned and additive schema migrations;
- seal secrets with `internal/keyring`, bound to their record;
- preserve unreadable data for diagnosis rather than overwriting it;
- never write the 3.3 data in `DATA_DIR`; only `internal/migrate/legacy` reads it.

When changing SSH/SFTP or transfers:

- preserve user ownership checks;
- dial only through `internal/ssh/client` and its network policy;
- keep timeouts, cancellation, and quota admission;
- ensure quick connections outlive queued/active transfer references;
- test graceful shutdown and disconnect races with `-race`.

## Contributions

Keep changes focused and match the surrounding module's style and error contracts. Feature proposals belong in GitHub Discussions. Security vulnerabilities must follow the private process in `SECURITY.md`, not a public issue.

Before submitting a change, run the checks relevant to its actual blast radius and document any gate that could not be executed.
