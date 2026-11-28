# Tests outside the Go packages

| Path | What it checks | How it runs |
|---|---|---|
| `tests/test_*.py` | CI scripts, workflows, dependency and supply-chain policy, licences, frontend sources | `python -m pytest tests` with `requirements-test.txt` (CI job `lint`) |
| `tests/js/` | frontend units | `npm run test:js` |
| `tests/e2e/` | browser suite against the Go server's e2e build | `npx playwright test` (README there) |
| `tests/e2e/m1/`, `tests/e2e/m2/` | acceptance journeys against the release build and the test lab | `npx playwright test -c tests/e2e/m1/playwright.config.js` |
| `tests/image/` | the image of the root Dockerfile, the 3.3 and 3.4 Compose files, the upgrade from 3.3 | `tests/image/check.sh`, `tests/image/upgrade.sh` |
| `tests/lab/` | the shared test lab | `tests/lab/up.sh` (README there) |
| `tests/golden/` | generators and checks of the golden data sets | needs the Python release, see below |

## The Python release

WebSSH 3.4 has no Python. The differential oracles, the golden data set
generators and checks, the lab migration tests and the migration fixture
of the M1 browser specs still ask the last Python release. It is not part
of this repository; they take it from a worktree named by
`WEBSSH_PYTHON_ROOT`. The commit is `PYTHON_RELEASE` in
`scripts/record-python-oracles.sh`: `7d883135` (3.3.1 on main) until the
tag `v3.3.1` exists, then the tag.

```sh
git worktree add --detach ../py-3.3.1 7d8831353ec44d7e5ed7b3e7644fa09c608bfc01
(cd ../py-3.3.1 && uvx uv@0.13.5 venv && \
  VIRTUAL_ENV=$PWD/.venv uvx uv@0.13.5 pip install --require-hashes -r requirements-test.txt)
export WEBSSH_PYTHON_ROOT=$PWD/../py-3.3.1
```

The application comes from that worktree, the recorders, fixtures and
generators from this repository; the interpreter defaults to
`$WEBSSH_PYTHON_ROOT/.venv/bin/python` (`WEBSSH_PYTHON` or `PYTHON`
override it).

| Task | Command |
|---|---|
| record every oracle again | `scripts/record-python-oracles.sh` |
| record, compare and run the differential tests live | `scripts/check-python-oracles.sh` (CI: `python-oracles.yml`, on request) |
| golden data set checks | `"$WEBSSH_PYTHON_ROOT/.venv/bin/python" -m pytest tests/golden` |
| regenerate a golden data set | `PYTHONPATH=$WEBSSH_PYTHON_ROOT "$WEBSSH_PYTHON_ROOT/.venv/bin/python" -m tests.golden.generate --out <dir>` |
| lab migration tests | `WEBSSH_LAB_JSON=tests/lab/runtime/lab.json go test -tags lab -run TestLabMigrated ./cmd/webssh` |
| browser migration spec | `npx playwright test -c tests/e2e/m1/playwright.config.js tests/e2e/m1/migration.spec.js` |

Without `WEBSSH_PYTHON_ROOT` the Go tests replay the recordings and
`pytest tests` leaves `tests/golden` out; every command above that asks
the release fails instead of skipping.
