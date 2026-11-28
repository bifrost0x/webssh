# Contributing to WebSSH

Thanks for your interest in contributing! This project is open to contributions of all kinds - bug reports, feature requests, documentation improvements, and code.

## Quick Links

- [Report a Bug](https://github.com/bifrost0x/webssh/issues/new?template=bug_report.md)
- [Propose a Feature](https://github.com/bifrost0x/webssh/discussions)
- [Security Issues](SECURITY.md) - Please don't open public issues for vulnerabilities
- [Roadmap](ROADMAP.md) and [planning workflow](docs/project-planning.md)

## Getting Started

### Prerequisites

- Go at the version named by the `go` line in `go.mod`
- Node.js for the JavaScript and browser tests
- Python 3 for the repository tool tests in `tests/` and `scripts/` (not needed to build or run WebSSH)
- Docker (optional, for the image and the test lab)

### Local Development Setup

Follow [Development and Testing](docs/wiki/Development-and-Testing.md) for the
build, an isolated test data directory, Node tooling and the required checks.
Browser assets are already vendored; `scripts/stage-webassets.sh` copies them
into the binary before `go build ./cmd/webssh`.

### Project Structure

| Path | Purpose |
|---|---|
| `cmd/webssh` | The program: wiring and subcommands (`webssh help`) |
| `internal/` | One package per capability: HTTP API and pages (`internal/httpapi/pages/*.gohtml`), realtime transport, SSH/SFTP/SMB, storage, migration |
| `static/` | Vanilla JavaScript, CSS and vendored browser assets, embedded into the binary |
| `tests/` | JavaScript, browser, image and lab tests, repository tool tests, golden data of the 3.3 release |
| `scripts/` | Asset staging, vendor updates, CI and release checks |
| `Dockerfile`, `docker-compose*.yml`, `deploy/` | Container image and Compose files |
| `docs/wiki/` | Versioned user and operator documentation |
| `site/` | Public project website |

## How to Contribute

### Reporting Bugs

Before opening an issue:
1. Check if the issue already exists
2. Try the latest version
3. Collect relevant info (browser, OS, error messages, logs)

Include in your bug report:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Environment details (browser, OS, Docker version if applicable)

### Suggesting Features

Start a [Discussion](https://github.com/bifrost0x/webssh/discussions) for feature ideas. Please include:
- Clear description of the feature
- Use case - why is this useful?
- Possible implementation approach (optional)

### Pull Requests

#### Before You Start

1. **Check existing issues/PRs** - Someone might already be working on it
2. **Open an issue first** for larger changes - Let's discuss the approach
3. **Small PRs are better** - Easier to review and merge

For substantial work, state the user problem, expected outcome and acceptance criteria
in the linked issue/proposal. Include the reason for the chosen approach, validation,
compatibility/security impact and remaining rollout checks in the PR. A new or changed
setting, port or volume in `docker-compose.yml` also updates the Unraid template
`unraid/webssh.xml` in the same PR; `tests/test_unraid_template.py` enforces this. Maintainers assign
accepted work to a release milestone; merging does not itself publish a release.
See the [planning and release workflow](docs/project-planning.md) for the lightweight cycle.

#### Development Workflow

1. Fork the repository
2. Create a feature branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Test your changes locally
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

#### Code Style

**Go:**
- `gofmt`, `go vet`, `staticcheck` and `gosec` must be clean on `./cmd/... ./internal/...`
- One package per capability, at most 400 lines per production file; `go test ./internal/architecture` checks the [package map](docs/architecture/go-package-map.md) and the import rules
- Use meaningful names and keep functions focused and small
- Lean code: no unnecessary comments, doc comments where the logic is non-obvious

**Python (repository tools only):**
- `scripts/*.py` and the tool tests in `tests/` use the standard library and pytest
- Lint with `python -m ruff check .`; ruff is part of `requirements-test.txt` and configured in `ruff.toml`

**JavaScript:**
- Vanilla JS only (no frameworks - intentional architecture decision)
- Use consistent indentation (4 spaces)
- Prefer `const` over `let`, avoid `var`
- Lint with `npm run lint:js` (rules in `eslint.config.js`)

**Translations:**
- Each language has its own dictionary in `static/js/i18n/<lang>.js`. Add every new key to all of them; the tests reject missing, empty or unused keys.
- The sign-in pages use `static/js/i18n-auth.js`, generated from those dictionaries. Run `npm run i18n:auth` after changing a key they show.

**General:**
- No trailing whitespace
- Files end with a newline
- Keep lines under 100 characters when reasonable

#### Commit Messages

Write clear commit messages:

```
Add SFTP directory creation support

- Implement mkdir in internal/files
- Add the files.mkdir realtime event
- Update file manager UI with create folder button

Fixes #42
```

Format:
- First line: Brief summary (imperative mood, max 50 chars)
- Blank line
- Body: Explain what and why (wrap at 72 chars)
- Reference issues if applicable

#### Security Considerations

This project handles SSH credentials. When contributing, please:

- Never log passwords or private keys
- Validate and sanitize all user input
- Check session ownership before operations
- Use parameterized SQL queries; never build SQL from input
- Clear sensitive data from memory when done
- Consider path traversal in file operations

If your change touches authentication, encryption, or session handling, please note this in your PR for extra review attention.

#### Public Repository Hygiene

Everything committed here is published. Do not commit local development
instructions, tool configuration, private notes, development captures,
temporary test output, workstation paths, credentials, or unreferenced media.
Keep reusable product and operator documentation in the public documentation areas.

Run the same repository guard used by CI before submitting:

```bash
python scripts/check_repository_hygiene.py
```

The guard inspects tracked files directly, so force-adding an ignored file does
not bypass it. Changes that add a forbidden path, an internal-instruction marker,
a workstation-specific tool path, or an unreferenced file under `assets/` fail
the required `dispatch-integrity` check.

On pull requests the same check also rejects coding-assistant attribution in the
PR title, description, branch name and every commit of the PR: tool identities
as author or committer, co-author or session trailers, session links and
"generated by" footers. Check your commits before pushing:

```bash
python scripts/check_repository_hygiene.py --commits origin/main..HEAD
```

The description is checked when the PR is opened or updated with new commits;
editing it alone does not rerun the check.

#### Testing Your Changes

Before submitting:

1. **Manual testing** - Verify your changes work as expected
2. **Test edge cases** - Empty inputs, special characters, large files
3. **Check different browsers** - Chrome, Firefox, Safari at minimum
4. **Test with Docker** - Ensure containerized deployment works
   ```bash
   docker build -t webssh:test .
   docker build --target debug -t webssh:test-debug .   # variant with BusyBox for debugging
   docker run -p 5000:5000 -e SECRET_KEY=$(openssl rand -hex 32) -e CORS_ORIGINS=http://localhost:5000 webssh:test
   ```

### Documentation

Documentation improvements are always welcome:
- Fix typos or unclear explanations
- Add examples
- Improve README
- Add inline code comments

## What's Needed

Areas where contributions are especially welcome:

- [ ] Automated tests (Go, Playwright)
- [ ] Internationalization (new language translations)
- [ ] Accessibility improvements
- [ ] Performance optimizations
- [ ] Additional themes
- [ ] Documentation

## Code of Conduct

Be respectful and constructive. We're all here to build something useful.

- Be welcoming to newcomers
- Accept constructive criticism gracefully
- Focus on what's best for the project
- Show empathy towards others

## Questions?

Reach out via issues or directly at dwight@scranton.de

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0. See [LICENSE](LICENSE) for the terms and [Licensing](docs/licensing.md) for historical and third-party notices.
