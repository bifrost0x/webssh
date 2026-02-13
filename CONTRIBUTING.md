# Contributing to WebSSH

Thanks for your interest in contributing! This project is open to contributions of all kinds - bug reports, feature requests, documentation improvements, and code.

## Quick Links

- [Report a Bug](https://github.com/bifrost0x/webssh/issues/new?template=bug_report.md)
- [Request a Feature](https://github.com/bifrost0x/webssh/issues/new?template=feature_request.md)
- [Security Issues](SECURITY.md) - Please don't open public issues for vulnerabilities

## Getting Started

### Prerequisites

- Python 3.11+
- Docker (optional, for testing)

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/bifrost0x/webssh.git
cd webssh

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set required environment variable
export SECRET_KEY=$(openssl rand -hex 32)
export DEBUG=True

# Run the application
python start.py
```

Open http://localhost:5000 and create a test account.

### Project Structure

```
webssh/
├── app/                    # Flask application (15 modules)
│   ├── __init__.py        # App factory, routes, security headers
│   ├── auth.py            # Authentication, rate limiting
│   ├── models.py          # SQLAlchemy models
│   ├── socket_events.py   # WebSocket event handlers
│   ├── ssh_manager.py     # SSH connection management
│   ├── sftp_handler.py    # SFTP file operations
│   ├── connection_pool.py # SSH connection pooling
│   ├── key_manager.py     # SSH key storage
│   ├── key_encryption.py  # SSH key encryption at rest
│   ├── profile_manager.py # Connection profiles
│   ├── command_manager.py # Command library
│   ├── binary_transfer.py # Binary file transfer protocol
│   ├── user_settings.py   # User preferences
│   ├── audit_logger.py    # Security audit logging
│   └── decorators.py      # Shared decorators
├── static/
│   ├── css/               # Stylesheets (3 files)
│   └── js/                # Frontend JavaScript (12 modules)
├── templates/             # Jinja2 templates (4 files)
├── config.py              # Central configuration
├── start.py               # Entry point
└── requirements.txt       # Python dependencies
```

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

Feature requests are welcome! Please include:
- Clear description of the feature
- Use case - why is this useful?
- Possible implementation approach (optional)

### Pull Requests

#### Before You Start

1. **Check existing issues/PRs** - Someone might already be working on it
2. **Open an issue first** for larger changes - Let's discuss the approach
3. **Small PRs are better** - Easier to review and merge

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

**Python:**
- Follow PEP 8
- Use meaningful variable names
- Keep functions focused and small
- Lean code: no unnecessary comments, docstrings only where logic is non-obvious

**JavaScript:**
- Vanilla JS only (no frameworks - intentional architecture decision)
- Use consistent indentation (4 spaces)
- Prefer `const` over `let`, avoid `var`

**General:**
- No trailing whitespace
- Files end with a newline
- Keep lines under 100 characters when reasonable

#### Commit Messages

Write clear commit messages:

```
Add SFTP directory creation support

- Implement mkdir operation in sftp_handler.py
- Add socket event handler for create_directory
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
- Use parameterized queries (SQLAlchemy handles this)
- Clear sensitive data from memory when done
- Consider path traversal in file operations

If your change touches authentication, encryption, or session handling, please note this in your PR for extra review attention.

#### Testing Your Changes

Before submitting:

1. **Manual testing** - Verify your changes work as expected
2. **Test edge cases** - Empty inputs, special characters, large files
3. **Check different browsers** - Chrome, Firefox, Safari at minimum
4. **Test with Docker** - Ensure containerized deployment works
   ```bash
   docker build -t webssh:test .
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

- [ ] Automated tests (pytest, playwright)
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

By contributing, you agree that your contributions will be licensed under the MIT License.
