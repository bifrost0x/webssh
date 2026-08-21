"""Contracts for the repository README, canonical Wiki source, and media."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "docs" / "wiki"
README = ROOT / "README.md"

WIKI_PAGE_NAMES = {
    "Home.md",
    "Quick-Start.md",
    "Installation-from-Source.md",
    "Docker-and-Docker-Compose.md",
    "Production-Deployment.md",
    "Reverse-Proxy-and-Subfolder-Deployment.md",
    "Upgrading-Rollback-and-FAQ.md",
    "Users-and-Account-Management.md",
    "Authentication-Overview.md",
    "LDAP-and-Active-Directory.md",
    "OpenID-Connect.md",
    "Passkeys-and-Recovery-Codes.md",
    "SSH-Connections-and-Host-Keys.md",
    "Profiles-Jump-Hosts-and-Commands.md",
    "Terminal-and-Persistent-tmux-Sessions.md",
    "SFTP-File-Workspace-and-Transfers.md",
    "Tailscale-SSH.md",
    "Configuration-Reference.md",
    "Administration-Audit-and-Diagnostics.md",
    "Backup-Restore-and-Secret-Rotation.md",
    "Security-Model-and-Hardening.md",
    "Data-Storage-and-Persistence.md",
    "Architecture-and-Runtime-Lifecycle.md",
    "Health-Checks-and-Troubleshooting.md",
    "Development-and-Testing.md",
    "_Sidebar.md",
    "_Footer.md",
}

MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def extract_markdown_targets(text: str) -> list[str]:
    """Return Markdown link targets without fragment identifiers."""
    return [
        match.group(1).split("#", 1)[0]
        for match in MARKDOWN_LINK.finditer(text)
    ]


def test_complete_canonical_wiki_source_is_versioned():
    """The pull request carries every published Wiki page for review."""
    assert {path.name for path in WIKI.glob("*.md")} == WIKI_PAGE_NAMES


def test_sidebar_links_every_public_wiki_page_once():
    """The custom sidebar exposes every public page exactly once."""
    sidebar = (WIKI / "_Sidebar.md").read_text(encoding="utf-8")
    targets = [
        target
        for target in extract_markdown_targets(sidebar)
        if not target.startswith("http")
    ]
    expected = {
        path.stem
        for path in WIKI.glob("*.md")
        if not path.name.startswith("_")
    }
    assert set(targets) == expected
    assert len(targets) == len(set(targets))


def test_local_wiki_links_resolve():
    """Every relative Wiki link resolves to a versioned Markdown page."""
    missing = []
    for page in WIKI.glob("*.md"):
        for target in extract_markdown_targets(page.read_text(encoding="utf-8")):
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            candidate = WIKI / (
                target if target.endswith(".md") else f"{target}.md"
            )
            if not candidate.is_file():
                missing.append(f"{page.name}: {target}")
    assert missing == []


def test_wiki_has_no_unresolved_placeholders():
    """Public Wiki prose contains no unfinished editorial markers."""
    forbidden = re.compile(r"\b(?:TODO|TBD|FIXME)\b", re.IGNORECASE)
    findings = []
    for page in WIKI.glob("*.md"):
        if forbidden.search(page.read_text(encoding="utf-8")):
            findings.append(page.name)
    assert findings == []
