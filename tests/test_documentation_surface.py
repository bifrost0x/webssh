"""Contracts for the repository README, canonical Wiki source, and media."""

import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "docs" / "wiki"

DIAGRAM_NAMES = {
    "system-trust-boundaries",
    "authentication-assurance",
    "session-and-transfer-lifecycle",
    "backup-restore-safety",
}
DESKTOP_PRODUCT_CAPTURES = {
    "workspace-overview.png",
    "multi-session.png",
    "sftp-workspace.png",
    "security-center.png",
}
MOBILE_PRODUCT_CAPTURES = {"mobile-workspace.png"}
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


def wiki_text(name: str) -> str:
    """Read one canonical Wiki page as UTF-8 text."""
    return (WIKI / name).read_text(encoding="utf-8")


def png_size(path: Path) -> tuple[int, int]:
    """Read the dimensions from a PNG IHDR header."""
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II", data[16:24])


def gif_metadata(path: Path) -> tuple[int, int, int, int, bool]:
    """Read GIF canvas size, frame count, duration, and loop marker."""
    data = path.read_bytes()
    assert data[:6] in {b"GIF87a", b"GIF89a"}
    width, height = struct.unpack("<HH", data[6:10])
    delays = []
    for match in re.finditer(rb"\x21\xf9\x04", data):
        payload = match.end()
        delays.append(struct.unpack("<H", data[payload + 1:payload + 3])[0] * 10)
    return width, height, len(delays), sum(delays), b"NETSCAPE2.0" in data


def test_diagram_sources_and_wiki_exports_exist_at_readable_size():
    """Every Wiki diagram keeps its source and a readable raster export."""
    directory = ROOT / "docs" / "media" / "diagrams"
    for name in DIAGRAM_NAMES:
        html = directory / f"{name}.html"
        svg = directory / f"{name}.svg"
        png = directory / f"{name}.png"
        assert html.is_file() and "<svg" in html.read_text(encoding="utf-8")
        assert svg.is_file() and "<svg" in svg.read_text(encoding="utf-8")
        assert png_size(png) == (2880, 1800)


def test_current_product_captures_exist_at_readable_size():
    """README screenshots are current, legible, and consistently exported."""
    assets = ROOT / "assets"
    for name in DESKTOP_PRODUCT_CAPTURES:
        assert png_size(assets / name) == (2560, 1440)
    for name in MOBILE_PRODUCT_CAPTURES:
        assert png_size(assets / name) == (1080, 1920)


def test_product_tours_are_readable_looping_animations():
    """README tours are high-resolution, multi-frame, and long enough to read."""
    expectations = {
        "webssh-demo.gif": 15_000,
        "file-editing.gif": 12_000,
        "command-sets.gif": 12_000,
    }
    for name, minimum_duration in expectations.items():
        width, height, frames, duration, loops = gif_metadata(ROOT / "assets" / name)
        assert (width, height) == (1280, 720)
        assert frames >= 25
        assert duration >= minimum_duration
        assert loops
    assert "assets/command-sets.gif?raw=true" in wiki_text(
        "Profiles-Jump-Hosts-and-Commands.md"
    )


def test_readme_is_a_compact_project_entry_point():
    """The repository landing page stays concise enough to scan on GitHub."""
    lines = README.read_text(encoding="utf-8").splitlines()
    assert 200 <= len(lines) <= 400


def test_readme_has_the_approved_information_architecture():
    """The README routes readers through product, setup, safety, and docs."""
    readme = README.read_text(encoding="utf-8")
    for heading in (
        "## Why WebSSH",
        "## Features",
        "## Screenshots",
        "## Quick Start",
        "## Security Boundary",
        "## Documentation",
        "## Contributing and Support",
    ):
        assert heading in readme


def test_readme_uses_the_new_product_media():
    """The compact README presents every current product capture."""
    readme = README.read_text(encoding="utf-8")
    for name in (
        "webssh-demo.gif",
        "workspace-overview.png",
        "multi-session.png",
        "sftp-workspace.png",
        "security-center.png",
        "mobile-workspace.png",
    ):
        assert f"assets/{name}" in readme


def test_readme_moves_long_form_runbooks_to_the_wiki():
    """Operational detail lives in the versioned Wiki instead of the README."""
    readme = README.read_text(encoding="utf-8")
    for removed_heading in (
        "### Environment Variables",
        "### Reverse Proxy Setup",
        "### CLI Backup, Restore, and Secret Rotation",
        "### Project Structure",
    ):
        assert removed_heading not in readme


def test_current_diagrams_are_embedded_on_the_relevant_wiki_pages():
    """Each diagram is discoverable from the Wiki topic it explains."""
    placements = {
        "system-trust-boundaries.png": (
            "Home.md",
            "Architecture-and-Runtime-Lifecycle.md",
        ),
        "authentication-assurance.png": ("Authentication-Overview.md",),
        "session-and-transfer-lifecycle.png": (
            "Terminal-and-Persistent-tmux-Sessions.md",
            "SFTP-File-Workspace-and-Transfers.md",
        ),
        "backup-restore-safety.png": (
            "Backup-Restore-and-Secret-Rotation.md",
        ),
    }
    for image, pages in placements.items():
        for page in pages:
            assert f"docs/media/diagrams/{image}?raw=true" in wiki_text(page)


def test_current_workspace_and_session_flows_are_documented():
    """The Wiki covers the current focused and capability-aware workspace."""
    terminal = wiki_text("Terminal-and-Persistent-tmux-Sessions.md")
    for phrase in (
        "focused session workspace",
        "capability",
        "persistent tmux",
        "sudo",
        "manual reconnect",
        "Files",
    ):
        assert phrase.lower() in terminal.lower()


def test_current_sftp_workspace_is_documented_without_active_smb_claims():
    """The file guide is current while keeping SMB explicitly unavailable."""
    sftp = wiki_text("SFTP-File-Workspace-and-Transfers.md")
    for phrase in ("source", "independent", "server-to-server", "transfer queue"):
        assert phrase.lower() in sftp.lower()
    assert "SMB" in sftp and "Coming soon" in sftp
    assert "SMB connection is available" not in sftp


def test_current_authentication_assurance_is_documented():
    """The identity guide describes current MFA and Admin step-up contracts."""
    auth = wiki_text("Authentication-Overview.md")
    for phrase in (
        "authentication assurance",
        "authenticator app",
        "action-bound",
        "administrator step-up",
        "OIDC",
        "LDAP",
        "passkey",
    ):
        assert phrase.lower() in auth.lower()


def test_ldap_provisioning_contract_is_documented():
    """The Wiki distinguishes safe default linking from explicit provisioning."""
    ldap = wiki_text("LDAP-and-Active-Directory.md")
    assert "LDAP_AUTO_PROVISION=false" in ldap
    assert "LDAP_AUTO_PROVISION=true" in ldap
    assert "non-admin" in ldap
    assert "never claims an existing local username" in ldap


def test_recovery_codes_are_not_documented_as_generic_password_bypass():
    """Recovery codes retain their implemented second-factor-only boundary."""
    recovery = wiki_text("Passkeys-and-Recovery-Codes.md")
    assert "second-factor recovery" in recovery.lower()
    assert "alternative password" not in recovery.lower()


def test_current_runtime_and_proxy_contracts_are_documented():
    """The operator guide covers native threading and all supported proxies."""
    architecture = wiki_text("Architecture-and-Runtime-Lifecycle.md")
    proxy = wiki_text("Reverse-Proxy-and-Subfolder-Deployment.md")
    for phrase in ("gthread", "exactly one", "threading", "HTTP reserve"):
        assert phrase.lower() in architecture.lower()
    for proxy_name in ("Nginx", "Traefik", "Caddy", "Apache"):
        assert proxy_name in proxy


def test_supported_python_versions_are_documented():
    """Development docs retain both the support floor and production runtime."""
    development = wiki_text("Development-and-Testing.md")
    assert "Python 3.11" in development
    assert "Python 3.14" in development
