"""Public contracts for the repository README and GitHub Pages artifact."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PAGES_WORKFLOW = ROOT / ".github" / "workflows" / "graph-pages.yml"
GRAPHIFY_IGNORE = ROOT / ".graphifyignore"
LANDING_PAGE = ROOT / "site" / "index.html"
SESSION_WORKSPACE_IMAGE = ROOT / "assets" / "session-workspace.png"
SESSION_DIAGNOSTICS_IMAGE = ROOT / "assets" / "session-diagnostics.png"


@pytest.mark.parametrize(
    "public_url",
    [
        "https://github.com/bifrost0x/webssh/pkgs/container/webssh",
        "https://bifrost0x.github.io/webssh/",
        "https://bifrost0x.github.io/webssh/code-graph/",
    ],
)
def test_readme_exposes_the_public_product_entry_points(public_url):
    """Users can reach the package, product site, and separate code graph."""
    assert public_url in README.read_text(encoding="utf-8")


def test_pages_workflow_publishes_product_root_and_code_graph_subpath():
    """The Pages artifact keeps the product root separate from Graphify output."""
    workflow = PAGES_WORKFLOW.read_text(encoding="utf-8")

    assert "cp -R site/. _site/" in workflow
    assert "mkdir -p _site/code-graph" in workflow
    assert "cp graphify-out/graph.html _site/code-graph/index.html" in workflow


def test_code_graph_excludes_vendored_runtime_dependencies():
    """The public code graph stays focused on first-party project code."""
    patterns = {
        line.strip()
        for line in GRAPHIFY_IGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "/static/vendor/" in patterns
    assert "/site/vendor/" in patterns


def test_readme_code_map_badge_targets_graph_subpath():
    """The project-structure badge opens Graphify, not the product landing page."""
    readme = README.read_text(encoding="utf-8")
    badge = "Interaktive%20Code--Map"
    badge_position = readme.index(badge)
    link_position = readme.rfind("<a href=", 0, badge_position)

    assert (
        'href="https://bifrost0x.github.io/webssh/code-graph/"'
        in readme[link_position:badge_position]
    )


def test_product_landing_page_uses_current_connection_terminology():
    """Public landing-page copy does not preserve labels replaced in the UI."""
    assert LANDING_PAGE.is_file(), "The public product landing page is missing."

    landing_page = LANDING_PAGE.read_text(encoding="utf-8")
    for obsolete_label in ("New Connection", "New SSH Connection", "Profiles"):
        assert obsolete_label not in landing_page


def test_public_surfaces_use_the_large_real_session_workspace_capture():
    """The new workspace is shown with a desktop-sized product capture."""
    image_reference = "assets/session-workspace.png"
    assert image_reference in README.read_text(encoding="utf-8")
    assert image_reference in LANDING_PAGE.read_text(encoding="utf-8")

    png = SESSION_WORKSPACE_IMAGE.read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width = int.from_bytes(png[16:20], "big")
    height = int.from_bytes(png[20:24], "big")
    assert width >= 1920
    assert height >= 1080


def test_readme_documents_session_diagnostics_with_a_large_capture():
    """Monitoring, diagnostics, and safe service actions stay public."""
    readme = README.read_text(encoding="utf-8")
    for feature in (
        "Active Session Monitoring",
        "Expanded Diagnostics",
        "Clipboard-Only Service Actions",
    ):
        assert feature in readme

    assert "assets/session-diagnostics.png" in readme
    png = SESSION_DIAGNOSTICS_IMAGE.read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert int.from_bytes(png[16:20], "big") >= 1920
    assert int.from_bytes(png[20:24], "big") >= 1080
