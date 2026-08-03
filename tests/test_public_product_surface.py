"""Public contracts for the repository README and GitHub Pages artifact."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PAGES_WORKFLOW = ROOT / ".github" / "workflows" / "graph-pages.yml"
LANDING_PAGE = ROOT / "site" / "index.html"


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
