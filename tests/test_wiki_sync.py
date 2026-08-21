"""Behavioral tests for publishing the canonical Wiki source."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.wiki_sync import sync_wiki


class WikiSyncTests(unittest.TestCase):
    def make_wiki_source(self, root: Path) -> Path:
        source = root / "source"
        source.mkdir()
        (source / "Home.md").write_text("# Home\n", encoding="utf-8")
        (source / "_Sidebar.md").write_text("[Home](Home)\n", encoding="utf-8")
        (source / "_Footer.md").write_text("Versioned source\n", encoding="utf-8")
        return source

    def make_wiki_checkout(self, root: Path) -> Path:
        destination = root / "wiki"
        destination.mkdir()
        (destination / ".git").mkdir()
        return destination

    def test_sync_mirrors_markdown_pages_without_touching_other_files(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            destination = self.make_wiki_checkout(root)
            (source / "Quick-Start.md").write_text(
                "# Quick Start\n", encoding="utf-8"
            )
            (destination / "Home.md").write_text(
                "# Stale home\n", encoding="utf-8"
            )
            (destination / "Removed-Page.md").write_text(
                "# Removed\n", encoding="utf-8"
            )
            (destination / "attachment.png").write_bytes(b"keep")

            result = sync_wiki(source, destination)

            self.assertEqual(
                {path.name for path in destination.glob("*.md")},
                {"Home.md", "Quick-Start.md", "_Sidebar.md", "_Footer.md"},
            )
            self.assertEqual(
                (destination / "Home.md").read_text(encoding="utf-8"),
                "# Home\n",
            )
            self.assertEqual((destination / "attachment.png").read_bytes(), b"keep")
            self.assertEqual(result.copied, 4)
            self.assertEqual(result.removed, 1)

    def test_sync_rejects_non_markdown_source_artifacts(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            destination = self.make_wiki_checkout(root)
            (source / "notes.txt").write_text("not a Wiki page", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Markdown files"):
                sync_wiki(source, destination)

    def test_sync_requires_the_navigation_pages(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            destination = self.make_wiki_checkout(root)
            (source / "_Footer.md").unlink()

            with self.assertRaisesRegex(ValueError, "_Footer.md"):
                sync_wiki(source, destination)

    def test_sync_refuses_a_destination_that_is_not_a_git_checkout(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            destination = root / "not-a-checkout"
            destination.mkdir()
            (destination / "valuable.md").write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Git checkout"):
                sync_wiki(source, destination)

            self.assertEqual(
                (destination / "valuable.md").read_text(encoding="utf-8"),
                "keep",
            )


if __name__ == "__main__":
    unittest.main()
