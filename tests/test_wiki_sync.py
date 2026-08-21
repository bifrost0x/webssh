"""Behavioral tests for publishing the canonical Wiki source."""

from pathlib import Path
import subprocess
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
        subprocess.run(
            ["git", "init", "--quiet", str(destination)],
            check=True,
            capture_output=True,
            text=True,
        )
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
            (destination / "Rogue.markdown").write_text(
                "# Rogue\n", encoding="utf-8"
            )
            (destination / "attachment.png").write_bytes(b"keep")
            temporary_attachment = destination / ".Home.md.wiki-sync.tmp"
            temporary_attachment.write_bytes(b"keep temporary attachment")

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
            self.assertEqual(
                temporary_attachment.read_bytes(), b"keep temporary attachment"
            )
            self.assertEqual(result.copied, 4)
            self.assertEqual(result.removed, 2)

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

    def test_sync_refuses_fake_git_metadata_before_removing_pages(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            destination = root / "fake-checkout"
            destination.mkdir()
            (destination / ".git").write_text("not Git metadata", encoding="utf-8")
            valuable = destination / "valuable.md"
            valuable.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Git checkout"):
                sync_wiki(source, destination)

            self.assertEqual(valuable.read_text(encoding="utf-8"), "keep")

    def test_sync_rejects_page_symlinks_before_removing_stale_pages(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.make_wiki_source(root)
            (source / "ZZZ.md").write_text("linked", encoding="utf-8")
            destination = self.make_wiki_checkout(root)
            outside = root / "outside.md"
            outside.write_text("outside", encoding="utf-8")
            stale = destination / "AAA-Stale.md"
            stale.write_text("stale", encoding="utf-8")
            linked_page = destination / "ZZZ.md"
            try:
                linked_page.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "symbolic link"):
                sync_wiki(source, destination)

            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            self.assertEqual(stale.read_text(encoding="utf-8"), "stale")


if __name__ == "__main__":
    unittest.main()
