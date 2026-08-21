"""Mirror the versioned Wiki pages into a cloned GitHub Wiki checkout."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil


REQUIRED_PAGES = {"Home.md", "_Sidebar.md", "_Footer.md"}


@dataclass(frozen=True)
class SyncResult:
    copied: int
    removed: int
    unchanged: int


def _existing_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist: {path}") from exc
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a directory: {path}")
    return resolved


def _canonical_pages(source: Path) -> dict[str, Path]:
    pages: dict[str, Path] = {}
    for entry in source.iterdir():
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".md":
            raise ValueError(
                "The canonical Wiki source may contain Markdown files only: "
                f"{entry.name}"
            )
        pages[entry.name] = entry

    missing = sorted(REQUIRED_PAGES - pages.keys())
    if missing:
        raise ValueError(
            "The canonical Wiki source is missing required pages: "
            + ", ".join(missing)
        )
    return pages


def sync_wiki(source: Path | str, destination: Path | str) -> SyncResult:
    """Mirror top-level Markdown pages without deleting non-page attachments."""
    source_path = _existing_directory(Path(source), "Wiki source")
    destination_path = _existing_directory(
        Path(destination), "Wiki destination"
    )

    if (
        source_path == destination_path
        or source_path in destination_path.parents
        or destination_path in source_path.parents
    ):
        raise ValueError("Wiki source and destination must not overlap")

    git_metadata = destination_path / ".git"
    if git_metadata.is_symlink() or not git_metadata.exists():
        raise ValueError("Wiki destination must be an existing Git checkout")

    pages = _canonical_pages(source_path)
    removed = 0
    for existing in destination_path.glob("*.md"):
        if existing.is_symlink():
            raise ValueError(
                f"Wiki destination page must not be a symbolic link: {existing.name}"
            )
        if existing.name not in pages:
            existing.unlink()
            removed += 1

    copied = 0
    unchanged = 0
    for name, source_page in sorted(pages.items()):
        destination_page = destination_path / name
        if destination_page.is_symlink():
            raise ValueError(
                f"Wiki destination page must not be a symbolic link: {name}"
            )
        if (
            destination_page.is_file()
            and destination_page.read_bytes() == source_page.read_bytes()
        ):
            unchanged += 1
            continue

        temporary_page = destination_path / f".{name}.wiki-sync.tmp"
        try:
            shutil.copyfile(source_page, temporary_page)
            os.replace(temporary_page, destination_page)
        finally:
            temporary_page.unlink(missing_ok=True)
        copied += 1

    return SyncResult(copied=copied, removed=removed, unchanged=unchanged)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)

    try:
        result = sync_wiki(args.source, args.destination)
    except ValueError as exc:
        parser.exit(2, f"wiki-sync: {exc}\n")

    print(
        "Wiki pages synchronized: "
        f"{result.copied} copied, {result.removed} removed, "
        f"{result.unchanged} unchanged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
