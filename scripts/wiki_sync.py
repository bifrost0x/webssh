"""Mirror the versioned Wiki pages into a cloned GitHub Wiki checkout."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


REQUIRED_PAGES = {"Home.md", "_Sidebar.md", "_Footer.md"}
PUBLISHED_PAGE_SUFFIXES = {".md", ".markdown"}


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


def _require_git_toplevel(destination: Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(destination), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError("Wiki destination must be an existing Git checkout")
    try:
        top_level = Path(result.stdout.strip()).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(
            "Wiki destination must be an existing Git checkout"
        ) from exc
    if top_level != destination:
        raise ValueError("Wiki destination must be the Git checkout top-level")


def _published_pages(destination: Path) -> dict[str, Path]:
    pages: dict[str, Path] = {}
    for entry in destination.iterdir():
        if entry.suffix.lower() not in PUBLISHED_PAGE_SUFFIXES:
            continue
        if entry.is_symlink():
            raise ValueError(
                f"Wiki destination page must not be a symbolic link: {entry.name}"
            )
        if not entry.is_file():
            raise ValueError(
                f"Wiki destination page must be a regular file: {entry.name}"
            )
        pages[entry.name] = entry
    return pages


def _copy_page(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".wiki-sync-{destination.name}-",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary_page = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        if destination.is_symlink() or (
            destination.exists() and not destination.is_file()
        ):
            raise ValueError(
                "Wiki destination page must be a regular non-symlink file: "
                f"{destination.name}"
            )
        os.replace(temporary_page, destination)
    finally:
        temporary_page.unlink(missing_ok=True)


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

    _require_git_toplevel(destination_path)
    pages = _canonical_pages(source_path)
    published_pages = _published_pages(destination_path)
    removed = 0
    for existing in published_pages.values():
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

        _copy_page(source_page, destination_page)
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
