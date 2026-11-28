"""Prune unreferenced, untagged manifests from GHCR.

Native per-platform builds and their attestations are pushed untagged and
only become reachable once a run assembles them into a tagged index. Runs
that fail before assembly leave orphans behind that nothing can pull by tag.

This script removes, after a minimum age, untagged versions that no tagged
index references. Tagged versions, including candidate-<run_id>-<attempt>[-debug]
tags, are never deleted: GHCR attributes download counts to versions, and
removing a version may remove its downloads from the package total.

It fails closed: any registry or API error, any unexpected tag or manifest
shape, or a plan larger than ``--max-deletions`` aborts before the first
deletion.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
from typing import Any


DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
TAG = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')
OWNER = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})')
PACKAGE = re.compile(r'[a-z0-9][a-z0-9._-]{0,99}')
INDEX_TYPES = frozenset({
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
})
MANIFEST_TYPES = INDEX_TYPES | frozenset({
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
})
PAGE_SIZE = 100
DEFAULT_MIN_AGE_DAYS = 90
MAX_PAGES = 100

Runner = Callable[..., Any]


def _run(arguments: list[str], runner: Runner) -> str:
    return runner(arguments, check=True, capture_output=True, text=True).stdout


def _versions_path(owner: str, package: str) -> str:
    if not OWNER.fullmatch(owner) or owner.endswith('-') or '--' in owner:
        raise ValueError('Invalid package owner')
    if not PACKAGE.fullmatch(package):
        raise ValueError('Invalid package name')
    return f'/users/{owner}/packages/container/{package}/versions'


def _parse_version(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError('Package version must be an object')
    version_id = raw.get('id')
    digest = raw.get('name')
    if not isinstance(version_id, int) or isinstance(version_id, bool) or version_id <= 0:
        raise ValueError('Invalid package version id')
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError(f'Package version {version_id} has no manifest digest')
    tags = raw.get('metadata', {}).get('container', {}).get('tags')
    if not isinstance(tags, list) or not all(isinstance(tag, str) and TAG.fullmatch(tag) for tag in tags):
        raise ValueError(f'Package version {version_id} has invalid tags')
    created = raw.get('created_at')
    if not isinstance(created, str):
        raise ValueError(f'Package version {version_id} has no creation time')
    created_at = datetime.fromisoformat(created)
    if created_at.tzinfo is None:
        raise ValueError(f'Package version {version_id} has a naive creation time')
    return {'id': version_id, 'digest': digest, 'tags': sorted(tags), 'created_at': created_at}


def list_versions(owner: str, package: str, *, runner: Runner = subprocess.run) -> list[dict[str, Any]]:
    """Read every package version, page by page, without writing anything."""
    path = _versions_path(owner, package)
    versions: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        batch = json.loads(_run(
            ['gh', 'api', '--method', 'GET', f'{path}?per_page={PAGE_SIZE}&page={page}'],
            runner,
        ))
        if not isinstance(batch, list):
            raise ValueError('Package version listing must be a list')
        versions.extend(_parse_version(item) for item in batch)
        if len(batch) < PAGE_SIZE:
            break
    else:
        raise ValueError('Package version listing exceeded the page limit')
    ids = [version['id'] for version in versions]
    digests = [version['digest'] for version in versions]
    if len(set(ids)) != len(ids) or len(set(digests)) != len(digests):
        raise ValueError('Package version listing contains duplicates')
    return versions


def child_digests(image: str, digest: str, *, runner: Runner = subprocess.run) -> set[str]:
    """Return every manifest an index references, including attestations."""
    if not DIGEST.fullmatch(digest):
        raise ValueError('Invalid manifest digest')
    document = json.loads(_run(
        ['docker', 'buildx', 'imagetools', 'inspect', '--raw', f'{image}@{digest}'],
        runner,
    ))
    media_type = document.get('mediaType')
    if document.get('schemaVersion') != 2 or media_type not in MANIFEST_TYPES:
        raise ValueError(f'Unexpected manifest type for {digest}')
    if media_type not in INDEX_TYPES:
        return set()
    children = set()
    for descriptor in document.get('manifests', []):
        child = descriptor.get('digest', '')
        if not isinstance(child, str) or not DIGEST.fullmatch(child):
            raise ValueError(f'Invalid child manifest digest in {digest}')
        children.add(child)
    return children


def plan(versions: list[dict[str, Any]], image: str, now: datetime, min_age: timedelta,
         *, runner: Runner = subprocess.run) -> dict[str, Any]:
    """Decide what to delete; read-only."""
    cutoff = now - min_age
    tagged = [version for version in versions if version['tags']]
    referenced: set[str] = set()
    for version in tagged:
        referenced |= child_digests(image, version['digest'], runner=runner)
    orphans = sorted(
        (version for version in versions
         if not version['tags'] and version['created_at'] <= cutoff
         and version['digest'] not in referenced),
        key=lambda v: v['created_at'],
    )
    for version in orphans:
        if version['tags'] or version['digest'] in referenced:
            raise AssertionError(f'Refusing to delete protected version {version["id"]}')
    return {
        'image': image,
        'cutoff': cutoff.isoformat(),
        'versions': len(versions),
        'kept_tagged': len(tagged),
        'referenced_children': len(referenced),
        'deletions': [
            {'id': v['id'], 'digest': v['digest'], 'tags': v['tags'],
             'created_at': v['created_at'].isoformat()}
            for v in orphans
        ],
    }


def apply(owner: str, package: str, deletions: list[dict[str, Any]],
          *, runner: Runner = subprocess.run) -> None:
    path = _versions_path(owner, package)
    for version in deletions:
        _run(['gh', 'api', '--method', 'DELETE', f'{path}/{version["id"]}'], runner)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--owner', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--image', required=True, help='e.g. ghcr.io/owner/package')
    parser.add_argument('--min-age-days', type=int, default=DEFAULT_MIN_AGE_DAYS)
    parser.add_argument('--max-deletions', type=int, default=200)
    parser.add_argument('--apply', action='store_true', help='Delete; otherwise only plan')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.min_age_days < 2:
        parser.error('--min-age-days must leave in-flight release runs untouched (>= 2)')
    if args.max_deletions < 1:
        parser.error('--max-deletions must be positive')
    if args.image != f'ghcr.io/{args.owner.lower()}/{args.package}':
        parser.error('--image must be the GHCR repository of --owner/--package')

    versions = list_versions(args.owner, args.package)
    result = plan(versions, args.image, datetime.now(timezone.utc),
                  timedelta(days=args.min_age_days))
    result['applied'] = False
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    count = len(result['deletions'])
    print(f'{count} of {result["versions"]} versions planned for deletion '
          f'(created before {result["cutoff"]}).')
    if count > args.max_deletions:
        raise SystemExit(f'Plan exceeds --max-deletions={args.max_deletions}; nothing deleted.')
    if args.apply and count:
        apply(args.owner, args.package, result['deletions'])
        result['applied'] = True
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(f'Deleted {count} versions.')


if __name__ == '__main__':
    main()
