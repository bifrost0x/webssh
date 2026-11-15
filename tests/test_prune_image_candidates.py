"""Candidate pruning must never touch release tags or manifests they reference."""

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from scripts.prune_image_candidates import apply, child_digests, list_versions, plan


IMAGE = 'ghcr.io/bifrost0x/webssh'
NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
OLD = (NOW - timedelta(days=30)).isoformat().replace('+00:00', 'Z')
YOUNG = (NOW - timedelta(days=1)).isoformat().replace('+00:00', 'Z')
MIN_AGE = timedelta(days=14)
INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'


def digest(char):
    return 'sha256:' + char * 64


def version(version_id, char, tags, created=OLD):
    return {
        'id': version_id, 'name': digest(char), 'created_at': created,
        'metadata': {'package_type': 'container', 'container': {'tags': tags}},
    }


class Registry:
    def __init__(self, versions, indexes):
        self.versions = versions
        self.indexes = indexes
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        assert kwargs['check'] is True
        assert kwargs.get('shell', False) is False
        if args[:2] == ['gh', 'api']:
            method, path = args[3], args[4]
            if method == 'DELETE':
                return SimpleNamespace(stdout='')
            assert method == 'GET'
            page = int(path.rsplit('page=', 1)[1])
            return SimpleNamespace(stdout=json.dumps(self.versions[(page - 1) * 100:page * 100]))
        assert args[:5] == ['docker', 'buildx', 'imagetools', 'inspect', '--raw']
        reference = args[5]
        assert reference.startswith(IMAGE + '@')
        children = self.indexes.get(reference.split('@', 1)[1])
        if children is None:
            return SimpleNamespace(stdout=json.dumps({'schemaVersion': 2, 'mediaType': MANIFEST}))
        return SimpleNamespace(stdout=json.dumps({
            'schemaVersion': 2, 'mediaType': INDEX,
            'manifests': [{'digest': child} for child in children],
        }))


def _plan(registry):
    versions = list_versions('bifrost0x', 'webssh', runner=registry)
    return plan(versions, IMAGE, NOW, MIN_AGE, runner=registry)


def _deleted_ids(result):
    return [item['id'] for item in result['deletions']]


def test_promoted_candidate_and_release_children_survive():
    registry = Registry(
        [
            version(1, 'a', ['latest', 'main', 'candidate-10-1']),
            version(2, 'b', []),  # amd64 child of the release
            version(3, 'c', []),  # attestation of the release
            version(4, 'd', ['3.1.0', '3.1', 'candidate-9-1']),
            version(5, 'e', []),
        ],
        {digest('a'): [digest('b'), digest('c')], digest('d'): [digest('e')]},
    )
    assert _deleted_ids(_plan(registry)) == []


def test_stale_superseded_candidate_and_its_exclusive_children_are_removed():
    registry = Registry(
        [
            version(1, 'a', ['latest', 'candidate-10-1']),
            version(2, 'b', []),
            version(3, 'f', ['candidate-8-1']),
            version(4, '7', []),
            version(5, '8', []),
        ],
        {digest('a'): [digest('b')], digest('f'): [digest('7'), digest('b')]},
    )
    result = _plan(registry)
    # The candidate index goes before its children; shared child b survives.
    assert _deleted_ids(result) == [3, 4, 5]
    # A doomed candidate is never inspected, so its children are not protected.
    assert ['docker', 'buildx', 'imagetools', 'inspect', '--raw', f'{IMAGE}@{digest("f")}'] \
        not in registry.calls


def test_young_candidates_and_in_flight_native_builds_are_kept():
    registry = Registry(
        [
            version(1, 'a', ['latest']),
            version(2, 'f', ['candidate-11-2'], created=YOUNG),
            version(3, '7', [], created=YOUNG),
            version(4, '8', []),
        ],
        {digest('f'): [digest('8')]},
    )
    assert _deleted_ids(_plan(registry)) == []


def test_any_non_candidate_tag_protects_a_version():
    registry = Registry(
        [
            version(1, 'a', ['candidate-1-1', 'sha256-' + 'a' * 64 + '.sig']),
            version(2, 'b', ['candidate-01-1']),
            version(3, 'c', ['candidate-2-1-extra']),
        ],
        {},
    )
    assert _deleted_ids(_plan(registry)) == []


@pytest.mark.parametrize('broken', [
    {'id': 1, 'name': 'latest', 'created_at': OLD, 'metadata': {'container': {'tags': []}}},
    {'id': 1, 'name': digest('a'), 'created_at': OLD, 'metadata': {}},
    {'id': 1, 'name': digest('a'), 'created_at': OLD,
     'metadata': {'container': {'tags': ['bad tag']}}},
    {'id': True, 'name': digest('a'), 'created_at': OLD,
     'metadata': {'container': {'tags': []}}},
    {'id': 1, 'name': digest('a'), 'created_at': '2026-01-01T00:00:00',
     'metadata': {'container': {'tags': []}}},
])
def test_unexpected_listing_shapes_fail_closed(broken):
    with pytest.raises(ValueError):
        list_versions('bifrost0x', 'webssh', runner=Registry([broken], {}))


def test_duplicate_versions_fail_closed():
    registry = Registry([version(1, 'a', []), version(2, 'a', [])], {})
    with pytest.raises(ValueError, match='duplicates'):
        list_versions('bifrost0x', 'webssh', runner=registry)


def test_listing_paginates_until_a_short_page():
    versions = [version(index + 1, 'a', []) for index in range(100)]
    for index, item in enumerate(versions):
        item['name'] = 'sha256:' + f'{index:064x}'
    versions.append(version(101, 'f', []))
    registry = Registry(versions, {})
    assert len(list_versions('bifrost0x', 'webssh', runner=registry)) == 101
    assert [call[4].rsplit('page=', 1)[1] for call in registry.calls] == ['1', '2']


def test_unexpected_manifest_type_fails_closed():
    def runner(args, **kwargs):
        return SimpleNamespace(stdout=json.dumps({'schemaVersion': 2, 'mediaType': 'text/plain'}))

    with pytest.raises(ValueError, match='Unexpected manifest type'):
        child_digests(IMAGE, digest('a'), runner=runner)


@pytest.mark.parametrize('owner, package', [
    ('bifrost0x/../x', 'webssh'), ('-bad', 'webssh'), ('bifrost0x', 'Web SSH'),
])
def test_api_paths_reject_injected_names(owner, package):
    with pytest.raises(ValueError):
        list_versions(owner, package, runner=Registry([], {}))


def test_apply_deletes_exactly_the_planned_version_ids():
    registry = Registry([], {})
    apply('bifrost0x', 'webssh', [{'id': 7}, {'id': 9}], runner=registry)
    assert registry.calls == [
        ['gh', 'api', '--method', 'DELETE', '/users/bifrost0x/packages/container/webssh/versions/7'],
        ['gh', 'api', '--method', 'DELETE', '/users/bifrost0x/packages/container/webssh/versions/9'],
    ]


def test_retention_workflow_shares_the_publisher_lock_and_defaults_to_dry_run():
    from pathlib import Path

    workflows = Path(__file__).resolve().parents[1] / '.github/workflows'
    retention = (workflows / 'image-retention.yml').read_text(encoding='utf-8')
    publish = (workflows / 'docker-publish.yml').read_text(encoding='utf-8')
    lock = 'group: image-publish-${{ github.repository }}'
    assert lock in publish and lock in retention
    assert 'permissions: {}' in retention
    assert retention.count('packages: write') == 1
    assert "if: github.ref == 'refs/heads/main'" in retention
    dispatch = retention.split('workflow_dispatch:', 1)[1].split('permissions:', 1)[0]
    assert 'default: false' in dispatch
    assert "APPLY: ${{ github.event_name == 'schedule' || inputs.apply }}" in retention
    assert 'persist-credentials: false' in retention
