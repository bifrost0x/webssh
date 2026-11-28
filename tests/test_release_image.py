"""Release promotion must preserve the tested, scanned image identity."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from scripts.release_image import inspect_candidate, promote, validate_index


IMAGE = 'ghcr.io/bifrost0x/webssh'
REVISION = '1' * 40
DIGEST = 'sha256:' + 'a' * 64
AMD64 = 'sha256:' + 'b' * 64
ARM64 = 'sha256:' + 'c' * 64
INDEX = {
    'schemaVersion': 2,
    'mediaType': 'application/vnd.oci.image.index.v1+json',
    'manifests': [
        {'digest': AMD64, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
        {'digest': ARM64, 'platform': {'os': 'linux', 'architecture': 'arm64'}},
        {'digest': 'sha256:' + 'd' * 64,
         'platform': {'os': 'unknown', 'architecture': 'unknown'},
         'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                         'vnd.docker.reference.digest': AMD64}},
        {'digest': 'sha256:' + 'e' * 64,
         'platform': {'os': 'unknown', 'architecture': 'unknown'},
         'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                         'vnd.docker.reference.digest': ARM64}},
    ],
}


class Registry:
    def __init__(self):
        self.calls = []
        self.index = deepcopy(INDEX)
        self.revisions = {'amd64': REVISION, 'arm64': REVISION}
        self.published_digest = DIGEST
        self.main_revision = REVISION

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        assert kwargs['check'] is True
        assert kwargs.get('shell', False) is False
        if args[:3] == ['git', 'ls-remote', '--exit-code']:
            assert args[3:] == ['origin', 'refs/heads/main']
            return SimpleNamespace(stdout=self.main_revision + '\trefs/heads/main\n')
        assert args[:3] == ['docker', 'buildx', 'imagetools']
        if args[3] == 'create':
            return SimpleNamespace(stdout='')
        reference = args[-1]
        if '--raw' in args:
            return SimpleNamespace(stdout=json.dumps(self.index))
        template = args[args.index('--format') + 1]
        if template == '{{.Manifest.Digest}}':
            digest = DIGEST if '@' in reference else self.published_digest
            return SimpleNamespace(stdout=digest + '\n')
        assert template == '{{json .Image}}'
        arch = 'amd64' if reference.endswith(AMD64) else 'arm64'
        return SimpleNamespace(stdout=json.dumps({
            'architecture': arch, 'os': 'linux',
            'config': {'Labels': {'org.opencontainers.image.revision': self.revisions[arch]}},
        }))


def test_promotion_copies_one_complete_index_without_rebuilding():
    registry = Registry()
    tags = [IMAGE + ':2.4.0', IMAGE + ':2.4', IMAGE + ':latest']
    evidence = promote(IMAGE, DIGEST, REVISION, tags, runner=registry)
    create = [call for call in registry.calls if call[3] == 'create']
    assert len(create) == 1
    assert create[0][-1] == IMAGE + '@' + DIGEST
    assert all(tag in create[0] for tag in tags)
    assert evidence['digest'] == DIGEST
    assert evidence['revision'] == REVISION
    assert evidence['platforms'] == {'linux/amd64': AMD64, 'linux/arm64': ARM64}
    assert evidence['tags'] == tags
    assert all(call[:3] == ['docker', 'buildx', 'imagetools'] for call in registry.calls)


@pytest.mark.parametrize('change', ['missing-arm', 'duplicate-amd', 'unexpected-os', 'missing-attestation', 'bad-digest'])
def test_invalid_candidate_never_reaches_tag_publication(change):
    registry = Registry()
    if change == 'missing-arm':
        registry.index['manifests'].pop(1)
    elif change == 'duplicate-amd':
        registry.index['manifests'].append(deepcopy(INDEX['manifests'][0]))
    elif change == 'unexpected-os':
        registry.index['manifests'][1]['platform']['os'] = 'windows'
    elif change == 'missing-attestation':
        registry.index['manifests'].pop()
    else:
        registry.index['manifests'][0]['digest'] = 'latest'
    with pytest.raises(ValueError):
        promote(IMAGE, DIGEST, REVISION, [IMAGE + ':latest'], runner=registry)
    assert not any(call[3] == 'create' for call in registry.calls)


def test_both_architectures_must_belong_to_the_verified_commit():
    registry = Registry()
    registry.revisions['arm64'] = '2' * 40
    with pytest.raises(ValueError, match='revision'):
        promote(IMAGE, DIGEST, REVISION, [IMAGE + ':latest'], runner=registry)
    assert not any(call[3] == 'create' for call in registry.calls)


@pytest.mark.parametrize('tags', [[], ['another/image:latest'], [IMAGE + ':latest\n--append'], [IMAGE + ':x', IMAGE + ':x']])
def test_tags_are_bounded_and_stay_in_the_candidate_repository(tags):
    registry = Registry()
    with pytest.raises(ValueError):
        promote(IMAGE, DIGEST, REVISION, tags, runner=registry)
    assert registry.calls == []


def test_wrong_published_digest_is_reported_as_failure():
    registry = Registry()
    registry.published_digest = 'sha256:' + 'f' * 64
    with pytest.raises(ValueError, match='digest'):
        promote(IMAGE, DIGEST, REVISION, [IMAGE + ':latest'], runner=registry)


def test_inspection_is_read_only_and_records_both_child_digests():
    registry = Registry()
    evidence = inspect_candidate(IMAGE, DIGEST, REVISION, runner=registry)
    assert evidence['immutable_ref'] == IMAGE + '@' + DIGEST
    assert evidence['platforms'] == validate_index(INDEX)
    assert all(call[3] == 'inspect' for call in registry.calls)


@pytest.mark.parametrize('current_main', ['2' * 40, '', 'invalid'])
def test_stale_or_invalid_main_never_reaches_promotion(current_main):
    registry = Registry()
    registry.main_revision = current_main
    with pytest.raises(ValueError, match='main'):
        promote(IMAGE, DIGEST, REVISION, [IMAGE + ':main'],
                require_current_main=True, runner=registry)
    assert not any(call[0] == 'docker' and call[3] == 'create' for call in registry.calls)


def test_current_main_is_rechecked_after_inspection_before_tag_writes():
    registry = Registry()
    promote(IMAGE, DIGEST, REVISION, [IMAGE + ':main'],
            require_current_main=True, runner=registry)
    guard = next(i for i, call in enumerate(registry.calls) if call[0] == 'git')
    create = next(i for i, call in enumerate(registry.calls) if call[3] == 'create')
    assert guard == create - 1
    assert all(call[3] == 'inspect' for call in registry.calls[:guard])


def test_version_tag_promotion_does_not_require_current_main():
    registry = Registry()
    registry.main_revision = '2' * 40
    promote(IMAGE, DIGEST, REVISION, [IMAGE + ':2.4.0'], runner=registry)
    assert all(call[0] == 'docker' for call in registry.calls)


class NativeRegistry(Registry):
    """Registry fixture with one immutable attested index per native build."""

    def __init__(self):
        super().__init__()
        self.native = {
            'sha256:' + '6' * 64: {**deepcopy(INDEX), 'manifests': [deepcopy(INDEX['manifests'][i]) for i in (0, 2)]},
            'sha256:' + '7' * 64: {**deepcopy(INDEX), 'manifests': [deepcopy(INDEX['manifests'][i]) for i in (1, 3)]},
        }
        self.drop_attestation = False
        self.change_attestation = False

    def __call__(self, args, **kwargs):
        if args[:3] == ['docker', 'buildx', 'imagetools'] and args[3] == 'inspect':
            reference = args[-1]
            candidate_digest = reference.partition('@')[2]
            if candidate_digest in self.native:
                self.calls.append(args)
                if '--raw' in args:
                    return SimpleNamespace(stdout=json.dumps(self.native[candidate_digest]))
                return SimpleNamespace(stdout=candidate_digest)
        if args[:4] == ['docker', 'buildx', 'imagetools', 'create']:
            if ':candidate-' in ' '.join(args):
                self.index['manifests'] = [deepcopy(d) for index in self.native.values() for d in index['manifests']]
                if self.drop_attestation:
                    self.index['manifests'].pop()
                if self.change_attestation:
                    self.index['manifests'][-1]['digest'] = 'sha256:' + '8' * 64
        return super().__call__(args, **kwargs)


def native_evidence(registry):
    from scripts import release_image
    return [release_image.inspect_platform(
        IMAGE, digest, REVISION, 'linux/' + arch, '123', '2', runner=registry,
    ) for digest, arch in zip(registry.native, ('amd64', 'arm64'))]


def test_native_platform_evidence_binds_full_index_child_commit_and_attempt():
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    assert evidence[0]['platforms'] == {'linux/amd64': AMD64}
    assert evidence[0]['run_id'] == '123'
    assert evidence[0]['run_attempt'] == '2'
    assert evidence[0]['digest'] == next(iter(registry.native))
    assert evidence[0]['revision'] == REVISION
    assert all(call[3] == 'inspect' for call in registry.calls)


def test_assembly_preserves_exact_native_descriptors_before_promotion():
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    combined = release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
    assert combined['digest'] == DIGEST
    assert combined['platforms'] == {'linux/amd64': AMD64, 'linux/arm64': ARM64}
    creates = [call for call in registry.calls if call[3] == 'create']
    assert creates == [[
        'docker', 'buildx', 'imagetools', 'create', '--tag', IMAGE + ':candidate-123-2',
        *[item['immutable_ref'] for item in evidence],
    ]]
    promote(IMAGE, combined['digest'], REVISION, [IMAGE + ':main'], runner=registry)
    assert registry.index['manifests'] == [d for index in registry.native.values() for d in index['manifests']]


def test_debug_assembly_keeps_its_own_candidate_tag():
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    release_image.assemble(IMAGE, REVISION, evidence, '123', '2', variant='debug', runner=registry)
    creates = [call for call in registry.calls if call[3] == 'create']
    assert [call[5] for call in creates] == [IMAGE + ':candidate-123-2-debug']
    with pytest.raises(ValueError, match='Unknown image variant'):
        release_image.assemble(IMAGE, REVISION, evidence, '123', '2', variant='latest', runner=registry)


@pytest.mark.parametrize('field,value', [
    ('repository', 'ghcr.io/another/image'), ('revision', '2' * 40),
    ('run_id', '456'), ('run_attempt', '3'), ('digest', AMD64),
    ('immutable_ref', IMAGE + ':main'), ('platforms', {'linux/amd64': ARM64}),
])
def test_mismatched_platform_evidence_cannot_write_even_a_candidate_tag(field, value):
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    evidence[0][field] = value
    with pytest.raises(ValueError):
        release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
    assert not any(call[3] == 'create' for call in registry.calls)


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'extra', 'missing-attestation', 'wrong-revision'])
def test_incomplete_native_candidates_are_rejected_before_assembly(change):
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    if change == 'missing':
        evidence.pop()
    elif change == 'duplicate':
        evidence[1] = evidence[0]
    elif change == 'extra':
        evidence.append(evidence[0])
    elif change == 'missing-attestation':
        registry.native[evidence[1]['digest']]['manifests'].pop()
    else:
        registry.revisions['arm64'] = '2' * 40
    with pytest.raises(ValueError):
        release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
    assert not any(call[3] == 'create' for call in registry.calls)


def test_assembly_that_loses_attestation_cannot_be_promoted():
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    registry.drop_attestation = True
    with pytest.raises(ValueError, match='attestation'):
        combined = release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
        promote(IMAGE, combined['digest'], REVISION, [IMAGE + ':main'], runner=registry)
    creates = [call for call in registry.calls if call[3] == 'create']
    assert len(creates) == 1
    assert IMAGE + ':main' not in creates[0]


@pytest.mark.parametrize('run_id,attempt', [('123/main', '2'), ('123', '0'), ('', '1')])
def test_invalid_run_identity_cannot_create_candidate_tags(run_id, attempt):
    from scripts import release_image
    registry = NativeRegistry()
    with pytest.raises(ValueError):
        release_image.assemble(IMAGE, REVISION, native_evidence(registry), run_id, attempt, runner=registry)
    assert not any(call[3] == 'create' for call in registry.calls)


def test_retry_can_reuse_successful_native_build_from_prior_attempt_of_same_run():
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    evidence[0]['run_attempt'] = '1'
    combined = release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
    assert combined['platforms'] == {'linux/amd64': AMD64, 'linux/arm64': ARM64}


def test_assembly_cannot_substitute_another_attestation_for_a_checked_descriptor():
    from scripts import release_image
    registry = NativeRegistry()
    evidence = native_evidence(registry)
    registry.change_attestation = True
    with pytest.raises(ValueError, match='descriptors'):
        combined = release_image.assemble(IMAGE, REVISION, evidence, '123', '2', runner=registry)
        promote(IMAGE, combined['digest'], REVISION, [IMAGE + ':main'], runner=registry)
    creates = [call for call in registry.calls if call[3] == 'create']
    assert len(creates) == 1
    assert IMAGE + ':main' not in creates[0]
