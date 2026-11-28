"""Inspect and promote one immutable multi-platform release candidate."""

import argparse
import json
from pathlib import Path
import re
import subprocess


DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
REVISION = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+')
TAG = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')
PLATFORMS = frozenset({'linux/amd64', 'linux/arm64'})
# Dockerfile targets published from one run; each keeps its own candidate tag.
VARIANTS = {'release': '', 'debug': '-debug'}
INDEX_TYPES = frozenset({
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
})


def validate_index(index, required_platforms=PLATFORMS):
    """Require exactly the requested runtime platforms and their attestations."""
    if index.get('schemaVersion') != 2 or index.get('mediaType') not in INDEX_TYPES:
        raise ValueError('Candidate must be a multi-platform image index')
    platforms = {}
    attestations = set()
    for descriptor in index.get('manifests', []):
        digest = descriptor.get('digest', '')
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Invalid child manifest digest')
        platform = descriptor.get('platform', {})
        name = f"{platform.get('os')}/{platform.get('architecture')}"
        if name in PLATFORMS:
            if name in platforms:
                raise ValueError('Duplicate runtime platform')
            platforms[name] = digest
        elif name == 'unknown/unknown':
            annotations = descriptor.get('annotations', {})
            if annotations.get('vnd.docker.reference.type') != 'attestation-manifest':
                raise ValueError('Unknown descriptor is not an attestation')
            attestations.add(annotations.get('vnd.docker.reference.digest'))
        else:
            raise ValueError('Unexpected runtime platform')
    if set(platforms) != required_platforms:
        raise ValueError('Candidate must contain exactly the required runtime platforms')
    if set(platforms.values()) != attestations:
        raise ValueError('Each runtime platform must retain its attestation')
    return platforms


def _identity(image, digest, revision):
    if not REPOSITORY.fullmatch(image) or '..' in image or '//' in image:
        raise ValueError('Invalid image repository')
    if not DIGEST.fullmatch(digest):
        raise ValueError('Invalid candidate digest')
    if not REVISION.fullmatch(revision):
        raise ValueError('Invalid source revision')


def _docker(arguments, runner):
    return runner(
        ['docker', 'buildx', 'imagetools', *arguments],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def inspect_candidate(image, digest, revision, *, runner=subprocess.run,
                      required_platforms=PLATFORMS):
    """Read registry identity and source labels without writing any tags."""
    _identity(image, digest, revision)
    reference = f'{image}@{digest}'
    actual = _docker(['inspect', '--format', '{{.Manifest.Digest}}', reference], runner)
    if actual != digest:
        raise ValueError('Candidate digest does not match registry identity')
    index = json.loads(_docker(['inspect', '--raw', reference], runner))
    platforms = validate_index(index, required_platforms)
    for platform, child in platforms.items():
        config = json.loads(_docker([
            'inspect', '--format', '{{json .Image}}', f'{image}@{child}',
        ], runner))
        if f"{config.get('os')}/{config.get('architecture')}" != platform:
            raise ValueError('Child config does not match its declared platform')
        labels = config.get('config', {}).get('Labels', {})
        if labels.get('org.opencontainers.image.revision') != revision:
            raise ValueError('Candidate revision does not match the tested commit')
    return {
        'repository': image, 'revision': revision, 'digest': digest,
        'immutable_ref': reference, 'platforms': platforms,
        'manifests': index['manifests'],
    }


def _run_identity(run_id, run_attempt):
    for value in (run_id, run_attempt):
        if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*', value):
            raise ValueError('Invalid workflow run identity')


def inspect_platform(image, digest, revision, platform, run_id, run_attempt,
                     *, runner=subprocess.run):
    """Bind a native attested build to its workflow run and exact source."""
    _run_identity(run_id, run_attempt)
    if platform not in PLATFORMS:
        raise ValueError('Unexpected runtime platform')
    evidence = inspect_candidate(image, digest, revision, runner=runner,
                                 required_platforms=frozenset({platform}))
    return {**evidence, 'run_id': run_id, 'run_attempt': run_attempt}


def assemble(image, revision, candidates, run_id, run_attempt, *, variant='release',
             runner=subprocess.run):
    """Combine successful native build evidence into a non-release candidate.

    The caller downloads only success artifacts from this run, after
    both scan and runtime jobs succeed. Reinspect every immutable source before
    writing even the candidate tag, then verify all descriptors survived.
    The variant names the Dockerfile target, so the release and debug
    indexes of one run never share, and overwrite, a candidate tag.
    """
    _run_identity(run_id, run_attempt)
    if variant not in VARIANTS:
        raise ValueError('Unknown image variant')
    if not isinstance(candidates, list) or len(candidates) != len(PLATFORMS):
        raise ValueError('Exactly two native candidates are required')
    by_platform = {}
    for evidence in candidates:
        if not isinstance(evidence, dict):
            raise ValueError('Invalid native candidate evidence')
        if (evidence.get('repository'), evidence.get('revision'),
                evidence.get('run_id')) != (image, revision, run_id):
            raise ValueError('Native candidate identity does not match this workflow run')
        attempt = evidence.get('run_attempt')
        _run_identity(run_id, attempt)
        if int(attempt) > int(run_attempt):
            raise ValueError('Native candidate belongs to a future workflow attempt')
        platforms = evidence.get('platforms')
        if not isinstance(platforms, dict) or len(platforms) != 1:
            raise ValueError('Each native candidate must describe one platform')
        platform = next(iter(platforms))
        if platform not in PLATFORMS or platform in by_platform:
            raise ValueError('Missing or duplicate native candidate platform')
        actual = inspect_platform(image, evidence.get('digest', ''), revision,
                                  platform, run_id, attempt, runner=runner)
        if actual != evidence:
            raise ValueError('Native candidate evidence does not match the registry')
        by_platform[platform] = actual
    ordered = [by_platform[platform] for platform in sorted(PLATFORMS)]
    candidate_tag = f'{image}:candidate-{run_id}-{run_attempt}{VARIANTS[variant]}'
    _docker(['create', '--tag', candidate_tag,
             *[item['immutable_ref'] for item in ordered]], runner)
    digest = _docker(['inspect', '--format', '{{.Manifest.Digest}}', candidate_tag], runner)
    combined = inspect_candidate(image, digest, revision, runner=runner)
    expected = [descriptor for item in ordered for descriptor in item['manifests']]
    # Descriptor order is immaterial; all metadata, including attestations,
    # must be retained exactly at the JSON value level.
    def canonical(values):
        return sorted(json.dumps(value, sort_keys=True) for value in values)

    if canonical(combined['manifests']) != canonical(expected):
        raise ValueError('Assembly changed the checked native manifest descriptors')
    return combined


def promote(image, digest, revision, tags, *, require_current_main=False,
            runner=subprocess.run):
    """Copy the complete checked index, then verify every destination tag."""
    _identity(image, digest, revision)
    if not tags or len(tags) > 16 or len(set(tags)) != len(tags):
        raise ValueError('A bounded, nonempty list of unique tags is required')
    prefix = image + ':'
    for tag in tags:
        if not tag.startswith(prefix) or not TAG.fullmatch(tag[len(prefix):]):
            raise ValueError('Release tags must stay in the candidate repository')
    evidence = inspect_candidate(image, digest, revision, runner=runner)
    arguments = ['create']
    for tag in tags:
        arguments.extend(['--tag', tag])
    # A single existing index is copied verbatim, including attestations.
    # Adding annotations, platform filters or child sources would change it.
    arguments.append(evidence['immutable_ref'])
    if require_current_main:
        # Test jobs run in parallel, so queue arrival need not match push order.
        # Recheck inside the publisher lock immediately before changing tags.
        remote = runner(
            ['git', 'ls-remote', '--exit-code', 'origin', 'refs/heads/main'],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        if remote != revision + '\trefs/heads/main':
            raise ValueError('Source revision is no longer the current main commit')
    _docker(arguments, runner)
    for tag in tags:
        actual = _docker(['inspect', '--format', '{{.Manifest.Digest}}', tag], runner)
        if actual != digest:
            raise ValueError(f'Published tag has an unexpected digest: {tag}')
    return {**evidence, 'tags': tags}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('inspect', 'inspect-platform', 'assemble', 'promote'))
    parser.add_argument('--image', required=True)
    parser.add_argument('--digest')
    parser.add_argument('--platform', choices=sorted(PLATFORMS))
    parser.add_argument('--run-id')
    parser.add_argument('--run-attempt')
    parser.add_argument('--evidence', type=Path, nargs='+')
    parser.add_argument('--variant', choices=sorted(VARIANTS), default='release')
    parser.add_argument('--revision', required=True)
    parser.add_argument('--tags-file', type=Path)
    parser.add_argument('--require-current-main', action='store_true',
                        help='Reject promotion if origin/main advanced during testing')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.mode != 'assemble' and args.digest is None:
        parser.error('inspection and promotion require --digest')
    if args.mode == 'assemble':
        if not args.evidence:
            parser.error('assemble requires --evidence')
        candidates = [json.loads(path.read_text(encoding='utf-8')) for path in args.evidence]
        evidence = assemble(args.image, args.revision, candidates, args.run_id, args.run_attempt,
                            variant=args.variant)
    elif args.mode == 'inspect-platform':
        evidence = inspect_platform(args.image, args.digest, args.revision, args.platform,
                                    args.run_id, args.run_attempt)
    elif args.mode == 'promote':
        if args.tags_file is None:
            parser.error('promote requires --tags-file')
        tags = args.tags_file.read_text(encoding='utf-8').splitlines()
        evidence = promote(args.image, args.digest, args.revision, tags,
                           require_current_main=args.require_current_main)
    else:
        evidence = inspect_candidate(args.image, args.digest, args.revision)
    args.output.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
