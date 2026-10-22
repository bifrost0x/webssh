"""Validate complete CI results against an explicitly classified change scope."""

import json
import os


REQUIRED = frozenset({
    'dispatch-integrity', 'dependency-locks', 'pytest-shards', 'pytest', 'redis-rate-limiter',
    'ssh-integration', 'smb-integration', 'browser-e2e-shards', 'browser-fonts', 'browser-e2e',
    'container-threading-smoke', 'release-contract',
})


IMAGE_REQUIRED = frozenset({'change-scope', 'image-security-amd64', 'image-security-arm64'})


def validate_gates(results, *, kind='tests'):
    if kind not in {'tests', 'images'}:
        raise ValueError('Unknown gate kind')
    required = REQUIRED if kind == 'tests' else IMAGE_REQUIRED
    scope_name = 'dispatch-integrity' if kind == 'tests' else 'change-scope'
    if set(results) != required:
        raise ValueError('CI validation must include every required gate')
    scope = results[scope_name]
    if scope.get('result') != 'success':
        raise ValueError('Required gates did not succeed: ' + scope_name)
    mode = scope.get('outputs', {}).get('mode')
    if mode not in {'full', 'docs'}:
        raise ValueError('Missing or invalid change scope')
    expected = 'success' if mode == 'full' else 'skipped'
    unexpected = sorted(name for name, value in results.items()
                        if name != scope_name and value.get('result') != expected)
    if unexpected:
        raise ValueError('Required gates did not succeed as planned: ' + ', '.join(unexpected))
    return mode


if __name__ == '__main__':
    mode = validate_gates(json.loads(os.environ['GATE_RESULTS']),
                          kind=os.environ.get('GATE_KIND', 'tests'))
    print(f'All gates match the verified {mode} change scope')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as stream:
            stream.write(f'Gate passed: **{mode}** scope; every job has its expected result.\n')
