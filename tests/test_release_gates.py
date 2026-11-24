"""A release cannot proceed when a required CI job is absent or not successful."""

import pytest
from scripts.check_release_gates import ALWAYS_RUN, REQUIRED, validate_gates


def successful():
    results = {name: {'result': 'success'} for name in REQUIRED}
    results['dispatch-integrity']['outputs'] = {'mode': 'full'}
    return results


def test_all_successful_gates_are_accepted():
    validate_gates(successful())


@pytest.mark.parametrize('result', ['failure', 'cancelled', 'skipped', '', None])
@pytest.mark.parametrize('gate', sorted(REQUIRED))
def test_every_unsuccessful_gate_blocks_release(gate, result):
    results = successful()
    results[gate]['result'] = result
    with pytest.raises(ValueError, match='did not succeed'):
        validate_gates(results)


def test_omitted_gate_is_not_treated_as_success():
    results = successful()
    results.pop('browser-e2e')
    with pytest.raises(ValueError, match='every required gate'):
        validate_gates(results)


def documentation_results():
    results = {name: {'result': 'skipped'} for name in REQUIRED}
    results['dispatch-integrity'] = {'result': 'success', 'outputs': {'mode': 'docs'}}
    for name in ALWAYS_RUN:
        results[name] = {'result': 'success'}
    return results


def test_documentation_only_permits_deliberate_skips():
    validate_gates(documentation_results())


@pytest.mark.parametrize('result', ['failure', 'cancelled', 'success', '', None])
@pytest.mark.parametrize('gate', sorted(REQUIRED - {'dispatch-integrity'} - ALWAYS_RUN))
def test_documentation_cannot_hide_unexpected_job_results(gate, result):
    results = documentation_results()
    results[gate]['result'] = result
    with pytest.raises(ValueError):
        validate_gates(results)


def test_lint_is_required_for_every_change_scope():
    assert ALWAYS_RUN == {'lint'}
    assert ALWAYS_RUN <= REQUIRED


@pytest.mark.parametrize('result', ['skipped', 'failure', 'cancelled', '', None])
@pytest.mark.parametrize('gate', sorted(ALWAYS_RUN))
def test_documentation_still_requires_always_run_gates(gate, result):
    results = documentation_results()
    results[gate]['result'] = result
    with pytest.raises(ValueError, match='did not succeed'):
        validate_gates(results)


@pytest.mark.parametrize('mode', ['', 'unknown', None])
def test_unknown_scope_cannot_pass(mode):
    results = successful()
    results['dispatch-integrity']['outputs']['mode'] = mode
    with pytest.raises(ValueError):
        validate_gates(results)


@pytest.mark.parametrize('result', ['skipped', 'failure', 'cancelled'])
def test_documentation_requires_successful_classification(result):
    results = documentation_results()
    results['dispatch-integrity']['result'] = result
    with pytest.raises(ValueError):
        validate_gates(results)


def image_results(mode):
    result = 'skipped' if mode == 'docs' else 'success'
    return {
        'change-scope': {'result': 'success', 'outputs': {'mode': mode}},
        'image-security-amd64': {'result': result},
        'image-security-arm64': {'result': result},
    }


@pytest.mark.parametrize('mode', ['docs', 'full'])
def test_image_gate_uses_the_same_explicit_scope_contract(mode):
    validate_gates(image_results(mode), kind='images')


@pytest.mark.parametrize('mode', ['docs', 'full'])
@pytest.mark.parametrize('gate', ['change-scope', 'image-security-amd64', 'image-security-arm64'])
@pytest.mark.parametrize('result', ['failure', 'cancelled'])
def test_image_gate_rejects_every_failure(mode, gate, result):
    results = image_results(mode)
    results[gate]['result'] = result
    with pytest.raises(ValueError):
        validate_gates(results, kind='images')


def test_image_gate_rejects_unexpected_skips_and_omitted_scans():
    results = image_results('full')
    results['image-security-arm64']['result'] = 'skipped'
    with pytest.raises(ValueError):
        validate_gates(results, kind='images')
    del results['image-security-arm64']
    with pytest.raises(ValueError):
        validate_gates(results, kind='images')
