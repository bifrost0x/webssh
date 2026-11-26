"""The browser fixture seed stays a self-contained, language-neutral contract."""
import importlib.util
import json
from pathlib import Path

import pytest


E2E_DIR = Path(__file__).parent / 'e2e'
_spec = importlib.util.spec_from_file_location('e2e_run_app', E2E_DIR / 'run_app.py')
run_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_app)


@pytest.fixture
def seed():
    return run_app.load_seed(E2E_DIR / 'seed.json')


def _write(tmp_path, document):
    path = tmp_path / 'seed.json'
    path.write_text(json.dumps(document), encoding='utf-8')
    return path


def test_default_seed_references_resolve_within_the_seed(seed):
    accounts = {account['ref'] for account in seed['accounts']}
    refs = {
        'key': {entry['ref'] for entry in seed['ssh_keys']},
        'jump_host': {entry['ref'] for entry in seed['jump_hosts']},
        'socks_proxy': {entry['ref'] for entry in seed['socks_proxies']},
    }
    owned = [
        *seed['ssh_keys'], *seed['jump_hosts'], *seed['socks_proxies'],
        *seed['commands'], *seed['command_sets'], *seed['profiles'],
        *seed['external_identities'], *seed['mfa_placeholders'],
    ]
    for entry in owned:
        assert entry['account'] in accounts
        for field, known in refs.items():
            if field in entry:
                assert entry[field] in known
    for feature in seed['security_features']:
        assert feature['updated_by'] in accounts
    for hook in seed['test_hooks']:
        assert set(hook.get('accounts', [])) <= accounts


def test_default_seed_profile_ids_are_unique_and_derived_from_names(seed):
    per_account = {}
    for profile in seed['profiles']:
        ids = per_account.setdefault(profile['account'], set())
        assert profile['id'] not in ids
        ids.add(profile['id'])
        # run_app.py derives the same id; an explicit id keeps the seed self-contained.
        assert profile['id'] == profile['name'].lower().replace(' ', '-')


def test_default_seed_lists_every_supported_hook(seed):
    names = [hook['name'] for hook in seed['test_hooks']]
    assert sorted(names) == sorted(run_app.DATA_HOOKS + run_app.SOCKET_HOOKS)


def test_environment_placeholders_expand_per_run(seed, tmp_path):
    environment = run_app.seed_environment(seed, '4999', str(tmp_path))
    assert environment['PORT'] == '4999'
    assert environment['CORS_ORIGINS'] == 'http://127.0.0.1:4999'
    assert environment['WEBAUTHN_ORIGIN'] == 'http://localhost:4999'
    assert environment['OIDC_REDIRECT_URI'] == 'http://127.0.0.1:4999/oidc/callback'
    assert environment['OIDC_CLIENT_SECRET_FILE'] == str(tmp_path / 'oidc-client-secret')
    assert not any('{' in value for value in environment.values())


def test_seed_path_comes_from_environment(seed, tmp_path, monkeypatch):
    path = _write(tmp_path, {**seed, 'accounts': seed['accounts'][:1]})
    monkeypatch.setenv('WEBSSH_E2E_SEED', str(path))
    assert [account['ref'] for account in run_app.load_seed()['accounts']] == ['admin']


@pytest.mark.parametrize('change, message', [
    ({'version': 2}, 'Unsupported E2E seed version'),
    ({'test_hooks': [{'name': 'shell_exec'}]}, 'Unknown E2E test hook'),
    ({'data_files': {'../escape': 'x'}}, 'plain file name'),
    ({'data_files': {'nested/file': 'x'}}, 'plain file name'),
    ({'accounts': [{'ref': 'a'}, {'ref': 'a'}]}, 'refs must be unique'),
])
def test_invalid_seed_fails_closed(seed, tmp_path, change, message):
    with pytest.raises(RuntimeError, match=message):
        run_app.load_seed(_write(tmp_path, {**seed, **change}))


def test_unknown_reference_kind_is_rejected():
    with pytest.raises(RuntimeError, match='Unsupported generated E2E key type'):
        run_app._generated_private_key('dsa')
