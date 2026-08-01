import json
import os
import subprocess
import sys

import pytest


SECURITY_ENV_NAMES = {
    'ALLOW_CORS_WILDCARD',
    'BLOCK_INTERNAL_SSH',
    'CORS_ORIGINS',
    'DEBUG',
    'DEPLOYMENT_PROFILE',
    'REGISTRATION_ENABLED',
    'SESSION_COOKIE_SECURE',
    'TRUSTED_PROXIES',
    'WEBAUTHN_ENABLED',
    'WEBAUTHN_ORIGIN',
    'WEBAUTHN_RP_ID',
    'WEBAUTHN_RP_NAME',
}


def _production_env(**overrides):
    env = os.environ.copy()
    for name in SECURITY_ENV_NAMES:
        env.pop(name, None)
    env.update({
        'SECRET_KEY': 'production-profile-test-secret',
        'DEBUG': 'False',
        'DEPLOYMENT_PROFILE': 'production',
        'CORS_ORIGINS': 'https://ssh.example.com',
        'ALLOW_CORS_WILDCARD': 'false',
        'SESSION_COOKIE_SECURE': 'true',
        'REGISTRATION_ENABLED': 'False',
        'BLOCK_INTERNAL_SSH': 'true',
        'TRUSTED_PROXIES': '1',
        'PYTHONIOENCODING': 'utf-8',
    })
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _load_config(env, code='import config'):
    return subprocess.run(
        [sys.executable, '-c', code],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        encoding='utf-8',
        errors='replace',
        check=False,
    )


def test_safe_production_profile_loads():
    result = _load_config(_production_env())

    assert result.returncode == 0, result.stdout + result.stderr


def test_recovery_json_limit_cannot_exceed_hard_security_ceiling():
    result = _load_config(
        _production_env(MAX_RECOVERY_JSON_SIZE='1048576'),
        'import config; print(config.MAX_RECOVERY_JSON_SIZE)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '4096'


@pytest.mark.parametrize(
    ('overrides', 'expected_setting'),
    (
        pytest.param(
            {
                'CORS_ORIGINS': '*',
                'ALLOW_CORS_WILDCARD': 'true',
            },
            'CORS_ORIGINS',
            id='wildcard-cors',
        ),
        pytest.param(
            {'ALLOW_CORS_WILDCARD': 'true'},
            'ALLOW_CORS_WILDCARD',
            id='latent-wildcard-opt-in',
        ),
        pytest.param(
            {'CORS_ORIGINS': 'http://ssh.example.com'},
            'CORS_ORIGINS',
            id='non-https-origin',
        ),
        pytest.param(
            {'SESSION_COOKIE_SECURE': 'false'},
            'SESSION_COOKIE_SECURE',
            id='insecure-cookie',
        ),
        pytest.param(
            {'REGISTRATION_ENABLED': 'true'},
            'REGISTRATION_ENABLED',
            id='open-registration',
        ),
        pytest.param(
            {'BLOCK_INTERNAL_SSH': 'false'},
            'BLOCK_INTERNAL_SSH',
            id='internal-ssh',
        ),
        pytest.param(
            {'DEBUG': 'true'},
            'DEBUG',
            id='debug',
        ),
    ),
)
def test_production_profile_rejects_unsafe_combinations(
    overrides,
    expected_setting,
):
    result = _load_config(_production_env(**overrides))

    assert result.returncode != 0
    assert expected_setting in result.stdout + result.stderr


@pytest.mark.parametrize(
    'missing_name',
    ('CORS_ORIGINS', 'TRUSTED_PROXIES'),
)
def test_production_profile_requires_explicit_network_boundaries(missing_name):
    result = _load_config(_production_env(**{missing_name: None}))

    assert result.returncode != 0
    assert missing_name in result.stdout + result.stderr


@pytest.mark.parametrize('value', ('invalid', '-1'))
def test_trusted_proxy_count_must_be_a_non_negative_integer(value):
    result = _load_config(_production_env(TRUSTED_PROXIES=value))

    assert result.returncode != 0
    assert 'TRUSTED_PROXIES' in result.stdout + result.stderr


def test_unknown_deployment_profile_is_rejected():
    result = _load_config(_production_env(DEPLOYMENT_PROFILE='internet'))

    assert result.returncode != 0
    assert 'DEPLOYMENT_PROFILE' in result.stdout + result.stderr


@pytest.mark.parametrize(
    ('overrides', 'expected_setting'),
    (
        pytest.param(
            {
                'WEBAUTHN_ENABLED': 'true',
                'WEBAUTHN_RP_ID': 'ssh.example.com',
                'WEBAUTHN_ORIGIN': 'http://ssh.example.com',
            },
            'WEBAUTHN_ORIGIN',
            id='production-http-origin',
        ),
        pytest.param(
            {
                'WEBAUTHN_ENABLED': 'true',
                'WEBAUTHN_RP_ID': 'other.example.com',
                'WEBAUTHN_ORIGIN': 'https://ssh.example.com',
            },
            'WEBAUTHN_RP_ID',
            id='rp-id-origin-mismatch',
        ),
    ),
)
def test_webauthn_configuration_fails_closed(overrides, expected_setting):
    result = _load_config(_production_env(**overrides))

    assert result.returncode != 0
    assert expected_setting in result.stdout + result.stderr


def test_webauthn_accepts_exact_production_origin():
    result = _load_config(_production_env(
        WEBAUTHN_ENABLED='true',
        WEBAUTHN_RP_ID='ssh.example.com',
        WEBAUTHN_ORIGIN='https://ssh.example.com',
    ))

    assert result.returncode == 0, result.stdout + result.stderr


def test_oidc_rejects_cleartext_issuer():
    result = _load_config(_production_env(
        OIDC_ENABLED='true',
        OIDC_ISSUER='http://issuer.example',
    ))

    assert result.returncode != 0
    assert 'OIDC_ISSUER' in result.stdout + result.stderr


def test_homelab_profile_reports_unsafe_compatibility_warnings():
    env = _production_env(
        DEPLOYMENT_PROFILE='homelab',
        CORS_ORIGINS='*',
        ALLOW_CORS_WILDCARD='true',
        SESSION_COOKIE_SECURE='false',
        REGISTRATION_ENABLED='True',
        BLOCK_INTERNAL_SSH='false',
        TRUSTED_PROXIES='0',
    )
    result = _load_config(
        env,
        (
            'import json, config; '
            'print(json.dumps(config.SECURITY_CONFIG_WARNINGS))'
        ),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    warnings = json.loads(result.stdout.splitlines()[-1])
    assert any('CORS_ORIGINS' in warning for warning in warnings)
    assert any('SESSION_COOKIE_SECURE' in warning for warning in warnings)
    assert any('REGISTRATION_ENABLED' in warning for warning in warnings)
    assert any('BLOCK_INTERNAL_SSH' in warning for warning in warnings)


def test_runtime_shutdown_grace_uses_container_stop_reserve_default():
    result = _load_config(
        _production_env(),
        'import config; print(config.RUNTIME_SHUTDOWN_GRACE_SECONDS)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '5'


def test_runtime_shutdown_grace_rejects_values_beyond_container_budget():
    result = _load_config(
        _production_env(RUNTIME_SHUTDOWN_GRACE_SECONDS='31')
    )

    assert result.returncode != 0
    assert 'RUNTIME_SHUTDOWN_GRACE_SECONDS' in result.stdout + result.stderr


def test_saved_registration_override_cannot_open_production(
    app,
    tmp_path,
    monkeypatch,
):
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    stored = {
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'],
        'registration_enabled': True,
    }
    path.write_text(json.dumps(stored), encoding='utf-8')
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    monkeypatch.setattr(
        app_settings.config,
        'DEPLOYMENT_PROFILE',
        'production',
        raising=False,
    )

    assert app_settings.is_registration_enabled() is False
    assert app_settings.set_registration_enabled(True) is False
    assert json.loads(path.read_text(encoding='utf-8')) == stored
