import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest


SECURITY_ENV_NAMES = {
    'ALLOW_CORS_WILDCARD',
    'BLOCK_INTERNAL_SSH',
    'BOOTSTRAP_REGISTRATION_ENABLED',
    'CORS_ORIGINS',
    'DEBUG',
    'DEPLOYMENT_PROFILE',
    'LDAP_BASE_DN',
    'LDAP_AUTO_PROVISION',
    'LDAP_BIND_DN',
    'LDAP_BIND_PASSWORD_FILE',
    'LDAP_CA_FILE',
    'LDAP_CONNECT_TIMEOUT',
    'LDAP_ENABLED',
    'LDAP_OPERATION_TIMEOUT',
    'LDAP_PROVIDER_ID',
    'LDAP_SESSION_REVALIDATION_SECONDS',
    'LDAP_UNIQUE_ID_ATTRIBUTE',
    'LDAP_URL',
    'LDAP_USER_FILTER',
    'OIDC_MFA_ACR_VALUES',
    'OIDC_MFA_AMR_VALUES',
    'OIDC_PHISHING_RESISTANT_ACR_VALUES',
    'OIDC_PHISHING_RESISTANT_AMR_VALUES',
    'OIDC_STEP_UP_ACR_VALUES',
    'REGISTRATION_ENABLED',
    'SESSION_COOKIE_SECURE',
    'SMB_ALLOWED_TARGETS',
    'SMB_ENABLED',
    'STEP_UP_MAX_AGE_SECONDS',
    'TOTP_ENABLED',
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
        'BOOTSTRAP_REGISTRATION_ENABLED': 'false',
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


def test_smb_is_disabled_by_default():
    result = _load_config(
        _production_env(),
        'import config; print(config.SMB_ENABLED, config.SMB_ALLOWED_TARGETS)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == 'False ()'


def test_enabled_smb_requires_nonempty_exact_allowlist():
    result = _load_config(
        _production_env(SMB_ENABLED='true', SMB_ALLOWED_TARGETS=''),
    )

    assert result.returncode != 0
    assert 'SMB_ALLOWED_TARGETS' in result.stderr


@pytest.mark.parametrize(
    'entry',
    ['*', 'smb://nas/share', 'nas:1445', 'user@nas', 'nas/share'],
)
def test_config_rejects_invalid_smb_allowlist_entries(entry):
    result = _load_config(
        _production_env(SMB_ENABLED='true', SMB_ALLOWED_TARGETS=entry),
    )

    assert result.returncode != 0
    assert 'SMB_ALLOWED_TARGETS' in result.stderr


def test_totp_is_disabled_by_default():
    result = _load_config(
        _production_env(),
        'import config; print(config.TOTP_ENABLED)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == 'False'


def test_oidc_assurance_values_default_to_empty_explicit_sets():
    result = _load_config(
        _production_env(),
        'import config; print('
        'config.OIDC_MFA_AMR_VALUES, '
        'config.OIDC_MFA_ACR_VALUES, '
        'config.OIDC_PHISHING_RESISTANT_AMR_VALUES, '
        'config.OIDC_PHISHING_RESISTANT_ACR_VALUES, '
        'config.OIDC_STEP_UP_ACR_VALUES)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == (
        'frozenset() frozenset() frozenset() frozenset() frozenset()'
    )


def test_oidc_assurance_values_are_trimmed_explicit_sets():
    result = _load_config(
        _production_env(
            OIDC_MFA_AMR_VALUES='mfa, otp, mfa',
            OIDC_MFA_ACR_VALUES='urn:example:aal2',
            OIDC_PHISHING_RESISTANT_AMR_VALUES='webauthn, hwk',
            OIDC_PHISHING_RESISTANT_ACR_VALUES='urn:example:aal3',
            OIDC_STEP_UP_ACR_VALUES='urn:example:aal2, urn:example:aal3',
        ),
        'import config; print('
        'sorted(config.OIDC_MFA_AMR_VALUES), '
        'sorted(config.OIDC_MFA_ACR_VALUES), '
        'sorted(config.OIDC_PHISHING_RESISTANT_AMR_VALUES), '
        'sorted(config.OIDC_PHISHING_RESISTANT_ACR_VALUES), '
        'sorted(config.OIDC_STEP_UP_ACR_VALUES))',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == (
        "['mfa', 'otp'] ['urn:example:aal2'] ['hwk', 'webauthn'] "
        "['urn:example:aal3'] ['urn:example:aal2', 'urn:example:aal3']"
    )


@pytest.mark.parametrize('configured_value', ('59', '901', 'not-an-integer'))
def test_step_up_max_age_rejects_values_outside_security_bounds(
    configured_value,
):
    result = _load_config(
        _production_env(STEP_UP_MAX_AGE_SECONDS=configured_value),
        'import config',
    )

    assert result.returncode != 0
    assert 'STEP_UP_MAX_AGE_SECONDS' in result.stdout + result.stderr


def test_step_up_max_age_defaults_to_five_minutes():
    result = _load_config(
        _production_env(),
        'import config; print(config.STEP_UP_MAX_AGE_SECONDS)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '300'


def test_ldap_is_disabled_by_default_and_ignores_incomplete_settings():
    result = _load_config(
        _production_env(LDAP_URL='not-an-ldap-url'),
        'import config; print(config.LDAP_ENABLED)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == 'False'


@pytest.mark.parametrize(
    ('configured_value', 'expected'),
    ((None, 'False'), ('true', 'True')),
)
def test_ldap_auto_provisioning_requires_explicit_opt_in(
    configured_value,
    expected,
):
    result = _load_config(
        _production_env(LDAP_AUTO_PROVISION=configured_value),
        'import config; print(config.LDAP_AUTO_PROVISION)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == expected


@pytest.mark.parametrize(
    'missing_name',
    (
        'LDAP_URL',
        'LDAP_BASE_DN',
        'LDAP_BIND_DN',
        'LDAP_USER_FILTER',
        'LDAP_UNIQUE_ID_ATTRIBUTE',
    ),
)
def test_enabled_ldap_requires_complete_configuration(missing_name):
    settings = {
        'LDAP_ENABLED': 'true',
        'LDAP_URL': 'ldaps://directory.example.com:636',
        'LDAP_BASE_DN': 'ou=people,dc=example,dc=com',
        'LDAP_BIND_DN': 'cn=webssh,ou=services,dc=example,dc=com',
        'LDAP_BIND_PASSWORD_FILE': '/run/webssh-auth/ldap_bind_password',
        'LDAP_CA_FILE': '/run/webssh-auth/ldap_ca.pem',
        'LDAP_USER_FILTER': '(&(objectClass=person)(uid={username}))',
        'LDAP_UNIQUE_ID_ATTRIBUTE': 'entryUUID',
    }
    settings[missing_name] = None

    result = _load_config(_production_env(**settings))

    assert result.returncode != 0
    assert missing_name in result.stdout + result.stderr


@pytest.mark.parametrize(
    'ldap_url',
    (
        'http://directory.example.com',
        'ldap://user:secret@directory.example.com',
        'ldaps://directory.example.com/dc=example,dc=com',
        'ldaps://directory.example.com?base',
        'ldap://directory.example.com:bad',
        'ldap://directory.example.com:99999',
        'ldap://directory.example.com:0',
    ),
)
def test_enabled_ldap_rejects_unsafe_or_ambiguous_url(ldap_url):
    result = _load_config(_production_env(
        LDAP_ENABLED='true',
        LDAP_URL=ldap_url,
        LDAP_BASE_DN='ou=people,dc=example,dc=com',
        LDAP_BIND_DN='cn=webssh,ou=services,dc=example,dc=com',
        LDAP_BIND_PASSWORD_FILE='/run/webssh-auth/ldap_bind_password',
        LDAP_CA_FILE='/run/webssh-auth/ldap_ca.pem',
        LDAP_USER_FILTER='(&(objectClass=person)(uid={username}))',
        LDAP_UNIQUE_ID_ATTRIBUTE='entryUUID',
    ))

    assert result.returncode != 0
    assert 'LDAP_URL' in result.stdout + result.stderr


def test_enabled_ldap_accepts_starttls_with_bounded_timeouts():
    result = _load_config(
        _production_env(
            LDAP_ENABLED='true',
            LDAP_URL='ldap://directory.example.com:389',
            LDAP_BASE_DN='ou=people,dc=example,dc=com',
            LDAP_BIND_DN='cn=webssh,ou=services,dc=example,dc=com',
            LDAP_BIND_PASSWORD_FILE='/run/webssh-auth/ldap_bind_password',
            LDAP_CA_FILE='/run/webssh-auth/ldap_ca.pem',
            LDAP_USER_FILTER='(&(objectClass=person)(uid={username}))',
            LDAP_UNIQUE_ID_ATTRIBUTE='entryUUID',
            LDAP_CONNECT_TIMEOUT='4',
            LDAP_OPERATION_TIMEOUT='6',
        ),
        (
            'import config; '
            'print(config.LDAP_CONNECT_TIMEOUT, config.LDAP_OPERATION_TIMEOUT)'
        ),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '4 6'


@pytest.mark.parametrize(
    ('setting_name', 'setting_value'),
    (
        ('LDAP_PROVIDER_ID', '../other-directory'),
        ('LDAP_USER_FILTER', '(uid={username})(mail={mail})'),
        ('LDAP_UNIQUE_ID_ATTRIBUTE', 'objectGUID)(uid=*'),
    ),
)
def test_enabled_ldap_rejects_injectable_identifiers_and_templates(
    setting_name,
    setting_value,
):
    settings = {
        'LDAP_ENABLED': 'true',
        'LDAP_PROVIDER_ID': 'primary',
        'LDAP_URL': 'ldaps://directory.example.com:636',
        'LDAP_BASE_DN': 'ou=people,dc=example,dc=com',
        'LDAP_BIND_DN': 'cn=webssh,ou=services,dc=example,dc=com',
        'LDAP_BIND_PASSWORD_FILE': '/run/webssh-auth/ldap_bind_password',
        'LDAP_CA_FILE': '/run/webssh-auth/ldap_ca.pem',
        'LDAP_USER_FILTER': '(&(objectClass=person)(uid={username}))',
        'LDAP_UNIQUE_ID_ATTRIBUTE': 'entryUUID',
    }
    settings[setting_name] = setting_value

    result = _load_config(_production_env(**settings))

    assert result.returncode != 0
    assert setting_name in result.stdout + result.stderr


def test_recovery_json_limit_cannot_exceed_hard_security_ceiling():
    result = _load_config(
        _production_env(MAX_RECOVERY_JSON_SIZE='1048576'),
        'import config; print(config.MAX_RECOVERY_JSON_SIZE)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '4096'


def test_webauthn_json_limit_cannot_exceed_hard_security_ceiling():
    result = _load_config(
        _production_env(MAX_WEBAUTHN_JSON_SIZE='1048576'),
        'import config; print(config.MAX_WEBAUTHN_JSON_SIZE)',
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == '65536'


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
            {'BOOTSTRAP_REGISTRATION_ENABLED': 'true'},
            'BOOTSTRAP_REGISTRATION_ENABLED',
            id='browser-bootstrap',
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


def test_env_example_documents_every_runtime_environment_variable():
    config_source = Path('config.py').read_text(encoding='utf-8')
    start_source = Path('start.py').read_text(encoding='utf-8')
    runtime_names = set(re.findall(
        r"(?:os\.environ\.get|os\.getenv|_positive_int_env|"
        r"_bounded_int_env|_non_negative_int_env|_csv_env)"
        r"\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]",
        config_source + '\n' + start_source,
    ))
    runtime_names.add('SECRET_KEY')

    example_source = Path('.env.example').read_text(encoding='utf-8')
    documented_names = set(re.findall(
        r'^#?\s*([A-Z][A-Z0-9_]*)=',
        example_source,
        re.MULTILINE,
    ))

    assert runtime_names - documented_names == set()


def test_homelab_compose_exposes_major_operator_choices():
    compose = Path('docker-compose.yml').read_text(encoding='utf-8')
    expected_names = {
        'APPLICATION_ROOT',
        'AUDIT_EXPORT_ENABLED',
        'BLOCK_INTERNAL_SSH',
        'BOOTSTRAP_REGISTRATION_ENABLED',
        'HOST_KEY_MANAGEMENT_ENABLED',
        'OIDC_ENABLED',
        'OIDC_MFA_ACR_VALUES',
        'OIDC_MFA_AMR_VALUES',
        'OIDC_PHISHING_RESISTANT_ACR_VALUES',
        'OIDC_PHISHING_RESISTANT_AMR_VALUES',
        'OIDC_STEP_UP_ACR_VALUES',
        'RECOVERY_CODES_ENABLED',
        'REGISTRATION_ENABLED',
        'STEP_UP_MAX_AGE_SECONDS',
        'TAILSCALE_SSH_ENABLED',
        'TOTP_ENABLED',
        'TMUX_DEFAULT',
        'TMUX_ENABLED',
        'WEBAUTHN_ENABLED',
    }

    assert {
        name for name in expected_names if name not in compose
    } == set()


def test_compose_exposes_totp_capability_without_bypassing_admin_gate():
    compose = Path('docker-compose.yml').read_text(encoding='utf-8')
    production = Path('docker-compose.production.yml').read_text(
        encoding='utf-8'
    )

    assert 'TOTP_ENABLED=${TOTP_ENABLED:-true}' in compose
    assert 'TOTP_ENABLED: "${TOTP_ENABLED:-true}"' in production


def test_default_compose_has_no_ldap_secret_infrastructure():
    compose = Path('docker-compose.yml').read_text(encoding='utf-8')
    dockerfile = Path('Dockerfile').read_text(encoding='utf-8')

    assert 'LDAP_ENABLED' not in compose
    assert 'webssh_auth_secrets' not in compose
    assert 'ldap-tools:' not in compose
    assert 'VOLUME /run/webssh-auth' not in dockerfile


def test_ldap_compose_overlay_supplies_complete_secret_infrastructure():
    overlay = Path('docker-compose.ldap.yml').read_text(encoding='utf-8')

    for name in (
        'LDAP_ENABLED',
        'LDAP_AUTO_PROVISION',
        'LDAP_PROVIDER_ID',
        'LDAP_URL',
        'LDAP_BASE_DN',
        'LDAP_BIND_DN',
        'LDAP_USER_FILTER',
        'LDAP_UNIQUE_ID_ATTRIBUTE',
    ):
        assert name in overlay
    assert 'LDAP_ENABLED: "true"' in overlay
    assert 'LDAP_AUTO_PROVISION: "false"' in overlay
    assert 'webssh_auth_secrets:/run/webssh-auth:ro' in overlay
    assert 'ldap-tools:' in overlay
    assert 'profiles: ["ldap-tools"]' in overlay
    assert 'python", "/app/deployment/ldap_secret_cli.py"' in overlay


def test_ldap_documentation_selects_overlay_for_every_helper_command():
    documentation = Path('docs/ldap-authentication.md').read_text(
        encoding='utf-8',
    )
    helper_commands = [
        line
        for line in documentation.splitlines()
        if 'ldap-tools run' in line
    ]

    assert helper_commands
    assert all(
        '-f docker-compose.yml -f docker-compose.ldap.yml' in command
        for command in helper_commands
    )
    assert (
        '-f docker-compose.yml -f docker-compose.ldap.yml '
        '-f docker-compose.production.yml up -d'
    ) in documentation


def test_wiki_documents_complete_ldap_compose_quickstart():
    documentation = Path(
        'docs/wiki/LDAP-and-Active-Directory.md'
    ).read_text(encoding='utf-8')
    normalized = ' '.join(documentation.replace('\\\n', '').split())
    documented_urls = {
        (parsed.scheme, parsed.hostname, parsed.port)
        for value in re.findall(
            r'`(ldaps?://[^`:/\s]+:\d+)`', documentation
        )
        if (parsed := urlsplit(value)).hostname
    }

    assert '# LDAP and Active Directory' in documentation
    assert ('ldap', 'ldap.example.com', 389) in documented_urls
    assert 'mandatory StartTLS' in documentation
    assert ('ldaps', 'ldap.example.com', 636) in documented_urls
    assert (
        '-f docker-compose.yml -f docker-compose.ldap.yml '
        '--profile ldap-tools run --rm ldap-tools set-password'
    ) in normalized
    assert (
        '-f docker-compose.yml -f docker-compose.ldap.yml up -d'
    ) in normalized
    assert (
        '-f docker-compose.yml -f docker-compose.ldap.yml '
        '-f docker-compose.production.yml up -d'
    ) in normalized
    assert (
        'docker compose -f docker-compose.yml '
        'up -d --force-recreate'
    ) in normalized
    assert (
        'docker compose -f docker-compose.yml '
        '-f docker-compose.production.yml '
        'up -d --force-recreate'
    ) in normalized


def test_disposable_ldap_lab_binds_published_test_service_to_loopback():
    compose = Path('tests/integration/ldap/docker-compose.yml').read_text(
        encoding='utf-8',
    )

    assert '127.0.0.1:5050:5000' in compose
    assert '- "5050:5000"' not in compose


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
        OIDC_REDIRECT_URI='https://ssh.example.com/oidc/callback',
    ))

    assert result.returncode != 0
    assert 'OIDC_ISSUER' in result.stdout + result.stderr


@pytest.mark.parametrize(
    'redirect_uri',
    (
        '',
        'http://ssh.example.com/oidc/callback',
        'https://user@ssh.example.com/oidc/callback',
        'https://ssh.example.com/oidc/callback?next=/admin',
        'https://ssh.example.com/not-the-callback',
    ),
)
def test_oidc_rejects_unsafe_or_mismatched_redirect_uri(redirect_uri):
    result = _load_config(_production_env(
        OIDC_ENABLED='true',
        OIDC_ISSUER='https://issuer.example',
        OIDC_REDIRECT_URI=redirect_uri,
    ))

    assert result.returncode != 0
    assert 'OIDC_REDIRECT_URI' in result.stdout + result.stderr


def test_oidc_accepts_explicit_production_callback():
    result = _load_config(_production_env(
        OIDC_ENABLED='true',
        OIDC_ISSUER='https://issuer.example',
        OIDC_REDIRECT_URI='https://ssh.example.com/oidc/callback',
    ))

    assert result.returncode == 0, result.stdout + result.stderr


def test_oidc_callback_must_include_application_root():
    result = _load_config(_production_env(
        APPLICATION_ROOT='/webssh',
        OIDC_ENABLED='true',
        OIDC_ISSUER='https://issuer.example',
        OIDC_REDIRECT_URI='https://ssh.example.com/oidc/callback',
    ))

    assert result.returncode != 0
    assert 'OIDC_REDIRECT_URI' in result.stdout + result.stderr


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
