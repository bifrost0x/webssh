"""Admin-managed GitHub configuration and provider boundary tests."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest


def _admin(app):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user('github_config_admin', 'password123')
        assert error is None
        user.is_admin = True
        db.session.commit()
        return user.id


def _payload(**overrides):
    data = {
        'enabled': True,
        'client_id': 'Iv1234567890abcdef',
        'client_secret': 'a' * 40,
        'redirect_uri': 'https://ssh.example.com/auth/github/callback',
        'auto_provision': False,
        'allowed_orgs': [],
    }
    data.update(overrides)
    return data


def test_runtime_configuration_encrypts_and_never_exposes_secret(app):
    from app.github_auth_service import get_settings, update_settings
    from app.models import GitHubAuthConfiguration, db

    admin_id = _admin(app)
    with app.app_context():
        public = update_settings(_payload(), admin_id)
        row = db.session.get(GitHubAuthConfiguration, 1)
        assert row.encrypted_client_secret != b'a' * 40
        assert public.active is True
        assert public.client_secret is None
        assert public.public_dict()['client_secret_configured'] is True
        assert 'client_secret' not in public.public_dict()
        assert get_settings(include_secret=True).client_secret == 'a' * 40


def test_configuration_update_preserves_secret_when_field_is_omitted(app):
    from app.github_auth_service import get_settings, update_settings

    admin_id = _admin(app)
    with app.app_context():
        update_settings(_payload(), admin_id)
        update_settings({
            'enabled': True,
            'client_id': 'Iv1234567890abcdef',
            'redirect_uri': 'https://ssh.example.com/auth/github/callback',
            'auto_provision': True,
            'allowed_orgs': ['Example-Org', 'example-org'],
        }, admin_id)
        settings = get_settings(include_secret=True)
        assert settings.client_secret == 'a' * 40
        assert settings.allowed_orgs == ('example-org',)
        assert settings.auto_provision is True


@pytest.mark.parametrize(('field', 'value'), (
    ('client_id', 123),
    ('client_secret', ['not', 'a', 'secret']),
    ('redirect_uri', {'url': 'https://ssh.example.com/auth/github/callback'}),
    ('allowed_orgs', ['valid-org', 123]),
    ('clear_client_secret', 'true'),
))
def test_configuration_rejects_noncanonical_field_types(app, field, value):
    from app.github_auth_service import GitHubConfigurationError, update_settings

    admin_id = _admin(app)
    with app.app_context(), pytest.raises(GitHubConfigurationError):
        update_settings(_payload(**{field: value}), admin_id)


@pytest.mark.parametrize('redirect_uri', (
    'http://ssh.example.com/auth/github/callback',
    'https://ssh.example.com/other',
    'https://user@ssh.example.com/auth/github/callback',
    'https://ssh.example.com/auth/github/callback?next=bad',
))
def test_configuration_rejects_unsafe_callback_urls(app, redirect_uri):
    from app.github_auth_service import GitHubConfigurationError, update_settings

    admin_id = _admin(app)
    with app.app_context(), pytest.raises(GitHubConfigurationError):
        update_settings(_payload(redirect_uri=redirect_uri), admin_id)


def test_oauth_state_is_bound_expiring_single_use_and_generation_scoped(app):
    from app.github_auth_service import (
        GitHubStateError, consume_oauth_state, create_oauth_state,
    )

    now = datetime.now(timezone.utc)
    with app.app_context():
        create_oauth_state(
            state='state-token', session_binding='browser-binding',
            code_verifier='verifier-token', purpose='login', generation=3,
            now=now,
        )
        with pytest.raises(GitHubStateError):
            consume_oauth_state(
                state='state-token', session_binding='other-binding',
                generation=3, now=now,
            )
        intent = consume_oauth_state(
            state='state-token', session_binding='browser-binding',
            generation=3, now=now,
        )
        assert intent.purpose == 'login'
        with pytest.raises(GitHubStateError):
            consume_oauth_state(
                state='state-token', session_binding='browser-binding',
                generation=3, now=now,
            )

        create_oauth_state(
            state='generation-state', session_binding='browser-binding',
            code_verifier='verifier-token', purpose='login', generation=3,
            now=now,
        )
        with pytest.raises(GitHubStateError):
            consume_oauth_state(
                state='generation-state', session_binding='browser-binding',
                generation=4, now=now,
            )


def test_oauth_state_rejects_external_continuations(app):
    from app.github_auth_service import consume_oauth_state, create_oauth_state

    with app.app_context():
        create_oauth_state(
            state='external-state', session_binding='browser-binding',
            code_verifier='verifier-token', purpose='login', generation=1,
            continuation='//attacker.example/path',
        )
        intent = consume_oauth_state(
            state='external-state', session_binding='browser-binding',
            generation=1,
        )
        assert intent.continuation == '/'


def test_organization_policy_accepts_active_membership_and_fails_closed():
    from app.github_auth_service import (
        GitHubOrganizationRejected, GitHubProviderError,
        enforce_organization_policy,
    )

    settings = SimpleNamespace(allowed_orgs=('allowed-org',))

    class ActiveHttp:
        @staticmethod
        def get(*_args, **_kwargs):
            return SimpleNamespace(status_code=200, json=lambda: {'state': 'active'})

    class MissingHttp:
        @staticmethod
        def get(*_args, **_kwargs):
            return SimpleNamespace(status_code=404, json=lambda: {})

    class FailedHttp:
        @staticmethod
        def get(*_args, **_kwargs):
            raise TimeoutError

    enforce_organization_policy('token', settings, http=ActiveHttp)
    with pytest.raises(GitHubOrganizationRejected):
        enforce_organization_policy('token', settings, http=MissingHttp)
    with pytest.raises(GitHubProviderError):
        enforce_organization_policy('token', settings, http=FailedHttp)
