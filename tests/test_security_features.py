"""Fail-closed deployment and administrator gates for auth features."""

from pathlib import Path
import time

import pytest


def _set_readiness(app, name, ready, reason=None):
    app.extensions.setdefault('security_feature_readiness', {})[name] = (
        ready,
        reason,
    )


@pytest.mark.parametrize(
    ('deployment', 'ready', 'admin_enabled', 'effective'),
    (
        (False, False, False, False),
        (False, True, True, False),
        (True, False, True, False),
        (True, True, False, False),
        (True, True, True, True),
    ),
)
def test_effective_feature_requires_all_three_gates(
    app,
    monkeypatch,
    deployment,
    ready,
    admin_enabled,
    effective,
):
    import config
    from app.models import SecurityFeatureState, db
    from app.security_features import feature_status

    monkeypatch.setattr(config, 'OIDC_ENABLED', deployment)
    _set_readiness(app, 'oidc', ready)
    with app.app_context():
        db.session.add(SecurityFeatureState(
            feature='oidc',
            enabled=admin_enabled,
        ))
        db.session.commit()

        status = feature_status('oidc')

    assert status.deployment_allowed is deployment
    assert status.ready is ready
    assert status.admin_enabled is admin_enabled
    assert status.active is effective


def test_existing_feature_without_state_preserves_deployment_behavior(
    app,
    monkeypatch,
):
    import config
    from app.security_features import feature_status

    monkeypatch.setattr(config, 'WEBAUTHN_ENABLED', True)
    _set_readiness(app, 'passkey', True)

    with app.app_context():
        status = feature_status('passkey')

    assert status.admin_enabled is True
    assert status.active is True
    assert status.reason is None


def test_new_totp_feature_requires_explicit_admin_activation(app, monkeypatch):
    import config
    from app.security_features import feature_status

    monkeypatch.setattr(config, 'TOTP_ENABLED', True)
    _set_readiness(app, 'totp', True)

    with app.app_context():
        status = feature_status('totp')

    assert status.deployment_allowed is True
    assert status.ready is True
    assert status.admin_enabled is False
    assert status.active is False
    assert status.reason


def test_admin_activation_persists_the_actor_and_enables_ready_totp(
    app,
    monkeypatch,
):
    import config
    from app.auth import register_user
    from app.models import SecurityFeatureState, db
    from app.security_features import set_feature_active

    monkeypatch.setattr(config, 'TOTP_ENABLED', True)
    _set_readiness(app, 'totp', True)

    with app.app_context():
        admin, error = register_user('featureadmin', 'password123')
        assert error is None
        admin.is_admin = True
        db.session.commit()

        status = set_feature_active('totp', True, admin.id)
        stored = db.session.get(SecurityFeatureState, 'totp')

        assert status.active is True
        assert stored.enabled is True
        assert stored.updated_by == admin.id
        assert stored.updated_at is not None


def test_admin_cannot_enable_a_deployment_disabled_feature(app):
    from app.auth import register_user
    from app.models import SecurityFeatureState, db
    from app.security_features import FeatureUnavailable, set_feature_active

    with app.app_context():
        admin, error = register_user('featureadmin', 'password123')
        assert error is None
        db.session.commit()

        with pytest.raises(FeatureUnavailable) as exc_info:
            set_feature_active('oidc', True, admin.id)

        assert exc_info.value.status.deployment_allowed is False
        assert exc_info.value.status.active is False
        assert db.session.get(SecurityFeatureState, 'oidc') is None


def test_runtime_activation_does_not_read_provider_secret_files(
    app,
    monkeypatch,
):
    import config
    from app.auth import register_user
    from app.models import db
    from app.security_features import set_feature_active

    monkeypatch.setattr(config, 'OIDC_ENABLED', True)
    _set_readiness(app, 'oidc', True)

    def fail_secret_read(*_args, **_kwargs):
        raise AssertionError('runtime activation must not read secret files')

    monkeypatch.setattr(Path, 'read_text', fail_secret_read)

    with app.app_context():
        admin, error = register_user('featureadmin', 'password123')
        assert error is None
        db.session.commit()

        status = set_feature_active('oidc', True, admin.id)

    assert status.active is True


def test_admin_disabled_oidc_blocks_new_provider_login(app, client, monkeypatch):
    import config
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, 'OIDC_ENABLED', True)
    _set_readiness(app, 'oidc', True)
    with app.app_context():
        db.session.add(SecurityFeatureState(feature='oidc', enabled=False))
        db.session.commit()

    response = client.get('/oidc/login')

    assert response.status_code == 404


def test_admin_disabled_oidc_is_not_advertised_in_templates(
    app,
    client,
    monkeypatch,
):
    import config
    from app.auth import register_user
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, 'OIDC_ENABLED', True)
    _set_readiness(app, 'oidc', True)
    with app.app_context():
        admin, error = register_user('featureadmin', 'password123')
        assert error is None
        admin.is_admin = True
        db.session.add(SecurityFeatureState(feature='oidc', enabled=False))
        db.session.commit()

    response = client.post('/login', data={
        'username': 'featureadmin',
        'password': 'password123',
    })
    assert response.status_code == 302

    response = client.get('/admin')

    assert response.status_code == 200
    assert b'<meta name="oidc-enabled" content="false">' in response.data


def test_admin_disabling_ldap_does_not_terminate_an_existing_session(
    app,
    client,
    monkeypatch,
):
    import config
    from app.auth import register_user
    from app.models import LDAPIdentity, SecurityFeatureState, db

    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    _set_readiness(app, 'ldap', True)
    with app.app_context():
        user, error = register_user('linkedldapuser', 'password123')
        assert error is None
        user.is_admin = False
        db.session.add(LDAPIdentity(
            user_id=user.id,
            provider='default',
            subject='stable-directory-id',
            directory_username='linkedldapuser',
            distinguished_name='uid=linkedldapuser,dc=example,dc=com',
        ))
        db.session.add(SecurityFeatureState(feature='ldap', enabled=False))
        db.session.commit()
        login_identifier = user.get_id()

    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = login_identifier
        browser_session['_fresh'] = True
        browser_session['_ldap_verified_at'] = int(time.time())

    response = client.get('/')

    assert response.status_code == 200
    with client.session_transaction() as browser_session:
        assert browser_session['_user_id'] == login_identifier
