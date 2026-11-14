"""A disable approval describes and is bound to the current account inventory."""
from tests.test_account_sessions import _login, separate_browser_contexts


def _enable_passkeys(app, monkeypatch):
    import config
    monkeypatch.setattr(config, 'WEBAUTHN_ENABLED', True)
    app.extensions['security_feature_readiness']['passkey'] = (True, None)


def _grant(client, feature='passkey'):
    response = client.post('/api/step-up/password', json={
        'action': 'security_feature.update', 'target': feature, 'password': 'password123',
    })
    assert response.status_code == 200
    return {'X-WebSSH-Step-Up': response.json['grant']}


def test_preflight_counts_affected_admins_and_configured_remaining_paths(app, monkeypatch):
    from app.models import User, WebAuthnCredential, db
    admin = _login(app, create=True)
    _login(app, 'normal_account', create=True)
    _enable_passkeys(app, monkeypatch)
    with app.app_context():
        for user in User.query.all():
            db.session.add(WebAuthnCredential(user_id=user.id, credential_id=str(user.id).encode(), public_key=b'test'))
        db.session.commit()
    response = admin.get('/admin/api/security-features/passkey/impact')
    assert response.status_code == 200
    impact = response.json['impact']
    assert impact['affected_accounts'] == 2
    assert impact['affected_admins'] == 1
    assert impact['remaining_primary']['password'] == 2
    assert impact['remaining_primary'].get('passkey', 0) == 0
    assert impact['tested'] is False
    assert {row['username'] for row in impact['accounts']} == {'session_owner', 'normal_account'}
    assert next(row for row in impact['accounts'] if row['admin'])['remaining_primary'] == ['password']
    assert response.json['approval']
    assert response.headers['Cache-Control'] == 'no-store'


def test_disable_requires_preflight_and_rejects_changed_inventory(app, monkeypatch):
    from app.models import User, db
    admin = _login(app, create=True)
    _login(app, 'changed_account', create=True)
    _enable_passkeys(app, monkeypatch)
    body = {'enabled': False, 'confirm_session_fallback': True}
    response = admin.post('/admin/api/security-features/passkey', json=body, headers=_grant(admin))
    assert response.status_code == 409
    assert response.json['code'] == 'feature_impact_changed'
    preview = admin.get('/admin/api/security-features/passkey/impact').json
    with app.app_context():
        user = User.query.filter_by(username='changed_account').one()
        user.mfa_enabled = True
        db.session.commit()
    response = admin.post('/admin/api/security-features/passkey',
        json={**body, 'impact_approval':preview['approval']}, headers=_grant(admin))
    assert response.status_code == 409
    assert response.json['code'] == 'feature_impact_changed'


def test_disable_accepts_exact_preview_once_and_does_not_bypass_step_up(app, monkeypatch):
    admin = _login(app, create=True)
    _enable_passkeys(app, monkeypatch)
    preview = admin.get('/admin/api/security-features/passkey/impact').json
    body = {'enabled': False, 'confirm_session_fallback': True, 'impact_approval': preview['approval']}
    assert admin.post('/admin/api/security-features/passkey', json=body).status_code == 403
    assert admin.post('/admin/api/security-features/passkey', json=body, headers=_grant(admin)).status_code == 200


def test_non_admin_cannot_inspect_account_impact(app):
    _login(app, create=True)
    ordinary = _login(app, 'normal_account', create=True)
    assert ordinary.get('/admin/api/security-features/passkey/impact').status_code == 403


def test_ldap_disable_has_no_password_fallback_for_directory_accounts(app, monkeypatch):
    import config
    from app.models import LDAPIdentity, User, WebAuthnCredential, db
    admin = _login(app, create=True)
    for username in ('directory_only', 'directory_passkey'):
        _login(app, username, create=True)
    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    app.extensions['security_feature_readiness']['ldap'] = (True, None)
    _enable_passkeys(app, monkeypatch)
    with app.app_context():
        for user in User.query.filter(User.username != 'session_owner'):
            db.session.add(LDAPIdentity(user_id=user.id, provider='default', subject=user.username,
                directory_username=user.username, distinguished_name=f'uid={user.username}'))
            if user.username == 'directory_passkey':
                db.session.add(WebAuthnCredential(user_id=user.id, credential_id=b'ldap-passkey', public_key=b'test'))
        db.session.commit()
    impact = admin.get('/admin/api/security-features/ldap/impact').json['impact']
    assert impact['affected_accounts'] == 2
    assert impact['accounts_without_primary'] == 1
    assert impact['remaining_primary'] == {'passkey':1}
    assert next(row for row in impact['accounts'] if row['username'] == 'directory_only')['remaining_primary'] == []


def test_mfa_loss_is_reported_even_when_password_primary_remains(app, monkeypatch):
    from app.models import User, WebAuthnCredential, db
    admin = _login(app, create=True)
    _enable_passkeys(app, monkeypatch)
    with app.app_context():
        user = User.query.first()
        user.mfa_enabled = True
        db.session.add(WebAuthnCredential(user_id=user.id, credential_id=b'only-factor', public_key=b'test'))
        db.session.commit()
    impact = admin.get('/admin/api/security-features/passkey/impact').json['impact']
    assert impact['accounts_without_primary'] == 0
    assert impact['mfa_required_without_local_factor'] == 1
    assert impact['admins_without_local_factor'] == 1


def test_consumed_recovery_codes_are_not_counted_as_configured_paths(app):
    from app.models import User
    from app.recovery_service import generate_codes, consume_code
    admin = _login(app, create=True)
    with app.app_context():
        user_id = User.query.first().id
        code = generate_codes(user_id, count=1)[0]
    assert admin.get('/admin/api/security-features/recovery/impact').json['impact']['affected_accounts'] == 1
    with app.app_context():
        assert consume_code(user_id, code)
    assert admin.get('/admin/api/security-features/recovery/impact').json['impact']['affected_accounts'] == 0


def test_impact_approval_expires_and_is_bound_to_feature_user_and_login(app, monkeypatch):
    import time
    from itsdangerous import TimestampSigner
    from app.security_feature_impact import feature_impact_preview, verify_impact_approval
    _login(app, create=True)
    now = int(time.time())
    monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda _self: now)
    with app.app_context():
        approval = feature_impact_preview('passkey', 1, 1)['approval']
        assert verify_impact_approval(approval, 'passkey', 1, 1)
        assert not verify_impact_approval(approval, 'totp', 1, 1)
        assert not verify_impact_approval(approval, 'passkey', 2, 1)
        assert not verify_impact_approval(approval, 'passkey', 1, 2)
        now += 301
        assert not verify_impact_approval(approval, 'passkey', 1, 1)


def test_impact_approval_cannot_be_replayed_after_login_row_id_reuse(app):
    from app.models import AuthenticationSession, db
    from app.security_feature_impact import feature_impact_preview, verify_impact_approval
    _login(app, create=True)
    with app.app_context():
        row = AuthenticationSession.query.first()
        approval = feature_impact_preview('passkey', row.user_id, row.id)['approval']
        row.session_hash = 'a' * 64
        db.session.commit()
        assert not verify_impact_approval(approval, 'passkey', row.user_id, row.id)
