"""Server-side pending authentication and finalized login boundaries."""

from datetime import datetime, timedelta, timezone
import logging

import pytest


def _create_user(app, username='alice', *, mfa_enabled=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        user.mfa_enabled = mfa_enabled
        db.session.commit()
        return user.id


def test_pending_authentication_is_session_bound_and_single_use(app):
    from app.auth_assurance import (
        AssuranceLevel,
        PendingAuthenticationError,
        begin_authentication,
        consume_pending,
    )
    from app.models import User, db

    user_id = _create_user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            remember=False,
            continuation='/',
            session_binding='browser-a',
        )

        with pytest.raises(PendingAuthenticationError):
            consume_pending(token, 'browser-b')
        pending = consume_pending(token, 'browser-a')

        assert pending.user_id == user.id
        assert pending.primary_method == 'password'
        with pytest.raises(PendingAuthenticationError):
            consume_pending(token, 'browser-a')


def test_mfa_back_action_invalidates_the_bound_pending_login(app, client):
    from app.auth_assurance import (
        AssuranceLevel,
        begin_authentication,
    )
    from app.models import PendingAuthentication, User, db

    user_id = _create_user(app, 'cancelled_mfa_login')
    binding = 'browser-binding-for-cancelled-login'
    with app.app_context():
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            remember=False,
            continuation='/',
            session_binding=binding,
        )
    with client.session_transaction() as browser_session:
        browser_session['_pending_authentication'] = token
        browser_session['_auth_binding'] = binding

    response = client.post('/login/cancel')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/login')
    assert client.get('/login/cancel').status_code == 405
    with client.session_transaction() as browser_session:
        assert '_pending_authentication' not in browser_session
        assert '_auth_binding' not in browser_session
        assert '_user_id' not in browser_session
    with app.app_context():
        assert PendingAuthentication.query.count() == 0


def test_mfa_back_action_requires_csrf_before_pending_login_is_deleted(
    app,
    client,
):
    from app.auth_assurance import AssuranceLevel, begin_authentication
    from app.models import PendingAuthentication, User, db

    user_id = _create_user(app, 'csrf_protected_mfa_cancel')
    binding = 'browser-binding-for-csrf-protected-cancel'
    with app.app_context():
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            remember=False,
            continuation='/',
            session_binding=binding,
        )
    with client.session_transaction() as browser_session:
        browser_session['_pending_authentication'] = token
        browser_session['_auth_binding'] = binding

    app.config['WTF_CSRF_ENABLED'] = True
    try:
        response = client.post('/login/cancel')
    finally:
        app.config['WTF_CSRF_ENABLED'] = False

    assert response.status_code == 400
    with client.session_transaction() as browser_session:
        assert browser_session['_pending_authentication'] == token
        assert browser_session['_auth_binding'] == binding
    with app.app_context():
        assert PendingAuthentication.query.count() == 1


def test_mfa_back_action_does_not_log_out_an_authenticated_user(app, client):
    from app.models import AuthenticationSession

    _create_user(app, 'active_login_cancel_guard')
    login = client.post('/login', data={
        'username': 'active_login_cancel_guard',
        'password': 'password123',
    })
    assert login.status_code == 302

    response = client.post('/login/cancel')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')
    assert client.get('/').status_code == 200
    with app.app_context():
        assert AuthenticationSession.query.count() == 1


@pytest.mark.parametrize(
    'unsafe_continuation',
    (
        'https://evil.example/path',
        '//evil.example/path',
        r'/safe\evil',
        'relative/path',
        '/path#fragment',
    ),
)
def test_pending_authentication_replaces_unsafe_continuations(
    app,
    unsafe_continuation,
):
    from app.auth_assurance import (
        AssuranceLevel,
        begin_authentication,
        consume_pending,
    )
    from app.models import User, db

    user_id = _create_user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            session_binding='browser-a',
            remember=False,
            continuation=unsafe_continuation,
        )

        pending = consume_pending(token, 'browser-a')

    assert pending.continuation == '/'


def test_finalizer_hashes_browser_session_token_and_records_assurance(app):
    from flask import session
    from app.auth_assurance import (
        AssuranceLevel,
        begin_authentication,
        consume_pending,
        current_authentication_session,
        finalize_login,
    )
    from app.models import AuthenticationSession, User, db

    user_id = _create_user(app)
    with app.test_request_context('/'):
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            session_binding='browser-a',
            remember=True,
            continuation='/admin?tab=settings',
        )
        pending = consume_pending(token, 'browser-a')

        row = finalize_login(pending, methods=['password'])
        browser_token = session['_auth_session']

        assert row.assurance == 'BASIC'
        assert row.methods_json == '["password"]'
        assert row.auth_generation == user.auth_generation
        assert row.user_id == user.id
        assert row.expires_at > datetime.now(timezone.utc).replace(tzinfo=None)
        assert row.session_hash != browser_token
        assert browser_token not in row.session_hash
        assert current_authentication_session().id == row.id
        assert AuthenticationSession.query.count() == 1


def test_finalizer_rejects_unconsumed_and_already_finalized_pending_rows(app):
    from app.auth_assurance import (
        AssuranceLevel,
        AuthenticationFinalizationError,
        begin_authentication,
        consume_pending,
        finalize_login,
    )
    from app.models import PendingAuthentication, User, db

    user_id = _create_user(app)
    with app.test_request_context('/'):
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            session_binding='browser-a',
            remember=False,
            continuation='/',
        )
        unconsumed = PendingAuthentication.query.one()

        with pytest.raises(AuthenticationFinalizationError):
            finalize_login(unconsumed, methods=['password'])

        consumed = consume_pending(token, 'browser-a')
        finalize_login(consumed, methods=['password'])

        with pytest.raises(AuthenticationFinalizationError):
            finalize_login(consumed, methods=['password'])


@pytest.mark.parametrize('sensitive_key', ('password', 'secret', 'token', 'code'))
def test_pending_authentication_rejects_sensitive_evidence_keys(
    app,
    sensitive_key,
):
    from app.auth_assurance import AssuranceLevel, begin_authentication
    from app.models import User, db

    user_id = _create_user(app)
    with app.app_context():
        user = db.session.get(User, user_id)

        with pytest.raises(ValueError):
            begin_authentication(
                user,
                'password',
                assurance=AssuranceLevel.BASIC,
                session_binding='browser-a',
                remember=False,
                continuation='/',
                evidence={sensitive_key: 'must-not-be-stored'},
            )


def test_finalizer_sets_ldap_verification_only_from_ldap_evidence(app):
    from flask import session
    from app.auth_assurance import (
        AssuranceLevel,
        begin_authentication,
        consume_pending,
        finalize_login,
    )
    from app.models import User, db

    user_id = _create_user(app)
    with app.test_request_context('/'):
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'ldap',
            assurance=AssuranceLevel.BASIC,
            session_binding='browser-a',
            remember=False,
            continuation='/',
            evidence={'verified_at': 123456},
        )
        pending = consume_pending(token, 'browser-a')

        finalize_login(pending, methods=['ldap'])

        assert session['_ldap_verified_at'] == 123456


def test_finalizer_storage_failure_leaves_browser_unauthenticated(
    app,
    monkeypatch,
):
    from flask import session
    from app.auth_assurance import (
        AssuranceLevel,
        AuthenticationFinalizationError,
        begin_authentication,
        consume_pending,
        finalize_login,
    )
    from app.models import AuthenticationSession, User, db

    user_id = _create_user(app)
    with app.test_request_context('/'):
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            'password',
            assurance=AssuranceLevel.BASIC,
            session_binding='browser-a',
            remember=False,
            continuation='/',
        )
        pending = consume_pending(token, 'browser-a')

        def fail_commit():
            raise RuntimeError('database unavailable')

        monkeypatch.setattr(db.session, 'commit', fail_commit)

        with pytest.raises(AuthenticationFinalizationError):
            finalize_login(pending, methods=['password'])

        assert '_user_id' not in session
        assert '_auth_session' not in session
        assert AuthenticationSession.query.count() == 0


def test_local_password_login_creates_one_assurance_session(
    app,
    client,
    caplog,
):
    from app.models import AuthenticationSession

    _create_user(app, 'plain')
    with caplog.at_level(logging.INFO, logger='security_audit'):
        response = client.post('/login', data={
            'username': 'plain',
            'password': 'password123',
        })

    assert response.status_code == 302
    with app.app_context():
        row = AuthenticationSession.query.one()
        assert row.assurance == 'BASIC'
        assert row.methods_json == '["password"]'
    successes = [
        record for record in caplog.records
        if 'AUTHENTICATION_SUCCESS' in record.getMessage()
    ]
    assert len(successes) == 1


def test_mfa_enabled_password_login_stays_pending(app, client):
    from app.models import AuthenticationSession, PendingAuthentication

    _create_user(app, 'needsmfa', mfa_enabled=True)

    response = client.post('/login', data={
        'username': 'needsmfa',
        'password': 'password123',
    })

    assert response.status_code == 200
    with client.session_transaction() as browser_session:
        assert '_user_id' not in browser_session
        assert browser_session.get('_pending_authentication')
        assert browser_session.get('_auth_binding')
    with app.app_context():
        assert PendingAuthentication.query.count() == 1
        assert AuthenticationSession.query.count() == 0


def test_remember_cookie_restores_the_bound_authentication_session(app, client):
    from flask import g
    from flask_login.utils import decode_cookie
    from app.auth_assurance import authentication_session_for_token

    _create_user(app, 'remembereduser')
    response = client.post('/login', data={
        'username': 'remembereduser',
        'password': 'password123',
        'remember': 'on',
    })
    assert response.status_code == 302
    remember_cookie = client.get_cookie('remember_token')
    assert remember_cookie is not None
    with app.app_context():
        remembered_identifier = decode_cookie(remember_cookie.value)
    assert remembered_identifier.count(':') == 2
    user_id, auth_generation, auth_session_token = remembered_identifier.split(
        ':',
        2,
    )
    with app.app_context():
        assert authentication_session_for_token(
            auth_session_token,
            int(user_id),
            int(auth_generation),
        ) is not None
    with client.session_transaction() as browser_session:
        assert browser_session.get('_auth_session') == auth_session_token
        assert browser_session.get('_user_id') == remembered_identifier

    client.delete_cookie('session', domain='localhost')
    assert client.get_cookie('session') is None
    # The shared app fixture intentionally keeps an outer app context alive.
    # Clear Flask-Login's app-context cache to emulate the next real request.
    g.pop('_login_user', None)

    restored = client.get('/')

    assert restored.status_code == 200
    with client.session_transaction() as browser_session:
        assert browser_session.get('_auth_session')


def test_legacy_remember_cookie_is_cleared_before_login_redirect(app, client):
    from flask_login.utils import encode_cookie
    from app.models import User, db

    user_id = _create_user(app, 'legacyremembered')
    with app.app_context():
        legacy_identifier = db.session.get(User, user_id).get_id()
        legacy_cookie = encode_cookie(legacy_identifier)

    client.set_cookie('remember_token', legacy_cookie)

    rejected = client.get('/')

    assert rejected.status_code == 302
    assert '/login?next=' in rejected.headers['Location']
    assert client.get_cookie('remember_token') is None

    login = client.get(rejected.headers['Location'])

    assert login.status_code == 200


def test_request_guard_rejects_invalid_server_side_sessions(
    app,
    client,
):
    from flask import g
    from app.auth import register_user
    from app.models import AuthenticationSession, db

    _create_user(app, 'guarded')
    with app.app_context():
        other, error = register_user('otheruser', 'password123')
        assert error is None
        db.session.commit()
        other_id = other.id

    assert client.post('/login', data={
        'username': 'guarded',
        'password': 'password123',
    }).status_code == 302
    with app.app_context():
        row = AuthenticationSession.query.one()
        row.user_id = other_id
        db.session.commit()

    wrong_user = client.get('/')

    assert wrong_user.status_code == 302
    assert '/login?next=' in wrong_user.headers['Location']

    assert client.post('/login', data={
        'username': 'guarded',
        'password': 'password123',
    }).status_code == 302
    with app.app_context():
        row = AuthenticationSession.query.order_by(
            AuthenticationSession.id.desc()
        ).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    expired = client.get('/')

    assert expired.status_code == 302
    assert '/login?next=' in expired.headers['Location']

    assert client.post('/login', data={
        'username': 'guarded',
        'password': 'password123',
    }).status_code == 302
    with app.app_context():
        AuthenticationSession.query.delete()
        db.session.commit()

    missing = client.get('/')

    assert missing.status_code == 302
    assert '/login?next=' in missing.headers['Location']

    assert client.post('/login', data={
        'username': 'guarded',
        'password': 'password123',
    }).status_code == 302
    with app.app_context():
        from app.models import User

        guarded = User.query.filter_by(username='guarded').one()
        guarded.auth_generation += 1
        db.session.commit()
        row = AuthenticationSession.query.order_by(
            AuthenticationSession.id.desc()
        ).first()
        assert guarded.auth_generation == 1
        assert row.auth_generation == 0
    g.pop('_login_user', None)
    db.session.expire_all()

    wrong_generation = client.get('/')

    assert wrong_generation.status_code == 302
    assert '/login?next=' in wrong_generation.headers['Location']


def test_logout_deletes_current_authentication_session(app, client):
    from app.models import AuthenticationSession

    _create_user(app, 'logoutassurance')
    assert client.post('/login', data={
        'username': 'logoutassurance',
        'password': 'password123',
        'remember': 'on',
    }).status_code == 302
    assert client.get_cookie('remember_token') is not None
    with app.app_context():
        assert AuthenticationSession.query.count() == 1

    response = client.post('/logout')

    assert response.status_code == 302
    assert client.get_cookie('remember_token') is None
    with app.app_context():
        assert AuthenticationSession.query.count() == 0
