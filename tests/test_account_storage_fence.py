"""Account retirement must drain writers and reject cached old identities."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace

import pytest
from werkzeug.exceptions import ServiceUnavailable


def _user(name):
    from app.auth import register_user
    user, error = register_user(name, 'synthetic-password')
    assert error is None
    return user


def test_delete_drains_key_upload_before_quarantine(app, monkeypatch, rsa_private_key_pem):
    from app import key_encryption, key_manager, user_lifecycle
    from app.models import User, db

    _user('keeper')
    target = _user('uploadtarget')
    user_id = target.id
    prepared, resume, revoking = Event(), Event(), Event()
    original_encrypt = key_encryption.encrypt_key_content

    def paused_encrypt(*args):
        encrypted = original_encrypt(*args)
        prepared.set()
        assert resume.wait(5)
        return encrypted

    def upload():
        with app.app_context():
            cached_user = db.session.get(User, user_id)
            assert cached_user is not None
            return key_manager.save_key(user_id, 'synthetic-key', rsa_private_key_pem)

    def delete():
        with app.app_context():
            user = db.session.get(User, user_id)
            user.is_locked = True
            db.session.commit()
            return user_lifecycle.delete_user_account(user, SimpleNamespace(server=None))

    monkeypatch.setattr(key_encryption, 'encrypt_key_content', paused_encrypt)
    monkeypatch.setattr(user_lifecycle, 'revoke_user_access', lambda *_args: revoking.set())
    with ThreadPoolExecutor(max_workers=2) as executor:
        writer = executor.submit(upload)
        try:
            assert prepared.wait(5)
            deletion = executor.submit(delete)
            assert revoking.wait(5)
            # Old deletion finishes here; a fenced deletion must await writer.
            try:
                deletion.result(timeout=0.2)
            except TimeoutError:
                pass
        finally:
            resume.set()
        metadata, error = writer.result(timeout=5)
        quarantined = deletion.result(timeout=5)
    assert error is None
    assert (quarantined / 'keys' / metadata['filename']).is_file()
    db.session.remove()
    replacement = _user('replacement')
    assert replacement.id == user_id
    assert key_manager.load_keys(replacement.id) == []


@pytest.mark.parametrize('store', ['settings', 'profiles'])
def test_cached_deleted_identity_cannot_recreate_or_read_replacement_store(app, monkeypatch, store):
    from app import key_manager, profile_manager, user_lifecycle, user_settings
    from app.models import User, db

    _user('keeper')
    target = _user('cachedtarget')
    user_id = target.id
    captured, resume = Event(), Event()

    def stale_operation():
        with app.app_context():
            cached_user = db.session.get(User, user_id)
            captured.set()
            assert resume.wait(5)
            assert cached_user is not None  # Retain its identity-map entry.
            if store == 'settings':
                return user_settings.save_user_settings(user_id, {'notepad': 'old account data'})
            return profile_manager.load_profiles(user_id)

    monkeypatch.setattr(user_lifecycle, 'revoke_user_access', lambda *_args: None)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(stale_operation)
        try:
            assert captured.wait(5)
            user_lifecycle.delete_user_account(target, SimpleNamespace(server=None))
            db.session.remove()
            replacement = _user('replacement')
            assert replacement.id == user_id
        finally:
            resume.set()
        with pytest.raises(ServiceUnavailable):
            pending.result(timeout=5)
    assert user_settings.get_user_settings(user_id)['notepad'] == ''
    assert key_manager.load_keys(user_id) == []


def test_admitted_http_request_cannot_write_as_replacement_after_orm_refresh(app, monkeypatch):
    from flask import jsonify
    from flask_login import current_user, login_required
    from app import user_lifecycle, user_settings
    from app.models import db

    _user('keeper')
    target = _user('httptarget')
    user_id = target.id
    entered, resume = Event(), Event()

    @app.post('/synthetic-storage-race')
    @login_required
    def delayed_write():
        admitted_id = current_user.id
        entered.set()
        assert resume.wait(5)
        db.session.expire_all()
        return jsonify(saved=user_settings.save_user_settings(admitted_id, {'notepad': 'old request data'}))

    browser = app.test_client()
    assert browser.post('/login', data={'username': 'httptarget', 'password': 'synthetic-password'}).status_code == 302
    monkeypatch.setattr(user_lifecycle, 'revoke_user_access', lambda *_args: None)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(browser.post, '/synthetic-storage-race')
        try:
            assert entered.wait(5)
            user_lifecycle.delete_user_account(target, SimpleNamespace(server=None))
            db.session.remove()
            assert _user('replacement').id == user_id
        finally:
            resume.set()
        response = pending.result(timeout=5)
    assert response.status_code == 503
    assert user_settings.get_user_settings(user_id)['notepad'] == ''


def test_retirement_timeout_preserves_admission_for_retry():
    from app.data_access import DataAccessGate

    gate = DataAccessGate()
    active, resume = Event(), Event()

    def operation():
        with gate.access(1):
            active.set()
            assert resume.wait(5)

    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(operation)
        try:
            assert active.wait(5)
            with pytest.raises(ServiceUnavailable):
                with gate.retire(1, on_blocked=lambda: None, timeout=0.01):
                    pytest.fail('retirement passed a running writer')
            # A timed-out retirement must not leave an account blocked.
            with gate.access(1), gate.access(2):
                pass
        finally:
            resume.set()
        pending.result(timeout=5)
    with gate.retire(1, on_blocked=lambda: None):
        with pytest.raises(ServiceUnavailable):
            with gate.access(1):
                pytest.fail('retiring account admitted a new writer')


def test_retirement_cleanup_failure_does_not_leave_account_blocked():
    from app.data_access import DataAccessGate

    gate = DataAccessGate()

    def fail():
        raise RuntimeError('synthetic cleanup failure')

    with pytest.raises(RuntimeError, match='synthetic cleanup failure'):
        with gate.retire(1, on_blocked=fail):
            pytest.fail('failed cleanup reached deletion')
    with gate.access(1):
        pass
