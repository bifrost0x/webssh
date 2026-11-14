import json
from pathlib import Path

import pytest
from tests.test_automation_service import context

STAMP = '2026-11-14T06:00:00+00:00'
NEW_STAMP = '2026-11-14T06:01:00+00:00'


def marker(monkeypatch, tmp_path, content):
    import config
    (Path(config.DATA_DIR) / 'recovery-check.json').write_text(content, encoding='utf-8')


def test_recovery_review_is_account_owned_and_specific_to_latest_restore(app, client, context, monkeypatch, tmp_path):
    marker(monkeypatch, tmp_path, json.dumps({'restored_at': STAMP}))
    assert client.get('/api/account/recovery-check').json['needs_review'] is True
    assert client.post('/api/account/recovery-check', json={'restored_at': STAMP}).status_code == 200
    assert client.get('/api/account/recovery-check').json['needs_review'] is False
    from app.auth import register_user
    from app.user_settings import get_user_settings
    other, error = register_user('recovery_notice_other', 'password123')
    assert error is None
    assert get_user_settings(other.id).get('recovery_reviewed_at', '') == ''
    assert client.post('/logout').status_code in (200, 302)
    assert client.post('/login', data={'username': 'recovery_notice_other', 'password': 'password123'}).status_code == 302
    assert client.get('/api/account/recovery-check').json['needs_review'] is True
    marker(monkeypatch, tmp_path, json.dumps({'restored_at': NEW_STAMP}))
    assert client.post('/api/account/recovery-check', json={'restored_at': STAMP}).status_code == 409
    assert client.get('/api/account/recovery-check').json['needs_review'] is True
    assert client.post('/api/account/recovery-check', json={'restored_at': NEW_STAMP}).status_code == 200
    assert get_user_settings(other.id)['recovery_reviewed_at'] == NEW_STAMP
    assert get_user_settings(context[0])['recovery_reviewed_at'] == STAMP


@pytest.mark.parametrize('content', ['', '{bad', '[]', '{"restored_at":null}', '{"restored_at":"2026-11-14"}', 'x'*513])
def test_invalid_recovery_marker_does_not_prompt_or_accept_review(app, client, context, monkeypatch, tmp_path, content):
    marker(monkeypatch, tmp_path, content)
    data = client.get('/api/account/recovery-check').json
    assert data['restored_at'] is None
    assert data['needs_review'] is False
    assert client.post('/api/account/recovery-check', json={'restored_at': STAMP}).status_code == 409


def test_missing_marker_does_not_prompt_and_review_is_strict(app, client, context, monkeypatch, tmp_path):
    assert client.get('/api/account/recovery-check').json['needs_review'] is False
    for body in ({}, {'restored_at': STAMP, 'user_id': 1}, {'restored_at': 1}, {'restored_at': 'x'*65}, {'restored_at': 'not-a-date'}):
        assert client.post('/api/account/recovery-check', json=body).status_code == 400
    from app.user_settings import save_user_settings
    assert save_user_settings(context[0], {'recovery_reviewed_at': 'x'*65}) is False
    assert save_user_settings(context[0], {'recovery_reviewed_at': 123}) is False


def test_recovery_review_requires_login_and_csrf(app, client, context, monkeypatch, tmp_path):
    marker(monkeypatch, tmp_path, json.dumps({'restored_at': STAMP}))
    app.config['WTF_CSRF_ENABLED'] = True
    assert client.post('/api/account/recovery-check', json={'restored_at': STAMP}).status_code == 400
    assert client.get('/api/account/recovery-check').json['needs_review'] is True
    app.config['WTF_CSRF_ENABLED'] = False
    assert app.test_client().post('/api/account/recovery-check', json={'restored_at': STAMP}).status_code in (302,401)


def test_optional_marker_write_failure_cannot_fail_successful_restore(app, tmp_path, monkeypatch):
    import app.customer_workflows as workflows
    def fail(*args, **kwargs):
        raise OSError('marker unavailable')
    monkeypatch.setattr(workflows, 'atomic_write_json', fail)
    assert workflows.mark_restore_recovery(tmp_path) is None
