import json

import pytest

from tests.test_admin_routes import _prepare_role


def test_support_report_requires_login_and_explicit_post(client):
    assert client.post('/api/account/support-report', json={}).status_code in (302, 401)
    assert client.get('/api/account/support-report').status_code == 405


@pytest.mark.parametrize('body', [None, [], {'area': []}, {'area': 'secrets'},
                                     {'password': 'private'}, {'reference': 'secret-value'},
                                     {'reference': 'SMB-ABCDEF123456\n'}])
def test_support_report_rejects_unrecognized_content(app, client, body):
    _prepare_role(app, client, 'normal')
    assert client.post('/api/account/support-report', json=body).status_code == 400


def test_support_report_limits_nonadmin_data_and_sanitizes_secrets(app, client, monkeypatch):
    import config
    _prepare_role(app, client, 'normal')
    monkeypatch.setenv('WEBSSH_REVISION', 'private-secret-not-a-revision')
    monkeypatch.setenv('SUPPORT_SECRET', 'must-not-export')
    monkeypatch.setattr(config, 'OIDC_CLIENT_SECRET_FILE', '/private/secret-path')
    monkeypatch.setattr(config, 'OIDC_ISSUER', 'https://private-idp.example')
    response = client.post('/api/account/support-report', json={
        'area': 'files', 'reference': 'SMB-ABCDEF123456',
    })
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    data = response.json
    assert set(data) == {'schema', 'generated_at', 'version', 'area', 'reference',
                         'https', 'readiness', 'features'}
    assert data['reference'] == 'SMB-ABCDEF123456'
    assert data['area'] == 'files'
    assert data['schema'] == 1
    assert set(data['readiness']) == {'status', 'failed'}
    assert set(data['features']) == {'ssh', 'sftp', 'smb', 'tmux', 'automation',
                                    'saved_passwords', 'passkey', 'totp', 'oidc',
                                    'ldap', 'recovery'}
    assert all(type(value) is bool for value in data['features'].values())
    serialized = json.dumps(data)
    for forbidden in ('must-not-export', 'private-', str(config.DATA_DIR), 'username',
                      'session_id', 'SECRET_KEY', 'password_hash', 'cookie'):
        assert forbidden not in serialized


def test_support_report_admin_posture_is_allowlisted(app, client, monkeypatch):
    import config
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'DEPLOYMENT_PROFILE', 'private-deployment-value')
    response = client.post('/api/account/support-report', json={})
    assert response.status_code == 200
    assert set(response.json['deployment']) == {'profile', 'secure_cookie',
                                               'internal_ssh_blocked'}
    assert response.json['deployment']['profile'] == 'unknown'
    assert 'private-deployment-value' not in response.get_data(as_text=True)


def test_support_report_unready_is_reported_without_raw_exception(app, client, monkeypatch):
    from app import health
    _prepare_role(app, client, 'normal')
    def fail():
        raise OSError('secret path /private/passwords')
    monkeypatch.setattr(health, '_probe_data_directory', fail)
    response = client.post('/api/account/support-report', json={})
    assert response.status_code == 200
    assert response.json['readiness']['status'] == 'not_ready'
    assert 'data_directory' in response.json['readiness']['failed']
    assert '/private/' not in response.get_data(as_text=True)


def test_support_report_requires_csrf(app, client):
    _prepare_role(app, client, 'normal')
    app.config['WTF_CSRF_ENABLED'] = True
    assert client.post('/api/account/support-report', json={}).status_code == 400


def test_support_report_unavailable_during_factor_recovery(app, client):
    from app.models import AuthenticationSession, User, db
    _prepare_role(app, client, 'normal')
    with app.app_context():
        user = User.query.filter_by(username='normaluser').one()
        row = AuthenticationSession.query.filter_by(user_id=user.id).one()
        row.methods_json = '["password","recovery_code"]'
        db.session.commit()
    assert client.post('/api/account/support-report', json={}).status_code == 403
