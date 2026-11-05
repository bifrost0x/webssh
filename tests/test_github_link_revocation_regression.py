"""A provider callback must not outlive its authorizing authentication."""
from urllib.parse import parse_qs, urlsplit
import pytest

from tests.test_github_auth_routes import _configure, _create_user, _login, _provider
from tests.step_up_helpers import account_password_step_up_headers


@pytest.mark.parametrize('boundary', ['exchange', 'profile', 'insert'])
@pytest.mark.parametrize('change', ['revoke', 'lock'])
def test_github_link_rejects_revocation_during_provider_exchange(app, client, monkeypatch, boundary, change):
    import app.github_auth_routes as routes
    from app.auth_assurance import invalidate_user_authentication
    from app.models import GitHubIdentity, User, db

    admin_id = _create_user(app, 'link_probe_admin', is_admin=True)
    user_id = _create_user(app, 'link_probe_user')
    _configure(app, admin_id)
    _login(client, 'link_probe_user')
    _provider(monkeypatch)
    headers = account_password_step_up_headers(client, 'github.link', user_id)[0]
    started = client.post('/api/account/github/link/start', json={}, headers=headers)
    assert started.status_code == 200
    state = parse_qs(urlsplit(started.json['authorization_url']).query)['state'][0]

    def revoke():
        target = db.session.get(User, user_id)
        if change == 'lock':
            target.is_locked = True
        invalidate_user_authentication(target)
        db.session.commit()

    def revoke_during_exchange(*_args, **_kwargs):
        revoke()
        return 'fixture-provider-token'

    if boundary == 'exchange':
        monkeypatch.setattr(routes, 'exchange_code', revoke_during_exchange)
    elif boundary == 'profile':
        original_profile = routes.fetch_profile
        def revoke_during_profile(token):
            revoke()
            return original_profile(token)
        monkeypatch.setattr(routes, 'fetch_profile', revoke_during_profile)
    else:
        original_execute = db.session.execute
        def revoke_before_insert(statement, *args, **kwargs):
            if getattr(statement, 'is_insert', False) and statement.table.name == 'github_identities':
                revoke()
            return original_execute(statement, *args, **kwargs)
        monkeypatch.setattr(db.session, 'execute', revoke_before_insert)
    response = client.get(f'/auth/github/callback?code=fixture-code&state={state}')
    with app.app_context():
        linked = GitHubIdentity.query.filter_by(user_id=user_id).count()
    assert (response.status_code, linked) == (403, 0)


def test_github_link_columns_upgrade_old_table_idempotently(app):
    from sqlalchemy import inspect, text
    from app.models import db, ensure_security_columns
    with app.app_context():
        for name in ('auth_generation', 'authentication_session_id'):
            db.session.execute(text(f'ALTER TABLE github_oauth_states DROP COLUMN {name}'))
        db.session.commit()
        ensure_security_columns()
        ensure_security_columns()
        columns = {column['name'] for column in inspect(db.engine).get_columns('github_oauth_states')}
        assert {'auth_generation', 'authentication_session_id'} <= columns
