"""GitHub login, linking, provisioning, and admin API tests."""

from urllib.parse import parse_qs, urlsplit

from tests.step_up_helpers import (
    account_password_step_up_headers,
    mint_account_step_up_headers,
    password_step_up_headers,
)


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        user.is_admin = is_admin
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post('/login', data={
        'username': username, 'password': 'password123'
    })
    assert response.status_code == 302


def _configure(app, admin_id, *, auto_provision=False, allowed_orgs=()):
    from app.github_auth_service import update_settings

    with app.app_context():
        update_settings({
            'enabled': True,
            'client_id': 'Iv1234567890abcdef',
            'client_secret': 'a' * 40,
            'redirect_uri': 'https://ssh.example.com/auth/github/callback',
            'auto_provision': auto_provision,
            'allowed_orgs': list(allowed_orgs),
        }, admin_id)


def _begin_login(client):
    response = client.get('/auth/github/login')
    assert response.status_code == 302
    return parse_qs(urlsplit(response.headers['Location']).query)['state'][0]


def _provider(monkeypatch, *, user_id='12345', login='octocat', org_error=None):
    import app.github_auth_routes as routes
    from app.github_auth_service import GitHubProfile

    monkeypatch.setattr(routes, 'exchange_code', lambda *_args, **_kwargs: 'temporary-token')
    monkeypatch.setattr(
        routes, 'fetch_profile',
        lambda _token: GitHubProfile(user_id, login, 'Octo Cat'),
    )
    if org_error is None:
        monkeypatch.setattr(
            routes, 'enforce_organization_policy', lambda *_args, **_kwargs: None
        )
    else:
        monkeypatch.setattr(
            routes, 'enforce_organization_policy',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(org_error),
        )


def test_routes_are_hidden_until_admin_configuration_is_active(app, client):
    response = client.get('/auth/github/login')
    assert response.status_code == 404


def test_github_step_up_start_rejects_non_object_json(app, client):
    admin_id = _create_user(app, 'github_json_admin', is_admin=True)
    _configure(app, admin_id)
    _login(client, 'github_json_admin')

    response = client.post(
        '/api/account/step-up/github/start',
        json=['unexpected'],
    )

    assert response.status_code == 400
    assert response.get_json() == {'error': 'Invalid request'}


def test_linked_identity_login_uses_numeric_id_and_callback_is_single_use(
    app, client, monkeypatch,
):
    from app.models import GitHubIdentity, db

    admin_id = _create_user(app, 'github_admin', is_admin=True)
    user_id = _create_user(app, 'github_user')
    _configure(app, admin_id)
    with app.app_context():
        db.session.add(GitHubIdentity(
            user_id=user_id, github_user_id='12345', login='old-name'
        ))
        db.session.commit()
    state = _begin_login(client)
    _provider(monkeypatch, login='new-name')

    callback = client.get(f'/auth/github/callback?code=code&state={state}')
    replay = client.get(f'/auth/github/callback?code=code&state={state}')

    assert callback.status_code == 302
    assert replay.status_code == 400
    with app.app_context():
        identity = GitHubIdentity.query.one()
        assert identity.github_user_id == '12345'
        assert identity.login == 'new-name'


def test_matching_login_or_email_never_links_unknown_identity(
    app, client, monkeypatch,
):
    admin_id = _create_user(app, 'github_admin_unknown', is_admin=True)
    _create_user(app, 'octocat')
    _configure(app, admin_id)
    state = _begin_login(client)
    _provider(monkeypatch, user_id='99999', login='octocat')

    response = client.get(f'/auth/github/callback?code=code&state={state}')

    assert response.status_code == 403
    assert 'not linked' in response.get_json()['error']


def test_auto_provision_never_creates_an_administrator(app, client, monkeypatch):
    from app.models import GitHubIdentity, User

    admin_id = _create_user(app, 'github_bootstrap_admin', is_admin=True)
    _configure(app, admin_id, auto_provision=True)
    state = _begin_login(client)
    _provider(monkeypatch, user_id='777', login='new-contributor')

    response = client.get(f'/auth/github/callback?code=code&state={state}')

    assert response.status_code == 302
    with app.app_context():
        identity = GitHubIdentity.query.filter_by(github_user_id='777').one()
        user = User.query.filter_by(username='new_contributor').one()
        assert identity.user_id == user.id
        assert identity.provisioned_by_github is True
        assert user.is_admin is False


def test_auto_provision_uses_a_distinct_name_for_casefold_collisions(
    app, client, monkeypatch,
):
    from app.models import GitHubIdentity, User

    admin_id = _create_user(app, 'github_case_admin', is_admin=True)
    _create_user(app, 'Octocat')
    _configure(app, admin_id, auto_provision=True)
    state = _begin_login(client)
    _provider(monkeypatch, user_id='6060', login='octocat')

    response = client.get(f'/auth/github/callback?code=code&state={state}')

    assert response.status_code == 302
    with app.app_context():
        identity = GitHubIdentity.query.filter_by(github_user_id='6060').one()
        user = User.query.filter_by(id=identity.user_id).one()
        assert user.username == 'octocat_gh6060'
        assert user.is_admin is False


def test_authenticated_user_can_link_only_after_step_up(app, client, monkeypatch):
    from app.models import GitHubIdentity

    admin_id = _create_user(app, 'github_link_admin', is_admin=True)
    user_id = _create_user(app, 'github_link_user')
    _configure(app, admin_id)
    _login(client, 'github_link_user')

    denied = client.post('/api/account/github/link/start', json={})
    headers = account_password_step_up_headers(
        client, 'github.link', user_id
    )[0]
    started = client.post(
        '/api/account/github/link/start', json={}, headers=headers
    )
    state = parse_qs(urlsplit(started.get_json()['authorization_url']).query)['state'][0]
    _provider(monkeypatch, user_id='314159', login='linked-user')
    callback = client.get(f'/auth/github/callback?code=code&state={state}')

    assert denied.status_code == 403
    assert started.status_code == 200
    assert callback.status_code == 302
    with app.app_context():
        assert GitHubIdentity.query.filter_by(user_id=user_id).one().github_user_id == '314159'


def test_admin_configuration_api_is_step_up_protected_and_secret_is_write_only(
    app, client,
):
    admin_id = _create_user(app, 'github_settings_admin', is_admin=True)
    _login(client, 'github_settings_admin')
    payload = {
        'enabled': True,
        'client_id': 'Iv1234567890abcdef',
        'client_secret': 'a' * 40,
        'redirect_uri': 'https://ssh.example.com/auth/github/callback',
        'auto_provision': False,
        'allowed_orgs': [],
    }
    denied = client.post('/admin/api/github-auth/config', json=payload)
    headers = password_step_up_headers(
        client, 'github.config', 'global'
    )[0]
    saved = client.post(
        '/admin/api/github-auth/config', json=payload, headers=headers
    )
    readback = client.get('/admin/api/github-auth/config')

    assert denied.status_code == 403
    assert saved.status_code == 200
    configuration = readback.get_json()['configuration']
    assert configuration['client_secret_configured'] is True
    assert 'client_secret' not in configuration

    clear_headers = password_step_up_headers(
        client, 'github.config', 'global'
    )[0]
    cleared = client.post(
        '/admin/api/github-auth/config',
        json={'enabled': False, 'clear_client_secret': True},
        headers=clear_headers,
    )
    assert cleared.status_code == 200
    cleared_configuration = cleared.get_json()['configuration']
    assert cleared_configuration['enabled'] is False
    assert cleared_configuration['client_secret_configured'] is False


def test_admin_configuration_validation_does_not_expose_exception_details(
    app, client,
):
    admin_id = _create_user(app, 'github_validation_admin', is_admin=True)
    _login(client, 'github_validation_admin')
    headers = password_step_up_headers(
        client, 'github.config', 'global'
    )[0]

    response = client.post(
        '/admin/api/github-auth/config',
        json={'enabled': 'not-a-boolean'},
        headers=headers,
    )

    assert response.status_code == 400
    assert response.get_json() == {'error': 'Invalid GitHub configuration'}
    assert b'enabled must be a boolean' not in response.data


def test_org_rejection_fails_closed(app, client, monkeypatch):
    from app.github_auth_service import GitHubOrganizationRejected

    admin_id = _create_user(app, 'github_org_admin', is_admin=True)
    _configure(app, admin_id, auto_provision=True, allowed_orgs=('required-org',))
    state = _begin_login(client)
    _provider(
        monkeypatch,
        org_error=GitHubOrganizationRejected('not a member'),
    )

    response = client.get(f'/auth/github/callback?code=code&state={state}')

    assert response.status_code == 403
    assert response.get_json()['error'] == 'GitHub organization membership is required'


def test_github_step_up_start_is_rate_limited_per_user_and_ip(
    app, client, monkeypatch,
):
    from app.models import GitHubIdentity, GitHubOAuthState, db

    admin_id = _create_user(app, 'github_limit_admin', is_admin=True)
    user_id = _create_user(app, 'github_limit_user')
    _configure(app, admin_id)
    with app.app_context():
        db.session.add(GitHubIdentity(
            user_id=user_id, github_user_id='515151', login='limited-user'
        ))
        db.session.commit()
    state = _begin_login(client)
    _provider(monkeypatch, user_id='515151', login='limited-user')
    assert client.get(
        f'/auth/github/callback?code=code&state={state}'
    ).status_code == 302
    intent_response = client.post('/api/account/step-up/intents', json={
        'action': 'github.unlink', 'target': user_id,
    })
    intent = intent_response.get_json()['intent']

    responses = [client.post('/api/account/step-up/github/start', json={
        'intent': intent, 'continuation': '/security',
    }) for _ in range(6)]

    assert [response.status_code for response in responses] == [200] * 5 + [429]
    assert responses[-1].headers['Retry-After'] == '60'
    with app.app_context():
        assert GitHubOAuthState.query.count() == 5


def test_github_provisioned_account_cannot_fall_back_to_local_password(app):
    from app.auth import authenticate_user
    from app.models import GitHubIdentity, User, db

    _create_user(app, 'break_glass_admin', is_admin=True)
    with app.app_context():
        user = User(username='github_managed', is_admin=False)
        user.set_password('known-password')
        db.session.add(user)
        db.session.flush()
        db.session.add(GitHubIdentity(
            user_id=user.id,
            github_user_id='8181',
            login='managed',
            provisioned_by_github=True,
        ))
        db.session.commit()

        authenticated, error = authenticate_user('github_managed', 'known-password')

        assert authenticated is None
        assert error == 'Invalid username or password'


def test_unlink_refuses_to_remove_managed_accounts_only_primary(
    app, client, monkeypatch,
):
    from app.models import GitHubIdentity

    admin_id = _create_user(app, 'unlink_break_glass', is_admin=True)
    _configure(app, admin_id, auto_provision=True)
    state = _begin_login(client)
    _provider(monkeypatch, user_id='9191', login='unlink-managed')
    assert client.get(
        f'/auth/github/callback?code=code&state={state}'
    ).status_code == 302
    with app.app_context():
        identity = GitHubIdentity.query.filter_by(
            github_user_id='9191'
        ).one()
        user_id = identity.user_id
    headers = mint_account_step_up_headers(
        app, client, 'github.unlink', user_id
    )

    response = client.delete('/api/account/github', headers=headers)

    assert response.status_code == 409
    assert 'passkey' in response.get_json()['error'].lower()
