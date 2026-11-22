"""Password sign-in limits per source network and per account."""

import pytest


LIMITED = b'Too many login attempts'


@pytest.fixture
def limited_app(app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', True)
    monkeypatch.setattr(config, 'RATELIMIT_LOGIN_LIMIT', '5 per minute')
    monkeypatch.setattr(config, 'RATELIMIT_LOGIN_ACCOUNT_LIMIT', '10 per hour', raising=False)
    with app.app_context():
        from app.auth import register_user

        user, error = register_user('victim', 'correct-password')
        assert error is None
    return app


def _attempt(app, address, username='victim', password='wrong-password', client=None):
    client = client or app.test_client()
    return client.post(
        '/login',
        data={'username': username, 'password': password},
        environ_base={'REMOTE_ADDR': address},
    )


def test_rotating_ipv6_addresses_in_one_prefix_share_the_source_limit(limited_app):
    responses = [
        _attempt(limited_app, f'2001:db8:1:2::{index:x}', username=f'name{index}')
        for index in range(1, 7)
    ]

    assert all(LIMITED not in response.data for response in responses[:5])
    assert LIMITED in responses[5].data


def test_other_ipv6_prefixes_keep_their_own_source_budget(limited_app):
    for index in range(1, 6):
        _attempt(limited_app, f'2001:db8:1:2::{index:x}', username=f'name{index}')

    response = _attempt(limited_app, '2001:db8:1:3::1', username='other')

    assert LIMITED not in response.data


@pytest.mark.parametrize('username', ['victim', 'nobody_here'])
def test_account_budget_stops_guessing_from_many_addresses(limited_app, username):
    responses = [
        _attempt(limited_app, f'198.51.100.{index}', username=username)
        for index in range(1, 12)
    ]

    assert all(LIMITED not in response.data for response in responses[:10])
    assert LIMITED in responses[10].data
    # The refused attempt is not checked, so a correct password gains nothing.
    blocked = _attempt(limited_app, '198.51.100.99', username=username, password='correct-password')
    assert blocked.status_code == 200
    assert LIMITED in blocked.data


def test_account_budget_ignores_case_and_surrounding_whitespace(limited_app):
    for index, name in enumerate(['victim', 'VICTIM', ' Victim '] * 4, start=1):
        response = _attempt(limited_app, f'198.51.100.{index}', username=name)

    assert LIMITED in response.data


def test_browser_that_signed_in_before_is_not_locked_out_by_an_attacker(limited_app):
    owner = limited_app.test_client()
    signed_in = _attempt(limited_app, '192.0.2.10', password='correct-password', client=owner)
    assert signed_in.status_code == 302
    assert any(
        header.startswith('session_device=') and 'HttpOnly' in header
        for header in signed_in.headers.getlist('Set-Cookie')
    )
    owner.post('/logout', environ_base={'REMOTE_ADDR': '192.0.2.10'})

    for index in range(1, 12):
        _attempt(limited_app, f'203.0.113.{index}')
    assert LIMITED in _attempt(limited_app, '203.0.113.50', password='correct-password').data

    again = _attempt(limited_app, '192.0.2.10', password='correct-password', client=owner)
    assert again.status_code == 302


def test_device_cookie_from_another_secret_is_ignored(limited_app):
    attacker = limited_app.test_client()
    attacker.set_cookie('session_device', 'forged.value.signature')
    for index in range(1, 11):
        _attempt(limited_app, f'203.0.113.{index}', client=attacker)

    assert LIMITED in _attempt(limited_app, '203.0.113.60', client=attacker).data


def test_rate_limit_source_normalizes_addresses():
    from app.auth import rate_limit_source

    assert rate_limit_source('2001:db8:1:2:aaaa:bbbb:cccc:dddd') == '2001:db8:1:2::/64'
    assert rate_limit_source('::ffff:198.51.100.7') == '198.51.100.7'
    assert rate_limit_source('198.51.100.7') == '198.51.100.7'
    assert rate_limit_source('unknown') == 'unknown'
