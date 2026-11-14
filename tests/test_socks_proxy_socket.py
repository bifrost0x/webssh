"""User-owned SOCKS resources and fail-closed connection entry points."""

import pytest
from flask import request

from app import socket_events as events

pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def user_socket(app, name):
    from app.auth import register_user, register_socket_session
    from app.models import db
    with app.app_context():
        user, error = register_user(name, 'socket-password-123')
        assert error is None
        sid = name + '-socket'
        register_socket_session(user.id, sid)
        db.session.commit()
        return user.id, sid


def call(app, monkeypatch, handler, sid, payload=None):
    emitted = []
    monkeypatch.setattr(events, 'emit', lambda event, data=None, **kw: emitted.append((event, data)))
    with app.test_request_context('/socket.io'):
        request.sid = sid
        result = handler() if payload is None else handler(payload)
    return result, emitted


def test_socks_crud_inventory_and_user_isolation(app, monkeypatch):
    from app.models import User, db
    owner, sid = user_socket(app, 'socks_owner')
    other, other_sid = user_socket(app, 'socks_other')
    saved, emitted = call(app, monkeypatch, events.handle_save_socks_proxy, sid, {
        'name': 'Office proxy', 'host': 'proxy.example', 'port': 1080,
        'auth_type': 'password', 'username': 'proxy-user', 'remote_dns': True,
        'password': 'must-not-persist', 'user_id': other,
    })
    assert saved['success'] is True
    proxy = saved['socks_proxy']
    assert 'password' not in proxy and 'user_id' not in proxy
    assert emitted == [('socks_proxy_saved', saved)]
    _, emitted = call(app, monkeypatch, events.handle_list_socks_proxies, sid)
    assert emitted == [('socks_proxies_list', {'socks_proxies': [proxy]})]
    _, emitted = call(app, monkeypatch, events.handle_list_socks_proxies, other_sid)
    assert emitted == [('socks_proxies_list', {'socks_proxies': []})]
    with app.app_context():
        inventory = events.initial_inventory(db.session.get(User, owner))
        assert inventory['socks_proxies'] == [proxy]
        assert b'must-not-persist' not in (
            db.session.get(User, owner).get_data_dir() / 'socks_proxies.json'
        ).read_bytes()
    denied, _ = call(app, monkeypatch, events.handle_delete_socks_proxy, other_sid,
                     {'socks_proxy_id': proxy['id']})
    assert denied['success'] is False
    deleted, emitted = call(app, monkeypatch, events.handle_delete_socks_proxy, sid,
                           {'socks_proxy_id': proxy['id']})
    assert deleted == {'success': True, 'socks_proxy_id': proxy['id']}
    assert emitted == [('socks_proxy_deleted', deleted)]


def test_socks_crud_rejects_used_proxy_and_limits_mutations(app, monkeypatch):
    from app import profile_manager, socks_proxy_manager
    owner, sid = user_socket(app, 'socks_usage')
    with app.app_context():
        proxy, error = socks_proxy_manager.add_socks_proxy(owner, 'Proxy', 'proxy.example', 1080)
        assert error is None
        profile, error = profile_manager.add_profile(
            owner, 'Target', 'target.example', 22, 'ops', 'password', socks_proxy_id=proxy['id'],
        )
        assert error is None
    denied, _ = call(app, monkeypatch, events.handle_delete_socks_proxy, sid,
                     {'socks_proxy_id': proxy['id']})
    assert denied['success'] is False
    assert 'Target' in denied['usages']
    monkeypatch.setattr(events, '_connection_mutation_rate_limit',
                        lambda user: {'success': False, 'error': 'limited'})
    for handler, payload in [
        (events.handle_save_socks_proxy, {'name': 'Blocked'}),
        (events.handle_delete_socks_proxy, {'socks_proxy_id': proxy['id']}),
    ]:
        result, _ = call(app, monkeypatch, handler, sid, payload)
        assert result == {'success': False, 'error': 'limited'}


@pytest.mark.parametrize('payload', [{}, {'port': True}, {'remote_dns': 'false'}])
def test_socks_crud_invalid_payload_is_safe(app, monkeypatch, payload):
    _, sid = user_socket(app, 'socks_invalid')
    result, _ = call(app, monkeypatch, events.handle_save_socks_proxy, sid, payload)
    assert result['success'] is False
