"""Saved bastion references survive browser and process restarts."""

import pytest
from types import SimpleNamespace


@pytest.mark.parametrize('replacement_kind', ['same', 'plain', 'other_tmux', 'other_route', 'other_socks_route'])
def test_preserved_tmux_keeps_recovery_row_unless_replacement_reattached_it(app, monkeypatch, replacement_kind):
    import app.socket_events as events
    from app.auth import register_user
    from app.models import SSHSession, db
    monkeypatch.setattr(events.ssh_manager, 'close_session', lambda *args, **kwargs: True)
    monkeypatch.setattr(events.socketio, 'emit', lambda *args, **kwargs: None)
    monkeypatch.setattr(events, 'log_ssh_disconnect', lambda *args, **kwargs: None)
    with app.test_request_context('/socket.io'):
        user, error = register_user('replace_user', 'socket-password-123')
        assert error is None
        for sid, persistent in [('original', True), ('replacement', replacement_kind != 'plain')]:
            db.session.add(SSHSession(session_id=sid, user_id=user.id, host='target', port=22,
                                      username='alice', connected=True, is_persistent=persistent,
                                      tmux_session_name='original-tmux' if persistent else None))
        db.session.commit()
        replacement = SSHSession.query.filter_by(session_id='replacement').first()
        if replacement_kind == 'other_tmux':
            replacement.tmux_session_name = 'different-tmux'
        if replacement_kind == 'other_route':
            replacement.jump_host_id = 'different-bastion'
        if replacement_kind == 'other_socks_route':
            replacement.socks_proxy_id = 'different-proxy'
            replacement.via_socks = True
        db.session.commit()
        events.handle_ssh_disconnect.__wrapped__(
            {'session_id': 'original', 'preserve_tmux': True, 'replacement_session_id': 'replacement'},
            current_user=user,
        )
        original = SSHSession.query.filter_by(session_id='original').first()
        if replacement_kind == 'same':
            assert original is None
        else:
            assert original is not None
            assert original.connected is False
            assert original.is_persistent is True


@pytest.mark.parametrize('preserve,expected_kill', [(True, False), (False, True), ('true', True)])
def test_replacement_disconnect_preserves_tmux_only_when_explicit(app, monkeypatch, preserve, expected_kill):
    import app.socket_events as events
    calls = []
    monkeypatch.setattr(events, 'verify_session_ownership', lambda sid, uid: True)
    monkeypatch.setattr(events.ssh_manager, 'close_session',
                        lambda sid, **kwargs: calls.append((sid, kwargs)) or True)
    monkeypatch.setattr(events.socketio, 'emit', lambda *args, **kwargs: None)
    monkeypatch.setattr(events, 'log_ssh_disconnect', lambda *args, **kwargs: None)
    with app.test_request_context('/socket.io'):
        events.handle_ssh_disconnect.__wrapped__(
            {'session_id': 'original', 'preserve_tmux': preserve},
            current_user=SimpleNamespace(id=1, username='user'),
        )
    assert calls == [('original', {'kill_tmux': expected_kill})]


def test_replacement_disconnect_cannot_close_another_users_session(app, monkeypatch):
    import app.socket_events as events
    monkeypatch.setattr(events, 'verify_session_ownership', lambda sid, uid: False)
    monkeypatch.setattr(events.ssh_manager, 'close_session',
                        lambda *args, **kwargs: pytest.fail('unauthorized close'))
    errors = []
    monkeypatch.setattr(events, 'emit', lambda *args, **kwargs: errors.append(args))
    with app.test_request_context('/socket.io'):
        events.handle_ssh_disconnect.__wrapped__(
            {'session_id': 'other', 'preserve_tmux': True},
            current_user=SimpleNamespace(id=1, username='user'),
        )
    assert errors[0][0] == 'ssh_error'


@pytest.mark.parametrize('route', ['jump', 'socks'])
def test_restore_preserves_active_and_persistent_route_metadata(app, monkeypatch, route):
    from app import ssh_manager
    from app.auth import register_user
    from app.models import SSHSession, db
    import app.socket_events as socket_events
    import config

    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, payload, **kwargs:
                        emitted.append((event, payload)))
    monkeypatch.setattr(ssh_manager, 'get_output_snapshot', lambda _id: ('', 0))
    monkeypatch.setattr(ssh_manager, 'get_session', lambda _id: {
        'connected': True, 'use_tmux': True, 'auth_type': 'key',
        'via_jump': 'bastion.example' if route == 'jump' else None,
        'jump_host_id': 'saved-bastion' if route == 'jump' else None,
        'socks_proxy_id': 'saved-proxy' if route == 'socks' else None,
        'via_socks': route == 'socks',
        'reconnect_route_known': True,
    })
    with app.app_context():
        user, error = register_user('routing_user', 'socket-password-123')
        assert error is None
        for connected in (True, False):
            db.session.add(SSHSession(
                session_id=f'route-{connected}', user_id=user.id,
                host='private.example', port=22, username='alice',
                connected=connected, is_persistent=True, key_id='target-key',
                auth_type='key', tmux_session_name='persistent',
                jump_host_id='saved-bastion' if route == 'jump' else None,
                via_jump='bastion.example' if route == 'jump' else None,
                socks_proxy_id='saved-proxy' if route == 'socks' else None,
                via_socks=route == 'socks',
                reconnect_route_known=True,
            ))
        db.session.commit()
        with app.test_request_context('/socket.io'):
            socket_events.restore_user_sessions(user.id, 'socket')
    routes = [payload for event, payload in emitted if event in {
        'ssh_session_restored', 'persistent_session_available'}]
    assert len(routes) == 2
    for payload in routes:
        assert payload['jump_host_id'] == ('saved-bastion' if route == 'jump' else None)
        assert payload['via_jump'] == ('bastion.example' if route == 'jump' else None)
        assert payload['socks_proxy_id'] == ('saved-proxy' if route == 'socks' else None)
        assert payload['via_socks'] == (route == 'socks')
        assert payload['reconnect_route_known'] is True
        assert payload['key_id'] == 'target-key'
