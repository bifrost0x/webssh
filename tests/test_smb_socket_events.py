from threading import Event

import pytest


pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def _socket_user(app, username):
    from app.auth import register_socket_session, register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        sid = f'{username}-sid'
        register_socket_session(user.id, sid)
        db.session.commit()
        return user.id, sid


def _payload(**overrides):
    value = {
        'request_id': 'smb-request-1',
        'host': 'nas.example',
        'share': 'Docs',
        'domain': 'DOMAIN',
        'username': 'alice',
        'password': 'Secret-Sentinel-42!',
    }
    value.update(overrides)
    return value


def _call(app, sid, handler, payload):
    from flask import request

    with app.test_request_context('/socket.io'):
        request.sid = sid
        return handler(payload)


class _Handle:
    def __init__(self, cancel_event):
        self.cancel_event = cancel_event

    def cancel(self):
        self.cancel_event.set()
        return True


class _CapturedLifecycle:
    def __init__(self):
        self.jobs = []

    def accepting_work(self):
        return True

    def start_job(self, name, target, **kwargs):
        event = Event()
        handle = _Handle(event)
        self.jobs.append((name, target, event, kwargs))
        return handle


def test_feature_off_stops_before_rate_limit_parser_and_pool(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'smb_disabled')
    emitted = []
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', False)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limiter must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda name, data=None, **_kwargs: emitted.append((name, data)),
    )

    _call(app, sid, socket_events.handle_smb_quick_connect, object())

    assert emitted == [(
        'smb_quick_connect_error',
        {'request_id': '', 'code': 'SMB_DISABLED'},
    )]


def test_success_is_correlated_and_password_never_reaches_response(app, monkeypatch):
    import app.socket_events as socket_events
    from app.file_sources import FileSourceDescriptor, FileSourceKind, make_source_id

    user_id, sid = _socket_user(app, 'smb_success')
    lifecycle = _CapturedLifecycle()
    app.extensions['runtime_lifecycle'] = lifecycle
    descriptor = FileSourceDescriptor(
        source_id=make_source_id(FileSourceKind.SMB_QUICK, 'source1'),
        kind='smb',
        label='Docs on nas.example',
        endpoint='nas.example/Docs',
        protocol='SMB 3.1.1',
        capabilities=(),
        ephemeral=True,
        security={'encrypted': True, 'signed': True, 'secure_negotiate': True},
    )

    class _Pool:
        def create_source(self, **kwargs):
            assert kwargs['password'] == 'Secret-Sentinel-42!'
            return descriptor

        def request_close(self, *_args):
            raise AssertionError('live success must not close')

    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(socket_events, '_smb_pool', lambda: _Pool())
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda name, data=None, **kwargs: emitted.append((name, data, kwargs)),
    )

    _call(app, sid, socket_events.handle_smb_quick_connect, _payload())
    assert len(lifecycle.jobs) == 1
    with app.app_context():
        lifecycle.jobs[0][1](lifecycle.jobs[0][2])

    assert emitted[0][0] == 'smb_quick_connect_success'
    assert emitted[0][1]['request_id'] == 'smb-request-1'
    assert emitted[0][1]['file_source']['source_id'] == descriptor.source_id
    assert 'Secret-Sentinel-42!' not in repr(emitted)
    assert emitted[0][2]['room'] == sid


@pytest.mark.parametrize(
    'code',
    ('PERMISSION_DENIED', 'SHARE_UNAVAILABLE', 'TIMEOUT'),
)
def test_connect_preserves_actionable_share_failure_codes(app, monkeypatch, code):
    import app.socket_events as socket_events
    from app.smb_pool import SMBSourceError

    _user_id, sid = _socket_user(app, f'smb_error_{code.lower()}')
    lifecycle = _CapturedLifecycle()
    app.extensions['runtime_lifecycle'] = lifecycle

    failure = SMBSourceError(code, r'secret \\server\share')
    failure.diagnostic_phase = 'share_access'
    failure.diagnostic_exception_type = 'SMBOSError'
    failure.diagnostic_nt_status = '0xC0000022'

    class _Pool:
        def create_source(self, **_kwargs):
            raise failure

    emitted = []
    logs = []
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(socket_events, '_smb_pool', lambda: _Pool())
    monkeypatch.setattr(
        socket_events,
        '_new_smb_diagnostic_id',
        lambda: 'SMB-A1B2C3D4E5F6',
        raising=False,
    )
    monkeypatch.setattr(
        socket_events,
        'log_warning',
        lambda event, **details: logs.append((event, details)),
    )
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda name, data=None, **kwargs: emitted.append((name, data, kwargs)),
    )

    _call(app, sid, socket_events.handle_smb_quick_connect, _payload())
    with app.app_context():
        lifecycle.jobs[0][1](lifecycle.jobs[0][2])

    assert emitted == [(
        'smb_quick_connect_error',
        {
            'request_id': 'smb-request-1',
            'code': code,
            'diagnostic_id': 'SMB-A1B2C3D4E5F6',
        },
        {'room': sid},
    )]
    assert logs == [(
        'SMB source connection failed',
        {
            'user_id': str(_user_id),
            'host': 'nas.example',
            'share': 'Docs',
            'result_code': code,
            'diagnostic_id': 'SMB-A1B2C3D4E5F6',
            'diagnostic_phase': 'share_access',
            'cause_type': 'SMBOSError',
            'nt_status': '0xC0000022',
            'exception_type': 'SMBSourceError',
        },
    )]
    assert 'secret' not in repr(emitted)
    assert 'server' not in repr(emitted)
    assert 'secret' not in repr(logs)
    assert 'server' not in repr(logs)


def test_cancelled_connect_closes_late_success(app, monkeypatch):
    import app.socket_events as socket_events
    from app.file_sources import FileSourceDescriptor, FileSourceKind, make_source_id

    _user_id, sid = _socket_user(app, 'smb_cancelled')
    lifecycle = _CapturedLifecycle()
    app.extensions['runtime_lifecycle'] = lifecycle
    descriptor = FileSourceDescriptor(
        source_id=make_source_id(FileSourceKind.SMB_QUICK, 'late'),
        kind='smb',
        label='Docs on nas.example',
        endpoint='nas.example/Docs',
        protocol='SMB 3.1.1',
        capabilities=(),
        ephemeral=True,
        security={},
    )
    closed = []

    class _Pool:
        def create_source(self, **_kwargs):
            return descriptor

        def request_close(self, source_id, user_id):
            closed.append((source_id, str(user_id)))
            return 'closed'

    pool = _Pool()
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(socket_events, '_smb_pool', lambda: pool)
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda name, data=None, **kwargs: emitted.append((name, data, kwargs)),
    )

    _call(app, sid, socket_events.handle_smb_quick_connect, _payload())
    _call(
        app,
        sid,
        socket_events.handle_smb_quick_connect_cancel,
        {'request_id': 'smb-request-1'},
    )
    # Simulate a blocking library call that returned despite cancellation.
    lifecycle.jobs[0][2].clear()
    with app.app_context():
        lifecycle.jobs[0][1](lifecycle.jobs[0][2])

    assert closed == [(descriptor.source_id, str(_user_id))]
    assert not any(name == 'smb_quick_connect_success' for name, _data, _kwargs in emitted)


def test_invalid_input_stops_before_job_and_never_echoes_password(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'smb_invalid')
    lifecycle = _CapturedLifecycle()
    app.extensions['runtime_lifecycle'] = lifecycle
    emitted = []
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda name, data=None, **_kwargs: emitted.append((name, data)),
    )

    _call(app, sid, socket_events.handle_smb_quick_connect, _payload(share='C$'))

    assert lifecycle.jobs == []
    assert emitted == [(
        'smb_quick_connect_error',
        {'request_id': 'smb-request-1', 'code': 'INVALID_REQUEST'},
    )]
    assert 'Secret-Sentinel-42!' not in repr(emitted)


def test_owned_smb_source_disconnect_uses_full_source_id(app, monkeypatch):
    import app.socket_events as socket_events

    user_id, sid = _socket_user(app, 'smb_disconnect')
    calls = []
    emitted = []

    class _Pool:
        def request_close(self, source_id, owner_id):
            calls.append((source_id, str(owner_id)))
            return 'closed'

    monkeypatch.setattr(socket_events, '_smb_pool', lambda: _Pool())
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda name, data=None, **_kwargs: emitted.append((name, data)),
    )

    _call(
        app,
        sid,
        socket_events.handle_file_source_disconnect,
        {'source_id': 'smb-quick:owned'},
    )

    assert calls == [('smb-quick:owned', str(user_id))]
    assert emitted == [(
        'file_source_disconnect_success',
        {'source_id': 'smb-quick:owned'},
    )]
