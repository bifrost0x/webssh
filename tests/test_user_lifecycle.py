import logging
from types import SimpleNamespace

import pytest

from tests.step_up_helpers import password_step_up_headers


def _create_user(username, password='password123', *, is_admin=False):
    from app.auth import register_user

    user, error = register_user(username, password)
    assert error is None
    user.is_admin = is_admin
    return user


def _login(client, username, password='password123'):
    response = client.post('/login', data={
        'username': username,
        'password': password,
    })
    assert response.status_code == 302


class _FakeSocketServer:
    def __init__(self):
        self.disconnected = []

    def disconnect(self, sid, namespace='/'):
        self.disconnected.append((sid, namespace))


class TestLockedUserRejection:
    def test_locked_user_is_rejected_by_http_and_socket_loaders(self, app):
        with app.app_context():
            from app.auth import load_user, register_socket_session, get_user_from_socket
            from app.models import db

            user = _create_user('lockeduser')
            register_socket_session(user.id, 'locked-sid')
            user.is_locked = True
            db.session.commit()

            assert load_user(str(user.id)) is None
            assert get_user_from_socket('locked-sid') is None

    def test_locked_user_cannot_open_new_socket_connection(self, app, monkeypatch):
        with app.app_context():
            from app.models import db

            user = _create_user('lockedsocket')
            user_id = user.id
            user.is_locked = True
            db.session.commit()

        from flask import request, session
        import app.socket_events as socket_events

        emitted = []
        disconnected = []
        monkeypatch.setattr(
            socket_events,
            'emit',
            lambda event, payload=None, **kwargs: emitted.append((event, payload)),
        )
        monkeypatch.setattr(
            socket_events,
            'disconnect',
            lambda: disconnected.append(True),
        )

        with app.test_request_context('/socket.io'):
            session['_user_id'] = str(user_id)
            request.sid = 'locked-connect-sid'

            assert socket_events.handle_connect() is False

        assert emitted == [('connected', {'status': 'unauthenticated'})]
        assert disconnected == [True]


class TestUserAccessRevocation:
    def test_revocation_cancels_only_target_user_transfers(self, runtime_app):
        with runtime_app.app_context():
            from app.transfer_routes import transfer_manager
            from app.user_lifecycle import revoke_user_access

            target = _create_user('transfer_revoked')
            other = _create_user('transfer_other')
            target_record = transfer_manager.create(
                user_id=target.id,
                source_id='sftp-session:target-session',
                direction='download',
                metadata={},
            )
            other_record = transfer_manager.create(
                user_id=other.id,
                source_id='sftp-session:other-session',
                direction='download',
                metadata={},
            )

            try:
                result = revoke_user_access(target.id)

                assert target_record.cancel_event.is_set()
                assert not other_record.cancel_event.is_set()
                assert result['transfers'] == 1
                assert result['errors'] == []
            finally:
                transfer_manager.cancel_all_for_user(other.id)

    def test_revocation_closes_only_target_user_resources(self, app, monkeypatch):
        with app.app_context():
            from app import ssh_manager
            from app.models import db, SocketSession, SSHSession
            from app.user_lifecycle import revoke_user_access
            import app.user_lifecycle as lifecycle

            target = _create_user('revoked')
            other = _create_user('other')
            db.session.add_all([
                SocketSession(user_id=target.id, socket_sid='target-sid'),
                SocketSession(user_id=other.id, socket_sid='other-sid'),
                SSHSession(session_id='target-ssh', user_id=target.id,
                           host='target.example', port=22, username='root'),
                SSHSession(session_id='other-ssh', user_id=other.id,
                           host='other.example', port=22, username='root'),
            ])
            db.session.commit()

            ssh_manager.sessions.clear()
            ssh_manager.sessions.update({
                'target-ssh': {'user_id': target.id},
                'other-ssh': {'user_id': other.id},
            })
            close_calls = []

            def fake_close_session(session_id, kill_tmux=False):
                # No asserts in here: revoke_user_access wraps close_session in
                # try/except, so a failing assert would be swallowed and surface
                # as a confusing "close failed" error instead. Record the call
                # and assert after revoke_user_access() returns.
                close_calls.append((session_id, kill_tmux))
                ssh_manager.sessions.pop(session_id, None)
                return True

            closed_pool = []

            def fake_close_pool(user_id):
                closed_pool.append(user_id)
                return 2

            monkeypatch.setattr(ssh_manager, 'close_session', fake_close_session)
            monkeypatch.setattr(
                lifecycle.connection_pool.temp_connection_pool,
                'close_all_user_connections',
                fake_close_pool,
            )
            fake_socketio = SimpleNamespace(server=_FakeSocketServer())

            result = revoke_user_access(target.id, fake_socketio)

            # Revocation must kill the remote tmux session so a revoked user
            # does not keep a live shell on the target host.
            assert close_calls == [('target-ssh', True)]
            assert 'other-ssh' in ssh_manager.sessions
            assert closed_pool == [str(target.id)]
            assert fake_socketio.server.disconnected == [('target-sid', '/')]
            assert SocketSession.query.filter_by(user_id=target.id).count() == 0
            assert SocketSession.query.filter_by(user_id=other.id).count() == 1
            assert SSHSession.query.filter_by(user_id=target.id).count() == 0
            assert SSHSession.query.filter_by(user_id=other.id).count() == 1
            assert result == {
                'transfers': 0,
                'sockets': 1,
                'ssh_sessions': 1,
                'pool_connections': 2,
                'smb_sources': 0,
                'errors': [],
            }

            ssh_manager.sessions.clear()

    def test_failing_credential_revocation_still_disconnects_sockets(self, app, monkeypatch):
        with app.app_context():
            from app.auth import register_socket_session
            from app.models import SocketSession
            from app.user_lifecycle import revoke_user_access

            user = _create_user('revokefailure')
            register_socket_session(user.id, 'revoke-sid')

            def broken(_user_id):
                raise OSError('storage unavailable')

            monkeypatch.setitem(app.extensions, 'credentials', SimpleNamespace(revoke=broken))
            fake_socketio = SimpleNamespace(server=_FakeSocketServer())

            result = revoke_user_access(user.id, fake_socketio)

            assert fake_socketio.server.disconnected == [('revoke-sid', '/')]
            assert SocketSession.query.filter_by(user_id=user.id).count() == 0
            assert result['errors'] == ['credentials:storage unavailable']

    def test_admin_lock_revokes_user_access(self, app, client, monkeypatch):
        with app.app_context():
            admin = _create_user('admin', is_admin=True)
            target = _create_user('locktarget')
            target_id = target.id
            assert admin.is_admin

        _login(client, 'admin')
        revoked = []

        import app.user_lifecycle as lifecycle
        monkeypatch.setattr(
            lifecycle,
            'revoke_user_access',
            lambda user_id, socketio_instance=None: revoked.append(user_id),
        )

        response = client.post(
            f'/admin/api/users/{target_id}/lock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:lock'
            )[0],
        )

        assert response.status_code == 200
        assert response.get_json()['user']['is_locked'] is True
        assert revoked == [target_id]

    def test_admin_unlock_does_not_reactivate_pre_lock_browser_session(
        self,
        app,
        client,
        monkeypatch,
    ):
        from flask import g

        with app.app_context():
            from app.models import db

            _create_user('lockadmin', is_admin=True)
            target = _create_user('lockbrowser')
            target_id = target.id
            db.session.commit()

        target_client = app.test_client()
        assert target_client.post('/login', data={
            'username': 'lockbrowser',
            'password': 'password123',
            'remember': 'on',
        }).status_code == 302
        g.pop('_login_user', None)
        _login(client, 'lockadmin')
        g.pop('_login_user', None)

        import app.user_lifecycle as lifecycle
        monkeypatch.setattr(
            lifecycle,
            'revoke_user_access',
            lambda user_id, socketio_instance=None: {'user_id': user_id},
        )

        lock = client.post(
            f'/admin/api/users/{target_id}/lock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:lock'
            )[0],
        )
        assert lock.status_code == 200
        g.pop('_login_user', None)
        unlock = client.post(
            f'/admin/api/users/{target_id}/unlock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:unlock'
            )[0],
        )
        assert unlock.status_code == 200

        g.pop('_login_user', None)
        rejected = target_client.get('/')
        assert rejected.status_code == 302
        assert '/login?next=' in rejected.headers['Location']
        with app.app_context():
            from app.models import AuthenticationSession, User

            target = db.session.get(User, target_id)
            assert target.is_locked is False
            assert target.auth_generation == 1
            assert AuthenticationSession.query.filter_by(
                user_id=target_id
            ).count() == 0

    def test_logout_revokes_current_user_access(self, app, client, monkeypatch):
        with app.app_context():
            user = _create_user('logoutuser')
            user_id = user.id

        _login(client, 'logoutuser')
        revoked = []

        import app.user_lifecycle as lifecycle
        monkeypatch.setattr(
            lifecycle,
            'revoke_user_access',
            lambda user_id, socketio_instance=None, *, kill_tmux=True: revoked.append(
                (user_id, kill_tmux)
            ),
        )

        response = client.post('/logout')

        assert response.status_code == 302
        assert revoked == [(user_id, False)]


class TestSafeUserDeletion:
    def test_failed_admin_delete_cannot_reactivate_old_session_after_unlock(
        self,
        app,
        client,
        monkeypatch,
    ):
        from flask import g

        with app.app_context():
            from app.models import db

            _create_user('delete_failure_admin', is_admin=True)
            target = _create_user('delete_failure_target')
            target_id = target.id
            db.session.commit()

        target_client = app.test_client()
        assert target_client.post('/login', data={
            'username': 'delete_failure_target',
            'password': 'password123',
            'remember': 'on',
        }).status_code == 302
        g.pop('_login_user', None)
        _login(client, 'delete_failure_admin')
        g.pop('_login_user', None)

        import app.user_lifecycle as lifecycle
        monkeypatch.setattr(
            lifecycle,
            'delete_user_account',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError('forced delete failure')
            ),
        )

        failed = client.post(
            f'/admin/api/users/{target_id}/delete',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:delete'
            )[0],
        )
        assert failed.status_code == 500
        g.pop('_login_user', None)
        unlocked = client.post(
            f'/admin/api/users/{target_id}/unlock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:unlock'
            )[0],
        )
        assert unlocked.status_code == 200

        g.pop('_login_user', None)
        rejected = target_client.get('/')
        assert rejected.status_code == 302
        assert '/login?next=' in rejected.headers['Location']
        with app.app_context():
            from app.models import AuthenticationSession, User

            target = db.session.get(User, target_id)
            assert target.is_locked is False
            assert target.auth_generation == 1
            assert AuthenticationSession.query.filter_by(
                user_id=target_id
            ).count() == 0

    def test_deleted_user_data_is_quarantined_and_not_inherited(self, app, client):
        with app.app_context():
            from app.models import db

            admin = _create_user('deleteadmin', is_admin=True)
            target = _create_user('deletetarget')
            target_id = target.id
            target_data_dir = target.get_data_dir()
            (target_data_dir / 'private-marker.txt').write_text(
                'must-not-be-inherited',
                encoding='utf-8',
            )
            assert admin.is_admin

        _login(client, 'deleteadmin')
        response = client.post(
            f'/admin/api/users/{target_id}/delete',
            headers=password_step_up_headers(
                client, 'user.manage', f'{target_id}:delete'
            )[0],
        )

        assert response.status_code == 200
        with app.app_context():
            import config
            from app.auth import register_user
            from app.models import db, User

            assert db.session.get(User, target_id) is None
            assert not target_data_dir.exists()

            quarantined = list(
                (config.DATA_DIR / 'deleted_users').glob(f'user_{target_id}_*')
            )
            assert len(quarantined) == 1
            assert (quarantined[0] / 'private-marker.txt').read_text(
                encoding='utf-8'
            ) == 'must-not-be-inherited'

            replacement, error = register_user('replacement', 'password123')
            assert error is None
            assert replacement.id == target_id
            assert not (replacement.get_data_dir() / 'private-marker.txt').exists()

    def test_failed_database_delete_restores_quarantined_data(
        self, app, monkeypatch
    ):
        with app.app_context():
            from app.models import db, User
            import app.user_lifecycle as lifecycle

            target = _create_user('restoretarget')
            target_id = target.id
            target.is_locked = True
            target_data_dir = target.get_data_dir()
            marker = target_data_dir / 'restore-marker.txt'
            marker.write_text('restore-me', encoding='utf-8')
            db.session.commit()

            monkeypatch.setattr(
                lifecycle,
                'revoke_user_access',
                lambda user_id, socketio_instance=None: None,
            )
            monkeypatch.setattr(
                db.session,
                'commit',
                lambda: (_ for _ in ()).throw(RuntimeError('forced commit failure')),
            )

            with pytest.raises(RuntimeError, match='forced commit failure'):
                lifecycle.delete_user_account(target, SimpleNamespace(server=None))

            assert db.session.get(User, target_id) is not None
            assert db.session.get(User, target_id).is_locked is True
            assert marker.read_text(encoding='utf-8') == 'restore-me'


class TestPersistentSessionsSurviveSignOut:
    """Logout only disconnects; password change, lock and deletion end tmux work."""

    def _seed_sessions(self, app, monkeypatch, username):
        from app import ssh_manager
        from app.models import SSHSession, db

        with app.app_context():
            user = _create_user(username)
            user_id = user.id
            for session_id, persistent in (('tmux-ssh', True), ('plain-ssh', False)):
                db.session.add(SSHSession(
                    session_id=session_id, user_id=user_id, host='target.example',
                    port=22, username='root', connected=True,
                    is_persistent=persistent,
                    tmux_session_name='webssh_root_target_22_abcd' if persistent else None,
                ))
            db.session.commit()

        monkeypatch.setattr(ssh_manager, 'sessions', {
            'tmux-ssh': {'user_id': user_id, 'use_tmux': True},
            'plain-ssh': {'user_id': user_id},
        })
        close_calls = []

        def fake_close_session(session_id, kill_tmux=False):
            close_calls.append((session_id, kill_tmux))
            ssh_manager.sessions.pop(session_id, None)
            return True

        monkeypatch.setattr(ssh_manager, 'close_session', fake_close_session)
        return user_id, close_calls

    def _remaining_rows(self, app, user_id):
        from app.models import SSHSession

        with app.app_context():
            return sorted(
                (row.session_id, row.connected)
                for row in SSHSession.query.filter_by(user_id=user_id)
            )

    def test_logout_detaches_without_killing_persistent_tmux(self, app, client, monkeypatch):
        user_id, close_calls = self._seed_sessions(app, monkeypatch, 'tmuxlogout')
        _login(client, 'tmuxlogout')

        assert client.post('/logout').status_code == 302

        assert sorted(close_calls) == [('plain-ssh', False), ('tmux-ssh', False)]
        assert self._remaining_rows(app, user_id) == [('tmux-ssh', False)]

    def test_password_change_still_kills_persistent_tmux(self, app, client, monkeypatch):
        user_id, close_calls = self._seed_sessions(app, monkeypatch, 'tmuxpassword')
        _login(client, 'tmuxpassword')

        response = client.post('/change-password', data={
            'current_password': 'password123',
            'new_password': 'password456',
            'confirm_password': 'password456',
        })

        assert response.status_code == 302
        assert sorted(close_calls) == [('plain-ssh', True), ('tmux-ssh', True)]
        assert self._remaining_rows(app, user_id) == []

    def test_admin_lock_still_kills_persistent_tmux(self, app, client, monkeypatch):
        user_id, close_calls = self._seed_sessions(app, monkeypatch, 'tmuxlocked')
        with app.app_context():
            from app.models import db

            _create_user('tmuxlockadmin', is_admin=True)
            db.session.commit()
        _login(client, 'tmuxlockadmin')

        response = client.post(
            f'/admin/api/users/{user_id}/lock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{user_id}:lock'
            )[0],
        )

        assert response.status_code == 200
        assert sorted(close_calls) == [('plain-ssh', True), ('tmux-ssh', True)]
        assert self._remaining_rows(app, user_id) == []

    def test_admin_lock_audits_detached_tmux_it_cannot_end(
        self, app, client, monkeypatch, caplog,
    ):
        user_id, close_calls = self._seed_sessions(app, monkeypatch, 'tmuxdetached')
        with app.app_context():
            from app.models import SSHSession, db

            _create_user('tmuxdetachadmin', is_admin=True)
            db.session.add(SSHSession(
                session_id='detached-ssh', user_id=user_id, host='old.example',
                port=2222, username='deploy', connected=False, is_persistent=True,
                tmux_session_name='webssh_deploy_old_2222_beef', key_id='key-1',
            ))
            db.session.commit()
        _login(client, 'tmuxdetachadmin')
        caplog.set_level(logging.INFO, logger='security_audit')

        response = client.post(
            f'/admin/api/users/{user_id}/lock',
            headers=password_step_up_headers(
                client, 'user.manage', f'{user_id}:lock'
            )[0],
        )

        assert response.status_code == 200
        assert sorted(close_calls) == [('plain-ssh', True), ('tmux-ssh', True)]
        assert self._remaining_rows(app, user_id) == []
        warnings = [
            record.getMessage() for record in caplog.records
            if record.name == 'security_audit'
            and record.levelno == logging.WARNING
            and record.getMessage().startswith('TMUX_SESSION_NOT_ENDED')
        ]
        assert len(warnings) == 1
        for detail in (
            'host=old.example', 'port=2222', 'ssh_user=deploy',
            'tmux_session=webssh_deploy_old_2222_beef', 'reason=detached',
            f'user_id={user_id}',
        ):
            assert detail in warnings[0]
        assert 'key-1' not in warnings[0]
