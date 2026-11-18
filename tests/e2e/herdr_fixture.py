"""Herdr session fixture: sockets, ownership, settings and parsing stay real.

Only the SSH transport is replaced. It answers the snapshot command with the
recorded snapshot of the tested Herdr release plus one hostile agent, and it
counts every exec channel, so a test can prove that no command ran.
"""
import json
import time
import uuid
from pathlib import Path

from flask_login import current_user

_RECORDED = Path(__file__).resolve().parents[1] / 'fixtures' / 'herdr_snapshot.json'


def _snapshot():
    document = json.loads(_RECORDED.read_text(encoding='utf-8'))
    document['result']['snapshot']['agents'].append({
        'agent': 'builder',
        'agent_status': 'working',
        'name': '<img src=x onerror="window.__herdrInjected=1">',
        'cwd': '/srv/"><script>window.__herdrInjected=2</script>',
        'pane_id': 'w1:p9',
    })
    return json.dumps(document).encode('utf-8') + b'\n'


def register_herdr_fixture(socketio):
    from app import herdr, profile_manager, ssh_manager
    from app.models import SSHSession, db

    owners = {}
    exec_counts = {}
    payload = _snapshot()

    class ExecChannel:
        def __init__(self, session_id):
            self.session_id = session_id
            self.output = b''

        def settimeout(self, _timeout):
            pass

        def exec_command(self, command):
            if command != herdr.SNAPSHOT_COMMAND:
                raise RuntimeError('Unexpected command on the Herdr fixture')
            exec_counts[self.session_id] = exec_counts.get(self.session_id, 0) + 1
            self.output = payload

        def recv_ready(self):
            return bool(self.output)

        def recv(self, size):
            chunk, self.output = self.output[:size], self.output[size:]
            return chunk

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return not self.output

        def recv_exit_status(self):
            return 0

        def close(self):
            pass

    class Transport:
        def __init__(self, session_id):
            self.session_id = session_id

        def is_active(self):
            return True

        def open_session(self, timeout=None):
            return ExecChannel(self.session_id)

    class Client:
        def __init__(self, session_id):
            self.transport = Transport(session_id)

        def get_transport(self):
            return self.transport

    class ShellChannel:
        def resize_pty(self, **_kwargs):
            pass

        def close(self):
            pass

    def clear(user_id):
        for session_id, owner in list(owners.items()):
            if owner != user_id:
                continue
            with ssh_manager.sessions_lock:
                ssh_manager.sessions.pop(session_id, None)
            SSHSession.query.filter_by(session_id=session_id, user_id=owner).delete()
            del owners[session_id]
            exec_counts.pop(session_id, None)
        db.session.commit()

    @socketio.on('e2e_herdr_sessions')
    def seed(data):
        if not current_user.is_authenticated or not isinstance(data, dict):
            return {'ok': False}
        profile_ids = data.get('profile_ids', [])
        if not isinstance(profile_ids, list) or len(profile_ids) > 12:
            return {'ok': False}
        clear(current_user.id)
        ids = []
        for profile_id in profile_ids:
            profile = profile_manager.get_profile(current_user.id, profile_id) if isinstance(profile_id, str) else None
            if not isinstance(profile, dict):
                return {'ok': False}
            session_id = str(uuid.uuid4())
            owners[session_id] = current_user.id
            with ssh_manager.sessions_lock:
                ssh_manager.sessions[session_id] = {
                    'host': profile['host'], 'port': profile['port'], 'username': profile['username'],
                    'connected': True, 'user_id': current_user.id, 'client': Client(session_id),
                    'channel': ShellChannel(), 'last_activity': time.time(),
                    'output_buffer': ['herdr fixture ready\r\n$ '], 'output_sequence': 1,
                    'profile_id': profile_id,
                    # Mirrors the connection rules: only an allowed saved host gets the
                    # overview, and only a host that selects it gets the session mode.
                    'herdr': herdr.overview_allowed(current_user.id, profile_id),
                    'use_herdr': herdr.session_mode_allowed(current_user.id, profile_id),
                }
            db.session.add(SSHSession(session_id=session_id, user_id=current_user.id,
                                      host=profile['host'], port=profile['port'], username=profile['username']))
            ids.append(session_id)
        db.session.commit()
        return {'ok': True, 'session_ids': ids}

    @socketio.on('e2e_herdr_exec_count')
    def count(_data=None):
        if not current_user.is_authenticated:
            return {'ok': False}
        mine = [session_id for session_id, owner in owners.items() if owner == current_user.id]
        return {'ok': True, 'count': sum(exec_counts.get(session_id, 0) for session_id in mine)}
