from types import SimpleNamespace
from threading import Lock

import pytest

from app import session_directory as directory, ssh_manager, socket_events


@pytest.mark.parametrize('path', ['/tmp', "/tmp/O'Brien $HOME", '/tmp/über uns'])
def test_parse_real_directory(path):
    result = directory.parse_directory(
        f'webssh-directory\0{42}\0{1}\0bash\0{path}\0'.encode()
    )
    assert result == {
        'path': path,
        'shell_ready': True,
        'shell_id': '42',
        'shell': 'bash',
    }


@pytest.mark.parametrize('flag,expected', [('0', False), ('1', True)])
def test_parse_tmux_pane_prompt_mode(flag, expected):
    result = directory.parse_directory(f'webssh-directory\0{42}\0{1}\0bash\0/tmp\0{flag}\0'.encode())
    assert result['bracketed_paste'] is expected


@pytest.mark.parametrize('flag', ['', '2', 'true', '1\0extra'])
def test_reject_invalid_tmux_pane_prompt_mode(flag):
    with pytest.raises(ValueError):
        directory.parse_directory(f'webssh-directory\0{42}\0{1}\0bash\0/tmp\0{flag}\0'.encode())


@pytest.mark.parametrize('payload', [
    b'garbage', b'webssh-directory\x0042\x002\x00bash\x00/tmp\x00',
    b'webssh-directory\x000\x001\x00bash\x00/tmp\x00',
    b'webssh-directory\x0042\x001\x00csh\x00/tmp\x00',
    b'webssh-directory\x0042\x001\x00bash\x00relative\x00',
    b'webssh-directory\x0042\x001\x00bash\x00/tmp\nwhoami\x00',
    b'webssh-directory\x0042\x001\x00bash\x00/tmp\x1b\x00',
    b'webssh-directory\x0042\x001\x00bash\x00/\xff\x00',
])
def test_reject_unusable_remote_directory(payload):
    with pytest.raises((ValueError, UnicodeError)):
        directory.parse_directory(payload)


def test_exec_is_explicit_and_tmux_target_is_quoted():
    import shlex
    command = directory.probe_command({'use_tmux': True, 'tmux_session_name': "name'; touch /tmp/nope"})
    script = shlex.split(command)[3]
    assert "tmux display-message -p -t '=name'\"'\"'; touch /tmp/nope:'" in script
    assert 'pane_in_mode' in script
    assert 'alternate_on' in script
    assert 'bracket_paste_flag' in script


class Channel:
    def __init__(self, payload=b'webssh-directory\x0042\x001\x00bash\x00/tmp\x00'):
        self.payload = payload
        self.closed = False
    def recv_ready(self): return bool(self.payload)
    def recv(self, size):
        result, self.payload = self.payload[:size], self.payload[size:]
        return result
    def exit_status_ready(self): return True
    def recv_exit_status(self): return 0
    def close(self): self.closed = True


def setup_session(monkeypatch, channel):
    transport = SimpleNamespace(is_active=lambda: True)
    session = {'connected': True, 'client': SimpleNamespace(get_transport=lambda: transport)}
    monkeypatch.setattr(ssh_manager, 'sessions', {'a': session})
    monkeypatch.setattr(ssh_manager, '_open_exec_channel', lambda *args, **kw: channel)
    return session


def test_probe_closes_channel_and_releases_lock(monkeypatch):
    channel = Channel(); session = setup_session(monkeypatch, channel)
    result, reason = directory.collect_directory('a')
    assert result['path'] == '/tmp' and reason is None
    assert channel.closed and not session['directory_probe_lock'].locked()


def test_tmux_probe_marks_only_a_successfully_checked_pane(monkeypatch):
    channel = Channel()
    session = setup_session(monkeypatch, channel)
    session.update(use_tmux=True, tmux_session_name='workspace')
    result, reason = directory.collect_directory('a')
    assert reason is None and result['tmux'] is True

    channel = Channel()
    channel.recv_exit_status = lambda: 1
    setup_session(monkeypatch, channel).update(use_tmux=True, tmux_session_name='workspace')
    assert directory.collect_directory('a') == (None, 'unsupported')


def test_probe_bounds_output_and_closes_channel(monkeypatch):
    channel = Channel(b'x' * 9000); session = setup_session(monkeypatch, channel)
    assert directory.collect_directory('a') == (None, 'unsupported')
    assert channel.closed and not session['directory_probe_lock'].locked()


def test_concurrent_probe_is_rejected(monkeypatch):
    session = setup_session(monkeypatch, Channel())
    lock = Lock(); lock.acquire(); session['directory_probe_lock'] = lock
    assert directory.collect_directory('a') == (None, 'busy')
    lock.release()


@pytest.mark.parametrize('owned,limited,valid', [(False,False,True),(True,True,True),(True,False,False)])
def test_socket_rejects_without_collecting(monkeypatch, owned, limited, valid):
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *args: owned)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *args: limited)
    def fail(*args): raise AssertionError('must not collect')
    monkeypatch.setattr(directory, 'collect_directory', fail)
    result = socket_events.handle_request_session_directory.__wrapped__(
        {'session_id': 'a' if valid else ['bad']}, current_user=SimpleNamespace(id=7))
    assert result['success'] is False


def test_socket_rate_limits_before_ownership_lookup(monkeypatch):
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *args: True,
    )
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *args: pytest.fail('ownership lookup must not follow rate limit'),
    )
    monkeypatch.setattr(
        directory,
        'collect_directory',
        lambda *args: pytest.fail('collection must not follow rate limit'),
    )

    result = socket_events.handle_request_session_directory.__wrapped__(
        {'session_id': 'unknown-session'},
        current_user=SimpleNamespace(id=7),
    )

    assert result == {'success': False, 'reason': 'busy'}


def test_socket_rate_limit_allows_every_admitted_workspace(monkeypatch):
    captured = {}
    monkeypatch.setattr(socket_events.config, 'MAX_SOCKET_CONNECTIONS_PER_USER', 3)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda user_id, endpoint, limit: captured.update(
            user_id=user_id,
            endpoint=endpoint,
            limit=limit,
        ) or False,
    )
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *args: True)
    monkeypatch.setattr(
        directory,
        'collect_directory',
        lambda *args: ({
            'path': '/tmp',
            'shell_ready': True,
            'shell_id': '42',
            'shell': 'bash',
        }, None),
    )

    result = socket_events.handle_request_session_directory.__wrapped__(
        {'session_id': 'a'},
        current_user=SimpleNamespace(id=7),
    )

    assert result['success'] is True
    assert captured == {
        'user_id': 7,
        'endpoint': 'session_directory',
        'limit': '180 per minute',
    }


def test_socket_returns_owned_directory(monkeypatch):
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *args: True)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *args: False)
    value = {
        'path': '/tmp', 'shell_ready': True, 'shell_id': '42', 'shell': 'bash',
    }
    monkeypatch.setattr(directory, 'collect_directory', lambda sid: (value, None))
    result = socket_events.handle_request_session_directory.__wrapped__(
        {'session_id': 'a'}, current_user=SimpleNamespace(id=7))
    assert result == {'success': True, 'directory': value, 'reason': None}


def test_probe_reads_actual_pty_shell_and_busy_nested_shell(tmp_path):
    """Exercise the real Linux process relationship, with no SSH credentials."""
    import shutil
    import sys

    if sys.platform != 'linux' or not shutil.which('bash') or not shutil.which('ps'):
        pytest.skip('Linux PTY and bash required')

    import fcntl
    import os
    import pty
    import select
    import subprocess
    import termios
    import time

    master, slave = pty.openpty()
    def setup_tty():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    shell = subprocess.Popen(
        ['bash', '--noprofile', '--norc', '-i'], stdin=slave,
        stdout=slave, stderr=slave, preexec_fn=setup_tty,
        env={**os.environ, 'PS1': 'TEST> ', 'HISTFILE': '/dev/null'},
    )
    os.close(slave)
    def wait_prompt():
        output = b''
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                output += os.read(master, 8192)
                if b'TEST> ' in output: return
        raise AssertionError('PTY prompt not received')
    def probe():
        result = subprocess.run(directory.probe_command({}), shell=True,
                                capture_output=True, timeout=3, check=True)
        return directory.parse_directory(result.stdout)
    try:
        wait_prompt()
        os.write(master, b'bash --noprofile --norc -i\n')
        wait_prompt()
        import shlex
        path = str(tmp_path / "O'Brien $HOME")
        os.mkdir(path)
        os.write(master, ('cd -- ' + shlex.quote(path) + '\n').encode())
        wait_prompt()
        assert probe()['path'] == path
        assert probe()['shell_ready'] is True
        os.write(master, b'sleep 10\n')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = probe()
            if not result['shell_ready']: break
            time.sleep(.02)
        assert result['shell_ready'] is False
        assert result['path'] == path
        os.write(master, b'\x03')
        wait_prompt()
        assert probe()['shell_ready'] is True
    finally:
        os.close(master)
        shell.wait(timeout=3)


def test_timeout_closes_probe_channel(monkeypatch):
    channel = Channel(b'')
    channel.exit_status_ready = lambda: False
    session = setup_session(monkeypatch, channel)
    assert directory.collect_directory('a', timeout=0) == (None, 'unavailable')
    assert channel.closed and not session['directory_probe_lock'].locked()


def test_disconnected_session_does_not_open_channel(monkeypatch):
    session = setup_session(monkeypatch, Channel())
    session['connected'] = False
    assert directory.collect_directory('a') == (None, 'disconnected')
    assert directory.collect_directory('missing') == (None, 'disconnected')


@pytest.mark.parametrize('phase', ['p', 'c', 'b'])
def test_parse_prompt_integration(phase):
    result = directory.parse_directory(f'webssh-directory\0{42}\0{1}\0bash\0/tmp\0\0{42}:7:{phase}\0'.encode())
    assert result['prompt'] == {'generation': 7, 'phase': phase}
    assert 'bracketed_paste' not in result


@pytest.mark.parametrize('marker', ['43:7:p', '42:0:p', '42:7:x', '42:99999999999999999:p', 'invalid'])
def test_untrusted_prompt_marker_cannot_confirm_readiness(marker):
    payload = f'webssh-directory\0{42}\0{1}\0bash\0/tmp\0\0{marker}\0'.encode()
    if marker == '43:7:p':
        assert 'prompt' not in directory.parse_directory(payload)
    else:
        with pytest.raises(ValueError):
            directory.parse_directory(payload)
