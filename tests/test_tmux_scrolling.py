"""Exercise session-local scrolling against an owned disposable tmux server."""

import os
import select
import shlex
import shutil
import struct
import subprocess
import sys
import time

import pytest

from app.ssh_manager import _tmux_session_command

if sys.platform == 'linux':
    import fcntl
    import pty
    import termios


pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or not shutil.which('tmux'),
    reason='Requires local Linux tmux',
)


@pytest.fixture
def tmux_lab(tmp_path):
    command = ['tmux', '-S', str(tmp_path / 'scroll.sock'), '-f', '/dev/null']
    clients = []

    def run(*args):
        return subprocess.check_output([*command, *args], stderr=subprocess.PIPE, timeout=5).decode().strip()

    def drain(fd, seconds=0.1):
        data = b''
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.02)[0]:
                try:
                    data += os.read(fd, 65536)
                except OSError:
                    break
        return data

    def start(name, reconnect=False):
        shell_command = _tmux_session_command(shlex.join(command), name, reconnect=reconnect)
        fd, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        try:
            process = subprocess.Popen(
                ['script', '-q', '-e', '-c', shell_command, '/dev/null'],
                stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                env={**os.environ, 'TERM': 'xterm-256color'},
            )
        except Exception:
            os.close(fd)
            raise
        finally:
            os.close(slave)
        clients.append((process, fd))
        return fd

    def until(predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            for _, fd in clients:
                drain(fd, 0.02)
            try:
                if predicate():
                    return
            except subprocess.CalledProcessError:
                pass
        pytest.fail('Disposable tmux did not reach the expected state')

    run('new-session', '-d', '-s', 'webssh_owned_neighbor', '-x', '80', '-y', '24')
    try:
        yield run, start, drain, until
    finally:
        subprocess.run([*command, 'kill-server'], capture_output=True, timeout=5)
        for process, fd in clients:
            os.close(fd)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.mark.parametrize('reconnect', [False, True])
def test_tmux_mouse_is_local_and_existing_process_history_and_policy_survive(tmux_lab, reconnect):
    run, start, drain, until = tmux_lab
    run('set-option', '-g', 'mouse', 'off')
    run('set-option', '-s', 'set-clipboard', 'external')
    run('set-option', '-t', '=webssh_owned_neighbor:', 'mouse', 'off')
    run('bind-key', '-T', 'root', 'F12', 'display-message', 'keep-custom-binding')
    global_options = run('show-options', '-g')
    server_options = run('show-options', '-s')
    bindings = run('list-keys')
    before = None
    if reconnect:
        run('new-session', '-d', '-s', 'webssh_owned', '-x', '80', '-y', '24')
        run('set-option', '-t', '=webssh_owned:', 'mouse', 'off')
        run('send-keys', '-t', '=webssh_owned:', 'seq 1 200', 'Enter')
        until(lambda: int(run('display-message', '-p', '-t', '=webssh_owned:', '#{history_size}')) > 100)
        before = (
            run('display-message', '-p', '-t', '=webssh_owned:', '#{pane_pid}'),
            run('capture-pane', '-p', '-t', '=webssh_owned:', '-S', '-'),
        )
    fd = start('webssh_owned', reconnect)
    until(lambda: run('show-options', '-v', '-t', '=webssh_owned:', 'mouse') == 'on')
    if before:
        assert run('display-message', '-p', '-t', '=webssh_owned:', '#{pane_pid}') == before[0]
        assert run('capture-pane', '-p', '-t', '=webssh_owned:', '-S', '-') == before[1]
    else:
        run('send-keys', '-t', '=webssh_owned:', 'seq 1 200', 'Enter')
        until(lambda: int(run('display-message', '-p', '-t', '=webssh_owned:', '#{history_size}')) > 100)
    assert run('show-options', '-g') == global_options
    assert run('show-options', '-s') == server_options
    assert run('list-keys') == bindings
    assert run('show-options', '-v', '-t', '=webssh_owned_neighbor:', 'mouse') == 'off'
    os.write(fd, b'\x1b[<64;5;5M' * 3)
    until(lambda: run('display-message', '-p', '-t', '=webssh_owned:', '#{pane_in_mode}') == '1')
    assert int(run('display-message', '-p', '-t', '=webssh_owned:', '#{scroll_position}')) > 0
    run('send-keys', '-t', '=webssh_owned:', '-X', 'cancel')
    assert run('display-message', '-p', '-t', '=webssh_owned:', '#{pane_in_mode}') == '0'


def test_tmux_session_name_cannot_execute_shell_substitution(tmux_lab, tmp_path):
    run, start, _, until = tmux_lab
    marker = tmp_path / 'not-created'
    name = f'webssh_$(touch {marker})'
    start(name)
    until(lambda: run('show-options', '-v', '-t', '=' + name + ':', 'mouse') == 'on')
    assert not marker.exists()
    assert run('show-options', '-gv', 'mouse') == 'off'


def test_tmux_forwards_wheel_to_a_mouse_aware_full_screen_application(tmux_lab, tmp_path):
    run, start, _, until = tmux_lab
    output = tmp_path / 'wheel-input'
    application = tmp_path / 'mouse_application.py'
    application.write_text(
        'import os, sys, tty, termios\n'
        'from pathlib import Path\n'
        'original = termios.tcgetattr(0)\n'
        'try:\n'
        '    tty.setraw(0)\n'
        '    os.write(1, b"\\x1b[?1049h\\x1b[?1000h\\x1b[?1006h")\n'
        '    Path(sys.argv[1]).write_bytes(os.read(0, 1024))\n'
        'finally:\n'
        '    os.write(1, b"\\x1b[?1000l\\x1b[?1006l\\x1b[?1049l")\n'
        '    termios.tcsetattr(0, termios.TCSANOW, original)\n',
        encoding='utf-8',
    )
    fd = start('webssh_owned')
    until(lambda: run('show-options', '-v', '-t', '=webssh_owned:', 'mouse') == 'on')
    run('send-keys', '-t', '=webssh_owned:', shlex.join([sys.executable, str(application), str(output)]), 'Enter')
    until(lambda: run('display-message', '-p', '-t', '=webssh_owned:', '#{mouse_any_flag}') == '1')
    os.write(fd, b'\x1b[<64;5;5M')
    until(lambda: output.exists() and output.read_bytes().startswith(b'\x1b[<64;'))
    assert run('display-message', '-p', '-t', '=webssh_owned:', '#{pane_in_mode}') == '0'
