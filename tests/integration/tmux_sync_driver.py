import re, tempfile, hashlib
import base64, json, os, pty, select, shlex, subprocess, sys, time, uuid
from pathlib import Path
root = Path(__file__).resolve().parents[2]
# The directory probe of the server (internal/files/sftp/directory.go),
# read from its source so the test follows the server's own script.
_go = (root / 'internal/files/sftp/directory.go').read_text()
_PROBE = re.search(r'(?s)const directoryProbe = `(.*?)`', _go)[1]
_TMUX = re.search(r'(?s)const tmuxShell = `(.*?)`', _go)[1]


def probe_command(session):
    select = _TMUX.replace('__TMUX_TARGET__', shlex.quote('=' + session['tmux_session_name'] + ':'), 1)
    return 'exec sh -c ' + shlex.quote(_PROBE.replace('__DIRECTORY_SELECT__', select, 1))


def parse_directory(payload):
    """The fields of the answer, as ParseDirectory reads them."""
    parts = payload.decode('utf-8', errors='strict').split('\0')
    if len(parts) not in {6, 7, 8} or parts[0] != 'webssh-directory' or parts[-1]:
        raise ValueError('Invalid directory response')
    pid, ready, shell, path = parts[1:5]
    if not pid.isdigit() or ready not in {'0', '1'} or not path.startswith('/'):
        raise ValueError('Unsupported directory')
    result = {'path': path, 'shell_ready': ready == '1', 'shell_id': pid, 'shell': shell}
    if len(parts) >= 7 and parts[5]:
        result['bracketed_paste'] = parts[5] == '1'
    if len(parts) == 8 and shell == 'bash':
        marker = re.fullmatch(r'([0-9]+):([1-9][0-9]{0,14}):([pcb])', parts[6])
        if parts[6] and not marker:
            raise ValueError('Invalid prompt marker')
        if marker and marker[1] == pid:
            result['prompt'] = {'generation': int(marker[2]), 'phase': marker[3]}
    return result


ns = {'probe_command': probe_command, 'parse_directory': parse_directory}
# Unsupported/protected configurations must be rejected before contacting tmux.
activation = shlex.quote(str(root / 'static/shell/tmux-sync.bash'))
for protection in ('readonly PS1', 'export PS1', 'shopt -u promptvars',
                   '__webssh_sync_v1() { printf KEEP_FUNCTION; }'):
    script = ('PS1=KEEP_PROMPT; TMUX=unused; TMUX_PANE=%0; ' + protection
              + '; source ' + activation
              + '; [[ $PS1 == KEEP_PROMPT ]] || exit 1; '
              + '[[ $(declare -p PS1) != *webssh* ]] || exit 1')
    protected = subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                               capture_output=True, check=True, timeout=5)
    assert not protected.stderr, protected.stderr
    assert b'Folder sync was not changed' in protected.stdout
name = 'webssh_live_' + uuid.uuid4().hex
def tmux(*args):
    return subprocess.run(['tmux', '-L', name, *args], capture_output=True, check=True, timeout=5)
def capture():
    output = bytearray()
    deadline = time.monotonic() + .35
    while time.monotonic() < deadline:
        if select.select([master], [], [], .05)[0]:
            output.extend(os.read(master, 65536))
    return base64.b64encode(output).decode()
def attach():
    child, master = pty.fork()
    if child == 0:
        os.environ['TERM'] = 'xterm-256color'
        os.execvp('tmux', ['tmux', '-L', name, 'attach', '-t', 'probe'])
    return child, master
fixture = tempfile.TemporaryDirectory(prefix='webssh-tmux-test-')
rc = Path(fixture.name) / '.bashrc'
rc.write_text("PROMPT_COMMAND=('__saved_status=$?' ':')\nPS1='CUSTOM(${__saved_status}) \\w $ '\nPS2='CONT> '\nPS0='EXEC: '\n__original_ps1=$PS1; __original_ps2=$PS2; __original_ps0=$PS0; __original_pc=$(declare -p PROMPT_COMMAND)\n")
special_path = Path(fixture.name) / "über O'Brien $HOME"
special_path.mkdir()
original_rc = hashlib.sha256(rc.read_bytes()).digest()
try:
    tmux('-f', '/dev/null', 'new-session', '-d', '-s', 'probe', 'bash --noprofile --rcfile ' + shlex.quote(str(rc)))
    tmux('new-session', '-d', '-s', 'unrelated', 'bash --noprofile --norc')
    sentinel = tmux('display-message', '-p', '-t', 'unrelated', '#{pane_pid}').stdout
    original_pid = tmux('display-message', '-p', '-t', 'probe', '#{pane_pid}').stdout
    sibling_options = tmux('show-options', '-p', '-t', 'unrelated').stdout
    global_options = tmux('show-options', '-g').stdout
    window_options = tmux('show-options', '-gw').stdout
    child, master = attach()
    for line in sys.stdin:
        request = json.loads(line)
        if request.get('reattach'):
            tmux('detach-client', '-s', 'probe')
            os.waitpid(child, 0)
            os.close(master)
            child, master = attach()
        if request.get('activate'):
            script = (root / 'static/shell/tmux-sync.bash').read_bytes().decode('utf-8').replace('command tmux ', 'command tmux -L ' + name + ' ')
            os.write(master, ('\x1b[200~' + script + '\x1b[201~\r').encode())
        if request.get('input'):
            os.write(master, base64.b64decode(request['input']))
        if request.get('copy'):
            tmux('copy-mode', '-t', 'probe')
        if request.get('cancel_copy'):
            tmux('send-keys', '-t', 'probe', '-X', 'cancel')
        output = capture()
        command = ns['probe_command']({'use_tmux': True, 'tmux_session_name': 'probe'})
        command = command.replace('tmux display-message', 'tmux -L ' + name + ' display-message')
        result = subprocess.run(command, shell=True, capture_output=True, timeout=5)
        directory = ns['parse_directory'](result.stdout) if result.returncode == 0 else None
        if directory:
            directory['tmux'] = True
        assert tmux('show-options', '-p', '-t', 'unrelated').stdout == sibling_options
        assert tmux('show-options', '-g').stdout == global_options
        assert tmux('show-options', '-gw').stdout == window_options
        assert hashlib.sha256(rc.read_bytes()).digest() == original_rc
        assert tmux('display-message', '-p', '-t', 'unrelated', '#{pane_pid}').stdout == sentinel
        assert tmux('display-message', '-p', '-t', 'probe', '#{pane_pid}').stdout == original_pid
        print(json.dumps({'output': output, 'directory': directory, 'special_path': str(special_path)}), flush=True)
finally:
    tmux('kill-server')
    if 'master' in globals():
        os.close(master)
        os.waitpid(child, 0)

    fixture.cleanup()
