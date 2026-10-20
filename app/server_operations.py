"""Allowlisted session operations with bounded channels and one-use intents."""

from dataclasses import dataclass
import hashlib
import re
import secrets
import shlex
import threading
import time

from . import ssh_manager

READ_ACTIONS = frozenset({'service.logs', 'container.logs', 'container.inspect', 'process.list', 'process.inspect', 'system.inspect'})
WRITE_ACTIONS = frozenset({
    'service.start', 'service.stop', 'service.restart',
    'container.start', 'container.stop', 'container.restart',
    'process.terminate', 'system.reboot',
})
_UNIT = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,254}\.service')
_CONTAINER = re.compile(r'[0-9a-f]{64}')
_intents = {}
_active = set()
_lock = threading.Lock()
INTENT_TTL = 90
MAX_OUTPUT = 64 * 1024


class OperationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _process_target(target, *, identity=False):
    pid = target.get('pid')
    if type(pid) is not int or not 1 < pid <= 4194304:
        raise OperationError('invalid_target')
    if identity:
        start = target.get('start_time')
        if not isinstance(start, str) or not re.fullmatch(r'[0-9]{1,20}', start):
            raise OperationError('invalid_target')
    return pid


def newest_container_logs(output, error_output):
    """Merge Docker's timestamped streams without reversing continuation lines."""
    records = []
    unstructured = []
    timestamp = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z)\s')
    for stream in (output, error_output):
        current = None
        for line in stream.splitlines():
            match = timestamp.match(line)
            if match:
                key = match.group(1)
                if current is None or current[0] != key:
                    current = (key, [])
                    records.append(current)
                current[1].append(line)
            elif current is not None:
                current[1].append(line)
            else:
                unstructured.append(line)
    ordered = sorted(records, key=lambda record: record[0], reverse=True)
    return '\n'.join(line for _, lines in ordered for line in lines), '\n'.join(unstructured)


def parse_process_list(output):
    """Parse a complete bounded ps snapshot, never silently drop malformed rows."""
    rows = []
    seen = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 4)
        if len(fields) != 5 or not re.fullmatch(r'[0-9]{1,7}', fields[0]):
            raise OperationError('invalid_output')
        pid = int(fields[0])
        if not 1 <= pid <= 4194304 or pid in seen:
            raise OperationError('invalid_output')
        if any(not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value) for value in fields[2:4]):
            raise OperationError('invalid_output')
        seen.add(pid)
        rows.append(dict(pid=pid, user=fields[1], cpu=fields[2],
                         memory=fields[3], command=fields[4]))
    return rows


def build_command(action, target, *, use_sudo=False):
    if not isinstance(action, str) or action not in READ_ACTIONS | WRITE_ACTIONS:
        raise OperationError('invalid_action')
    if not isinstance(target, dict) or type(use_sudo) is not bool:
        raise OperationError('invalid_target')
    if action.startswith('service.'):
        unit = target.get('unit')
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
            raise OperationError('invalid_target')
        if action == 'service.logs':
            command = f'journalctl --no-pager --reverse --lines=100 --output=short-iso --unit={shlex.quote(unit)}'
        else:
            command = f'systemctl {action.split(".")[1]} -- {shlex.quote(unit)}'
    elif action == 'container.inspect':
        name = target.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name):
            raise OperationError('invalid_target')
        template = '{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State.Status}},"image":{{json .Config.Image}}}'
        command = f'docker inspect --type container --format {shlex.quote(template)} -- {shlex.quote(name)}'
    elif action.startswith('container.'):
        container = target.get('container')
        if not isinstance(container, str) or not _CONTAINER.fullmatch(container):
            raise OperationError('invalid_target')
        verb = action.split('.')[1]
        option = '--timestamps --tail 100 ' if verb == 'logs' else ('--time 10 ' if verb in ('stop', 'restart') else '')
        command = f'docker {verb} {option}-- {container}'
    elif action == 'process.list':
        command = 'env LC_ALL=C ps -e -o pid=,user:32=,pcpu=,pmem=,comm= --sort=pid'
    elif action == 'process.inspect':
        pid = _process_target(target)
        script = (
            'import json,os,signal,sys\np=int(sys.argv[1])\nsupported=False\n'
            'if hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"):\n'
            ' try:\n'
            '  fd=os.pidfd_open(p)\n'
            '  try: signal.pidfd_send_signal(fd,0); supported=True\n'
            '  finally: os.close(fd)\n'
            ' except OSError: pass\n'
            's=open("/proc/%d/stat"%p).read()\n'
            'print(json.dumps({"pid":p,"start_time":s[s.rfind(")")+2:].split()[19],'
            '"command":open("/proc/%d/cmdline"%p,"rb").read(8192).replace(b"\\0",b" ").decode("utf-8","replace"),'
            '"pidfd_supported":supported}))'
        )
        command = f'python3 -c {shlex.quote(script)} {pid}'
    elif action == 'process.terminate':
        pid = _process_target(target, identity=True)
        script = (
            'import os,signal,sys\n'
            'if not hasattr(os,"pidfd_open") or not hasattr(signal,"pidfd_send_signal"): sys.exit(78)\n'
            'p=int(sys.argv[1]); fd=os.pidfd_open(p)\n'
            'try:\n'
            ' s=open("/proc/%d/stat"%p).read()\n'
            ' if s[s.rfind(")")+2:].split()[19]!=sys.argv[2]: sys.exit(75)\n'
            ' signal.pidfd_send_signal(fd,signal.SIGTERM)\n'
            'finally: os.close(fd)\n'
        )
        command = f'python3 -c {shlex.quote(script)} {pid} {target["start_time"]}'
    elif action == 'system.reboot':
        command = 'systemctl reboot'
    else:
        command = 'uname -a; uptime; df -hP; free -m'
        if use_sudo:
            command = f'sh -c {shlex.quote(command)}'
    return f'sudo -n -- {command}' if use_sudo else command


def owned_session(session_id, user_id):
    if not isinstance(session_id, str) or len(session_id) > 128:
        raise OperationError('unavailable')
    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(session_id)
        if not session or not session.get('connected') or str(session.get('user_id')) != str(user_id):
            raise OperationError('unavailable')
        return session


def _same_session(session_id, user_id, expected):
    try:
        return owned_session(session_id, user_id) is expected
    except OperationError:
        return False


def _display(value):
    return ''.join(character for character in value if character.isprintable() or character in '\n\t')


def execute_command(session_id, user_id, expected, command, *, timeout=15, mutating=False,
                    expected_client=None, cancelled=lambda: False):
    """Run on a separate exec channel; never infer success from PTY output."""
    with _lock:
        if session_id in _active:
            raise OperationError('busy')
        _active.add(session_id)
    channel = None
    sent = False
    output = bytearray()
    error_output = bytearray()
    client = expected_client if expected_client is not None else expected.get('client')
    try:
        if cancelled() or not _same_session(session_id, user_id, expected) or expected.get('client') is not client:
            raise OperationError('unavailable')
        transport = client.get_transport()
        if not transport or not transport.is_active():
            raise OperationError('unavailable')
        deadline = time.monotonic() + timeout
        # Once exec is attempted, loss of the acknowledgement is an unknown
        # mutation outcome. Do not suggest retrying an uncertain action.
        def before_exec():
            nonlocal sent
            if (cancelled() or not _same_session(session_id, user_id, expected)
                    or expected.get('client') is not client or client.get_transport() is not transport):
                raise OperationError('unavailable')
            sent = True
        channel = ssh_manager._open_exec_channel(
            transport, command, timeout=timeout, before_exec=before_exec,
        )
        while True:
            if cancelled() or not _same_session(session_id, user_id, expected) or expected.get('client') is not client:
                raise OperationError('unknown' if mutating else 'unavailable')
            if time.monotonic() >= deadline:
                raise OperationError('unknown' if mutating else 'timeout')
            received = False
            for ready, receive, buffer in (
                (channel.recv_ready, channel.recv, output),
                (channel.recv_stderr_ready, channel.recv_stderr, error_output),
            ):
                if ready():
                    chunk = receive(min(4096, MAX_OUTPUT + 1 - len(output) - len(error_output)))
                    buffer.extend(chunk)
                    received = bool(chunk) or received
                    if len(output) + len(error_output) > MAX_OUTPUT:
                        raise OperationError('unknown' if mutating else 'output_limit')
            if received:
                continue
            if channel.exit_status_ready():
                status = channel.recv_exit_status()
                if status < 0:
                    raise OperationError('unknown' if mutating else 'unavailable')
                return {
                    'status': 'completed' if status == 0 else 'failed',
                    'exit_status': status,
                    'output': _display(output.decode('utf-8', 'replace')),
                    'error_output': _display(error_output.decode('utf-8', 'replace')),
                }
            time.sleep(.02)
    except OperationError:
        raise
    except Exception as error:
        raise OperationError('unknown' if sent and mutating else 'unavailable') from error
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        with _lock:
            _active.discard(session_id)


@dataclass(frozen=True)
class Intent:
    user_id: str
    auth_id: str
    session_id: str
    session: dict
    client: object
    action: str
    command: str
    expires: float
    confirmation: str


def _digest(token):
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{20,128}', token):
        raise OperationError('invalid_intent')
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def prepare_intent(session_id, user_id, auth_id, action, target, *, use_sudo=False):
    if not isinstance(action, str) or action not in WRITE_ACTIONS:
        raise OperationError('invalid_action')
    command = build_command(action, target, use_sudo=use_sudo)
    session = owned_session(session_id, user_id)
    now = time.monotonic()
    token = secrets.token_urlsafe(32)
    confirmation = str(session.get('host', '')) if action == 'system.reboot' else ''
    intent = Intent(str(user_id), str(auth_id), session_id, session, session.get('client'),
                    action, command, now + INTENT_TTL, confirmation)
    with _lock:
        for key in [key for key, value in _intents.items() if value.expires <= now]:
            _intents.pop(key, None)
        if len(_intents) >= 256 or sum(item.user_id == str(user_id) for item in _intents.values()) >= 16:
            raise OperationError('busy')
        _intents[_digest(token)] = intent
    return token, intent


def get_intent(token, user_id, auth_id, *, consume=False):
    key = _digest(token)
    with _lock:
        intent = _intents.get(key)
        if (
            intent is None or intent.user_id != str(user_id) or intent.auth_id != str(auth_id)
            or intent.expires <= time.monotonic()
        ):
            raise OperationError('invalid_intent')
        if consume:
            _intents.pop(key)
    if (
        not _same_session(intent.session_id, user_id, intent.session)
        or intent.session.get('client') is not intent.client
    ):
        raise OperationError('unavailable')
    return intent
