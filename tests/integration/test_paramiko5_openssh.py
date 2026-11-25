import os
import socket
import stat
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
import config

from app import ssh_manager
from app.connection_pool import TemporaryConnectionPool
from app.host_key_store import HostKeyStore
from app.network_policy import proxy_jump_remote_dns_allowed
from app.quota_manager import QuotaKind, quota_manager


pytestmark = pytest.mark.skipif(
    os.environ.get('PARAMIKO5_INTEGRATION') != '1',
    reason='set PARAMIKO5_INTEGRATION=1 to run disposable OpenSSH tests',
)

TARGET_HOST = os.environ.get('PARAMIKO5_TARGET_HOST', 'target')
TARGET_PORT = int(os.environ.get('PARAMIKO5_TARGET_PORT', '22'))
PROXY_TARGET_HOST = os.environ.get(
    'PARAMIKO5_PROXY_TARGET_HOST',
    'target',
)
PROXY_TARGET_PORT = int(
    os.environ.get('PARAMIKO5_PROXY_TARGET_PORT', '22')
)
BASTION_HOST = os.environ.get('PARAMIKO5_BASTION_HOST', 'bastion')
BASTION_PORT = int(os.environ.get('PARAMIKO5_BASTION_PORT', '22'))
CHANGED_HOST = os.environ.get(
    'PARAMIKO5_CHANGED_HOST',
    'target-changed',
)
CHANGED_PORT = int(os.environ.get('PARAMIKO5_CHANGED_PORT', '22'))
USERNAME = 'testuser'
PASSWORD = 'Paramiko5-Test-Only!'
RUNTIME_DIR = (
    Path(__file__).resolve().parent / 'paramiko5' / 'runtime'
)


def make_pool():
    pool = TemporaryConnectionPool.__new__(TemporaryConnectionPool)
    pool.connections = {}
    pool.cleanup_interval = 300
    pool.lock = threading.Lock()
    pool.quota_manager = quota_manager
    pool.cleanup_handle = None
    pool._cleanup_lifecycle = None
    return pool


def upload_through_route(
        session_id, path, stream, *, chunk_size, max_bytes, replace=False,
        progress=None):
    """Upload exactly as the HTTP transfer route does."""
    from app import transfer_routes
    from app.sftp_backend import SFTPBackend

    source = SimpleNamespace(handle_id=session_id, backend=SFTPBackend())
    return transfer_routes._upload_to_backend(
        source,
        path,
        stream,
        chunk_size=chunk_size,
        max_bytes=max_bytes,
        cancel_event=threading.Event(),
        cancelled=lambda: False,
        progress=progress or (lambda _count: None),
        replace=replace,
    )


def read_terminal_marker(session_id, marker):
    channel = ssh_manager.sessions[session_id]['channel']
    split_at = len(marker) // 2
    channel.send(
        "printf '%s%s\\n' "
        f"'{marker[:split_at]}' '{marker[split_at:]}'\n"
    )
    received = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            chunk = channel.recv(32768)
        except socket.timeout:
            continue
        if not chunk:
            break
        received.extend(chunk)
        if marker.encode('utf-8') in received:
            return bytes(received)
    raise AssertionError(
        f'terminal marker not received; got {bytes(received)!r}'
    )


def connect_terminal(**overrides):
    uses_proxy = 'proxy_jump_host' in overrides
    kwargs = {
        'host': PROXY_TARGET_HOST if uses_proxy else TARGET_HOST,
        'port': PROXY_TARGET_PORT if uses_proxy else TARGET_PORT,
        'username': USERNAME,
        'user_id': 1,
        'host_key_decision': lambda details: details['fingerprint'].startswith('SHA256:'),
    }
    kwargs.update(overrides)
    session_id, error = ssh_manager.create_ssh_connection(**kwargs)
    assert error is None
    assert session_id
    return session_id


def assert_private_file_mode(path, os_name=os.name):
    if os_name == 'posix':
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def host_key_lookup_name(host, port):
    return host if port == 22 else f'[{host}]:{port}'


@pytest.fixture(autouse=True)
def isolated_host_key_store(tmp_path, monkeypatch):
    known_hosts = tmp_path / 'known_hosts'
    users_root = tmp_path / 'users'
    monkeypatch.setattr(
        ssh_manager.config,
        'KNOWN_HOSTS_FILE',
        known_hosts,
    )
    monkeypatch.setattr(ssh_manager.config, 'USERS_DIR', users_root)
    store = HostKeyStore(1, known_hosts, users_root)
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()
    yield store
    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)


def test_direct_password_terminal_roundtrip():
    session_id = connect_terminal(password=PASSWORD)
    try:
        output = read_terminal_marker(
            session_id,
            'PARAMIKO5_PASSWORD_TERMINAL_OK',
        )
        assert b'PARAMIKO5_PASSWORD_TERMINAL_OK' in output
    finally:
        assert ssh_manager.close_session(session_id) is True


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o750])
@pytest.mark.parametrize('route', ['backend', 'http-upload', 'backend-copy'])
def test_atomic_transfer_keeps_staging_private_and_preserves_destination_mode(mode, route):
    import io
    from types import SimpleNamespace
    from app.sftp_backend import SFTPBackend
    from app.paramiko_channels import open_sftp_client

    session_id = connect_terminal(password=PASSWORD)
    source = SimpleNamespace(handle_id=session_id)
    client = ssh_manager.sessions[session_id]['client']
    sftp = open_sftp_client(client.get_transport(), timeout=5, operation_timeout=5)
    directory = f'/tmp/webssh-transfer-mode-{uuid.uuid4().hex}'
    sftp.mkdir(directory, 0o755)
    target = directory + '/secret'
    try:
        with sftp.file(target, 'wb') as original:
            original.write(b'original')
        sftp.chmod(target, mode)
        def inspect_staging(*_args):
            staged = [item for item in sftp.listdir_attr(directory) if '.webssh-' in item.filename]
            assert len(staged) == 1
            assert stat.S_IMODE(staged[0].st_mode) == 0o600
        if route == 'backend':
            with SFTPBackend().open_atomic_writer(source, target, replace=True,
                                                  cancel_event=threading.Event()) as writer:
                writer.write(b'replacement')
                inspect_staging()
        elif route == 'http-upload':
            upload_through_route(session_id, target, io.BytesIO(b'replacement'),
                chunk_size=4, max_bytes=100, replace=True, progress=inspect_staging)
        else:
            source_path = directory + '/source'
            with sftp.file(source_path, 'wb') as source_file:
                source_file.write(b'replacement')
            from app.remote_transfer import TransferBudget, copy_remote_entry
            endpoint = SimpleNamespace(
                source_id='sftp-session:permissions-check',
                handle_id=session_id,
                backend=SFTPBackend(),
            )
            copy_remote_entry(
                endpoint, source_path, endpoint, target,
                conflict_policy='replace',
                budget=TransferBudget(max_bytes=100, max_members=2),
                cancel_event=threading.Event(),
                progress=inspect_staging,
                chunk_size=4,
            )
        assert stat.S_IMODE(sftp.stat(target).st_mode) == mode
        with sftp.file(target, 'rb') as result:
            assert result.read() == b'replacement'
    finally:
        for name in sftp.listdir(directory):
            sftp.remove(directory + '/' + name)
        sftp.rmdir(directory)
        sftp.close()
        ssh_manager.close_session(session_id)


def test_file_mutations_are_exclusive_preserve_modes_and_refuse_final_symlink_race(monkeypatch):
    import hashlib
    from types import SimpleNamespace
    from app.file_mutations import FileMutationError
    from app.paramiko_channels import BoundedSFTPClient
    from app.sftp_backend import SFTPBackend
    from app import sftp_handler

    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', True)

    session_id = connect_terminal(password=PASSWORD)
    source = SimpleNamespace(handle_id=session_id)
    backend = SFTPBackend()
    client = ssh_manager.sessions[session_id]['client']
    from app.paramiko_channels import open_sftp_client
    sftp = open_sftp_client(client.get_transport(), timeout=5, operation_timeout=5)
    directory = f'/tmp/webssh-mutations-{uuid.uuid4().hex}'
    sftp.mkdir(directory, 0o700)
    try:
        created = backend.create_file(source, directory, 'new.txt')
        path = created['path']
        assert sftp.stat(path).st_size == 0
        assert stat.S_IMODE(sftp.stat(path).st_mode) == 0o600
        with pytest.raises(FileMutationError) as conflict:
            backend.create_file(source, directory, 'new.txt')
        assert conflict.value.code in {'CONFLICT', 'OUTCOME_UNKNOWN'}
        sftp.mkdir(directory + '/existing-directory')
        for name in ['existing-directory']:
            with pytest.raises(FileMutationError):
                backend.create_file(source, directory, name)

        before = backend.get_permissions(source, path)
        result = backend.set_permissions(source, path, 0o750, verify_metadata=lambda current: current == before or pytest.fail('changed snapshot'))
        assert result['mode'] == '750'
        outcome = sftp_handler.write_file_text(session_id, path, 'edited', expected_revision=hashlib.sha256(b'').hexdigest())
        assert outcome.success, outcome.error
        assert stat.S_IMODE(sftp.stat(path).st_mode) == 0o750
        with sftp.file(path, 'rb') as remote:
            assert remote.read() == b'edited'
        before_directory = backend.get_permissions(source, directory + '/existing-directory')
        result = backend.set_permissions(source, directory + '/existing-directory', 0o700, verify_metadata=lambda current: current == before_directory or pytest.fail('changed directory'))
        assert result['mode'] == '700'

        # chmod changes the inode, so a hardlink observes the same mode. This
        # is an explicit remote-account boundary, not path confinement.
        alias = directory + '/hardlink'
        _, stdout, _ = client.exec_command(f'ln -- {path} {alias}')
        assert stdout.channel.recv_exit_status() == 0
        result = backend.set_permissions(source, path, 0o000, verify_metadata=lambda _current: None)
        assert result['mode'] == '000'
        assert stat.S_IMODE(sftp.stat(alias).st_mode) == 0o000
        backend.set_permissions(source, path, 0o750, verify_metadata=lambda _current: None)
        sftp.remove(alias)

        canary = directory + '/canary'
        backend.create_file(source, directory, 'canary')
        sftp.symlink(canary, directory + '/existing-link')
        with pytest.raises(FileMutationError):
            backend.create_file(source, directory, 'existing-link')
        with pytest.raises(FileMutationError):
            backend.get_permissions(source, directory + '/existing-link')

        original = BoundedSFTPClient.set_permissions_no_follow

        def swapped(self, remote_path, mode):
            self.remove(remote_path)
            self.symlink(canary, remote_path)
            return original(self, remote_path, mode)

        monkeypatch.setattr(BoundedSFTPClient, 'set_permissions_no_follow', swapped)
        with pytest.raises(FileMutationError):
            backend.set_permissions(source, path, 0o777, verify_metadata=lambda _current: None)
        assert stat.S_IMODE(sftp.stat(canary).st_mode) == 0o600
    finally:
        for entry in sftp.listdir_attr(directory):
            path = directory + '/' + entry.filename
            if stat.S_ISDIR(entry.st_mode):
                sftp.rmdir(path)
            else:
                sftp.remove(path)
        sftp.rmdir(directory)
        sftp.close()
        ssh_manager.close_session(session_id)


@pytest.mark.parametrize('key_name', ['rsa', 'ed25519', 'ecdsa'])
def test_direct_key_terminal_roundtrip(key_name):
    key_content = (RUNTIME_DIR / f'{key_name}.pem').read_text(
        encoding='utf-8'
    )
    session_id = connect_terminal(key_content=key_content)
    try:
        marker = f'PARAMIKO5_{key_name.upper()}_TERMINAL_OK'
        assert marker.encode() in read_terminal_marker(session_id, marker)
    finally:
        assert ssh_manager.close_session(session_id) is True


def test_quick_connect_sftp_rejects_unknown_host_key():
    pool = make_pool()
    connection_id, error = pool.create_connection(
        host=TARGET_HOST, port=TARGET_PORT, username=USERNAME,
        user_id='1', password=PASSWORD,
    )
    assert connection_id is None
    assert 'host key' in error.lower()
    assert not pool.connections


@pytest.mark.parametrize(
    'auth',
    ['password', 'rsa', 'ed25519', 'ecdsa'],
)
def test_quick_connect_sftp_roundtrip(auth):
    trusted_session = connect_terminal(password=PASSWORD)
    assert ssh_manager.close_session(trusted_session)
    pool = make_pool()
    kwargs = {'password': PASSWORD} if auth == 'password' else {
        'key_content': (RUNTIME_DIR / f'{auth}.pem').read_text(
            encoding='utf-8'
        )
    }
    connection_id, error = pool.create_connection(
        host=TARGET_HOST,
        port=TARGET_PORT,
        username=USERNAME,
        user_id='1',
        **kwargs,
    )
    assert error is None
    assert connection_id
    reservation = pool.connections[connection_id]['quota_reservation']
    assert reservation.kind is QuotaKind.QUICK_CONNECTION
    assert reservation.released is False

    remote_path = f'/tmp/paramiko5-{auth}-{uuid.uuid4().hex}.bin'
    payload = os.urandom(4096)
    sftp = pool.connections[connection_id]['sftp']
    try:
        with sftp.file(remote_path, 'wb') as remote_file:
            remote_file.write(payload)
        with sftp.file(remote_path, 'rb') as remote_file:
            assert remote_file.read() == payload
    finally:
        try:
            sftp.remove(remote_path)
        finally:
            assert pool.close_connection(connection_id) is True
            assert pool.connections == {}
            assert reservation.released is True


@pytest.mark.parametrize('auth', ['password', 'rsa'])
def test_proxy_jump_terminal_and_sftp_roundtrip(auth):
    assert proxy_jump_remote_dns_allowed(
        PROXY_TARGET_HOST,
        config.PROXY_JUMP_REMOTE_DNS_ALLOWLIST,
    )
    if auth == 'password':
        target_auth = {'password': PASSWORD}
        jump_auth = {'proxy_jump_password': PASSWORD}
    else:
        key_content = (RUNTIME_DIR / 'rsa.pem').read_text(encoding='utf-8')
        target_auth = {'key_content': key_content}
        jump_auth = {'proxy_jump_key_content': key_content}

    session_id = connect_terminal(
        proxy_jump_host=BASTION_HOST,
        proxy_jump_port=BASTION_PORT,
        proxy_jump_username=USERNAME,
        **target_auth,
        **jump_auth,
    )
    remote_path = f'/tmp/paramiko5-jump-{uuid.uuid4().hex}.txt'
    try:
        marker = f'PARAMIKO5_JUMP_{auth.upper()}_OK'
        assert marker.encode() in read_terminal_marker(session_id, marker)
        client = ssh_manager.sessions[session_id]['client']
        sftp = client.open_sftp()
        try:
            with sftp.file(remote_path, 'wb') as remote_file:
                remote_file.write(marker.encode())
            with sftp.file(remote_path, 'rb') as remote_file:
                assert remote_file.read() == marker.encode()
            sftp.remove(remote_path)
        finally:
            sftp.close()
    finally:
        assert ssh_manager.close_session(session_id) is True


def test_first_seen_host_key_is_persisted_with_mode_0600(
        isolated_host_key_store):
    session_id = connect_terminal(password=PASSWORD)
    assert ssh_manager.close_session(session_id) is True

    user_path = isolated_host_key_store.user_path
    assert user_path.exists()
    assert not isolated_host_key_store.global_path.exists()
    assert_private_file_mode(user_path)
    host_keys = paramiko.HostKeys(str(user_path))
    assert host_key_lookup_name(TARGET_HOST, TARGET_PORT) in host_keys

    second_session = connect_terminal(password=PASSWORD)
    assert ssh_manager.close_session(second_session) is True


def test_changed_host_key_is_rejected(isolated_host_key_store):
    session_id = connect_terminal(password=PASSWORD)
    assert ssh_manager.close_session(session_id) is True

    client = paramiko.SSHClient()
    isolated_host_key_store.load_into(client)
    client.set_missing_host_key_policy(
        isolated_host_key_store.missing_key_policy()
    )
    changed_socket = socket.create_connection(
        (CHANGED_HOST, CHANGED_PORT),
        timeout=5,
    )
    try:
        with pytest.raises(paramiko.BadHostKeyException):
            client.connect(
                hostname=TARGET_HOST,
                port=TARGET_PORT,
                username=USERNAME,
                password=PASSWORD,
                sock=changed_socket,
                timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
    finally:
        client.close()


@pytest.mark.parametrize('recursive', [False, True])
def test_permission_jobs_real_tree_preview_modes_and_symlink_exclusion(monkeypatch, recursive):
    from types import SimpleNamespace
    from app.permission_jobs import PermissionJobManager
    from app.paramiko_channels import open_sftp_client
    from app.sftp_backend import SFTPBackend

    class InlineRuntime:
        def accepting_work(self):
            return True

        def start_job(self, _name, target, **_kwargs):
            event = threading.Event()
            target(event)
            return SimpleNamespace(cancel=event.set)

    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', True)
    session_id = connect_terminal(password=PASSWORD)
    source = SimpleNamespace(handle_id=session_id, backend=SFTPBackend())
    client = ssh_manager.sessions[session_id]['client']
    sftp = open_sftp_client(client.get_transport(), timeout=5, operation_timeout=5)
    root = f'/tmp/webssh-permission-job-{uuid.uuid4().hex}'
    sftp.mkdir(root, 0o700)
    sftp.mkdir(root + '/nested', 0o700)
    canary = root + '-outside'
    with sftp.file(canary, 'wb') as remote:
        remote.write(b'outside selection')
    sftp.chmod(canary, 0o600)
    for name in ['file', 'nested/child']:
        with sftp.file(root + '/' + name, 'wb') as remote:
            remote.write(b'permission job fixture')
        sftp.chmod(root + '/' + name, 0o600)
    sftp.symlink(canary, root + '/nested/link')
    try:
        manager = PermissionJobManager(InlineRuntime())
        status = manager.prepare(
            user_id=1, socket_sid='disposable-job-socket',
            source_id='sftp-session:' + session_id,
            paths=[root, root + '/file'] if recursive else [root],
            recursive=recursive, file_mode='640', directory_mode='750',
            authorize=lambda: source,
        )
        assert status['state'] == 'ready', status
        assert (status['files'], status['directories'], status['skipped']) == (
            (2, 2, 1) if recursive else (0, 1, 0)
        )
        assert stat.S_IMODE(sftp.lstat(root).st_mode) == 0o700
        assert stat.S_IMODE(sftp.lstat(root + '/file').st_mode) == 0o600
        done = manager.apply(1, 'disposable-job-socket',
                             'sftp-session:' + session_id, status['job_id'],
                             authorize=lambda: source)
        assert done['state'] == 'completed', done
        assert done['changed'] == (4 if recursive else 1)
        assert stat.S_IMODE(sftp.lstat(root).st_mode) == 0o750
        assert stat.S_IMODE(sftp.lstat(root + '/nested').st_mode) == (0o750 if recursive else 0o700)
        assert stat.S_IMODE(sftp.lstat(root + '/file').st_mode) == (0o640 if recursive else 0o600)
        assert stat.S_IMODE(sftp.lstat(root + '/nested/child').st_mode) == (0o640 if recursive else 0o600)
        assert stat.S_ISLNK(sftp.lstat(root + '/nested/link').st_mode)
        assert stat.S_IMODE(sftp.lstat(canary).st_mode) == 0o600
    finally:
        sftp.chmod(root, 0o700)
        sftp.chmod(root + '/nested', 0o700)
        for name in ['nested/link', 'nested/child', 'file']:
            sftp.remove(root + '/' + name)
        sftp.rmdir(root + '/nested')
        sftp.rmdir(root)
        sftp.remove(canary)
        sftp.close()
        ssh_manager.close_session(session_id)


@pytest.fixture
def remote_workspace():
    from app.paramiko_channels import open_sftp_client

    session_id = connect_terminal(password=PASSWORD)
    client = ssh_manager.sessions[session_id]['client']
    sftp = open_sftp_client(client.get_transport(), timeout=5, operation_timeout=5)
    directory = f'/tmp/webssh-g1-{uuid.uuid4().hex}'
    sftp.mkdir(directory, 0o755)

    def write(name, data, mode=0o644):
        path = f'{directory}/{name}'.encode('utf-8', 'surrogateescape')
        with sftp.file(path, 'wb') as remote:
            remote.write(data)
        sftp.chmod(path, mode)

    def read(name):
        with sftp.file(f'{directory}/{name}'.encode('utf-8', 'surrogateescape'), 'rb') as remote:
            return remote.read()

    try:
        yield SimpleNamespace(session_id=session_id, sftp=sftp, path=directory,
                              write=write, read=read)
    finally:
        try:
            # Paramiko cannot list the non-UTF-8 fixture name; remove the tree
            # with the remote shell instead.
            channel = client.exec_command(f"rm -rf -- '{directory}'")[1].channel
            assert channel.recv_exit_status() == 0
        finally:
            sftp.close()
            ssh_manager.close_session(session_id)


def edit_and_save(workspace, name, change):
    from app import sftp_handler

    path = f'{workspace.path}/{name}'
    opened, error = sftp_handler.read_file_for_edit(workspace.session_id, path)
    assert error is None, error
    return opened, sftp_handler.write_file_text(
        workspace.session_id, path, change(opened['content']),
        encoding=opened['encoding'], newline=opened['newline'],
        expected_revision=opened['revision'],
    )


def test_names_with_two_dots_can_be_listed_opened_and_uploaded(remote_workspace):
    import io
    from app import sftp_handler

    remote_workspace.sftp.mkdir(f'{remote_workspace.path}/backup..old')
    remote_workspace.write('notes..txt', b'two dots\n')
    files, error = sftp_handler.list_directory(
        remote_workspace.session_id, f'{remote_workspace.path}/backup..old',
    )
    assert (files, error) == ([], None)
    opened, error = sftp_handler.read_file_for_edit(
        remote_workspace.session_id, f'{remote_workspace.path}/notes..txt',
    )
    assert error is None and opened['content'] == 'two dots\n'
    upload_through_route(
        remote_workspace.session_id, f'{remote_workspace.path}/backup..old/v1..2.tar.gz',
        io.BytesIO(b'archive'), chunk_size=4, max_bytes=100,
    )
    assert remote_workspace.read('backup..old/v1..2.tar.gz') == b'archive'
    assert sftp_handler.read_file_for_edit(
        remote_workspace.session_id, '../../etc/passwd',
    ) == (None, 'Invalid path')
    assert sftp_handler.read_file_for_edit(
        remote_workspace.session_id, 'notes..txt/../../etc/passwd',
    ) == (None, 'Invalid path')


def test_editor_keeps_mixed_line_endings_and_the_script_still_runs(remote_workspace):
    remote_workspace.write('mixed.sh', b'#!/bin/sh\necho a\r\necho b\necho c\n', 0o755)
    opened, outcome = edit_and_save(
        remote_workspace, 'mixed.sh', lambda text: text + 'echo d\n',
    )
    assert opened['newline'] == 'mixed'
    assert outcome.success, outcome.error
    assert remote_workspace.read('mixed.sh') == b'#!/bin/sh\necho a\r\necho b\necho c\necho d\n'
    channel = ssh_manager.sessions[remote_workspace.session_id]['client'].exec_command(
        f'{remote_workspace.path}/mixed.sh',
    )[1].channel
    assert channel.recv_exit_status() == 0


def test_editor_saves_a_file_opened_through_a_symlink(remote_workspace):
    remote_workspace.write('real.conf', b'listen 80;\n')
    remote_workspace.sftp.symlink('real.conf', f'{remote_workspace.path}/link.conf')
    _opened, outcome = edit_and_save(
        remote_workspace, 'link.conf', lambda text: text.replace('80', '8080'),
    )
    assert outcome.success, outcome.error
    assert remote_workspace.read('real.conf') == b'listen 8080;\n'
    assert stat.S_ISLNK(remote_workspace.sftp.lstat(f'{remote_workspace.path}/link.conf').st_mode)
    assert remote_workspace.sftp.readlink(f'{remote_workspace.path}/link.conf') == 'real.conf'


def test_directory_with_a_non_utf8_name_stays_browsable(remote_workspace):
    from app import sftp_handler

    remote_workspace.write('normal.txt', b'ok')
    remote_workspace.write('caf\udce9.txt', b'latin-1 name')
    files, error = sftp_handler.list_directory(
        remote_workspace.session_id, remote_workspace.path,
    )
    assert error is None
    assert sorted(entry['name'] for entry in files) == ['caf\udce9.txt', 'normal.txt']
    listing, error = sftp_handler.open_directory_listing(
        remote_workspace.session_id, remote_workspace.path,
    )
    assert error is None
    page, error, _more = listing.read_page(10)
    assert error is None and len(page) == 2


def test_editor_refuses_to_reencode_a_latin1_file(remote_workspace):
    remote_workspace.write('latin1.txt', b'Gr\xfc\xdfe\n')
    opened, outcome = edit_and_save(
        remote_workspace, 'latin1.txt', lambda text: text + 'Preis 5 €\n',
    )
    assert opened['encoding'] == 'latin-1'
    assert not outcome.success
    assert outcome.code == 'EDIT_ENCODING_UNSUPPORTED'
    assert (outcome.unsupported_character, outcome.unsupported_line) == ('€', 2)
    assert remote_workspace.read('latin1.txt') == b'Gr\xfc\xdfe\n'
    _opened, outcome = edit_and_save(
        remote_workspace, 'latin1.txt', lambda text: text + '\xc4ra\n',
    )
    assert outcome.success, outcome.error
    assert remote_workspace.read('latin1.txt') == b'Gr\xfc\xdfe\n\xc4ra\n'


def test_long_file_names_can_be_uploaded_and_saved(remote_workspace):
    import io

    name = '日' * 80 + '.txt'
    assert len(name.encode('utf-8')) <= 255
    upload_through_route(
        remote_workspace.session_id, f'{remote_workspace.path}/{name}',
        io.BytesIO(b'first\n'), chunk_size=4, max_bytes=100,
    )
    assert remote_workspace.read(name) == b'first\n'
    _opened, outcome = edit_and_save(remote_workspace, name, lambda text: text + 'second\n')
    assert outcome.success, outcome.error
    assert remote_workspace.read(name) == b'first\nsecond\n'
    assert sorted(remote_workspace.sftp.listdir(remote_workspace.path)) == [name]
