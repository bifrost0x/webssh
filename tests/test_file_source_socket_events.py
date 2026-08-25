from types import SimpleNamespace

import pytest

from app import socket_events
from app.file_backend import FileWriteOutcome
from app.file_service import FileService
from app.file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceUnavailable,
    ResolvedFileSource,
)


class ListingBackend:
    def __init__(self):
        self.calls = []

    def list_directory(self, source, path):
        self.calls.append((source.source_id, path))
        return [{'name': 'config.yml'}], None


def make_source(source_id, capabilities, backend, *, kind='sftp'):
    endpoint = 'host.test/Share' if kind == 'smb' else 'host.test:22'
    protocol = 'SMB 3.1.1' if kind == 'smb' else 'SFTP'
    return ResolvedFileSource(
        descriptor=FileSourceDescriptor(
            source_id=source_id,
            kind=kind,
            label='Owned source',
            endpoint=endpoint,
            protocol=protocol,
            capabilities=capabilities,
            ephemeral=False,
            security={},
        ),
        user_id='7',
        handle_id=source_id.split(':', 1)[1],
        backend=backend,
    )


def capture(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    return emitted, SimpleNamespace(id=7, username='operator')


def test_list_directory_accepts_source_id_and_uses_file_service(monkeypatch):
    emitted, user = capture(monkeypatch)
    backend = ListingBackend()
    source = make_source(
        'sftp-session:owned',
        (FileCapability.LIST,),
        backend,
    )
    service = FileService(
        SimpleNamespace(resolve=lambda source_id, user_id: source)
    )
    monkeypatch.setattr(socket_events, 'file_service', service)

    socket_events.handle_list_directory.__wrapped__({
        'source_id': 'sftp-session:owned',
        'remote_path': '/srv/current',
        'request_id': 'left:directory:4',
    }, current_user=user)

    assert backend.calls == [('sftp-session:owned', '/srv/current')]
    assert emitted == [('directory_listing', {
        'source_id': 'sftp-session:owned',
        'path': '/srv/current',
        'files': [{'name': 'config.yml'}],
        'request_id': 'left:directory:4',
    })]


@pytest.mark.parametrize(
    'source_id, capabilities',
    [
        ('sftp-session:foreign', None),
        ('sftp-session:missing', None),
        ('sftp-session:owned', (FileCapability.READ,)),
    ],
)
def test_list_directory_hides_unavailable_and_incapable_sources(
    monkeypatch,
    source_id,
    capabilities,
):
    emitted, user = capture(monkeypatch)
    backend = ListingBackend()

    def resolve(candidate, user_id):
        if candidate != 'sftp-session:owned':
            raise FileSourceUnavailable()
        return make_source(candidate, capabilities, backend)

    monkeypatch.setattr(
        socket_events,
        'file_service',
        FileService(SimpleNamespace(resolve=resolve)),
    )

    socket_events.handle_list_directory.__wrapped__({
        'source_id': source_id,
        'remote_path': '/',
        'request_id': 'left:directory:denied',
    }, current_user=user)

    assert backend.calls == []
    assert emitted == [('error', {
        'error': 'File source unavailable',
        'code': 'SOURCE_UNAVAILABLE',
        'operation': 'list_directory',
        'source_id': source_id,
        'path': '/',
        'request_id': 'left:directory:denied',
    })]


class OperationBackend:
    def __init__(self):
        self.calls = []

    def mkdir(self, source, path):
        self.calls.append(('mkdir', path))
        return True, None

    def normalize_path(self, path):
        if not isinstance(path, str) or not path.startswith('/') or '..' in path:
            return None
        return path.rstrip('/') or '/'

    def rename(self, source, old_path, new_path, *, replace=False):
        self.calls.append(('rename', old_path, new_path, replace))
        return True, None

    def delete(self, source, path, *, recursive, budget, cancel_event):
        self.calls.append(('delete', path, recursive, budget, cancel_event))
        return True, None

    def get_home_directory(self, source):
        self.calls.append(('home',))
        return '/home/operator', None

    def check_exists(self, source, path):
        self.calls.append(('exists', path))
        return {
            'exists': path != '/new',
            'is_dir': False,
            'size': 4,
        }, None

    def get_file_stat(self, source, path):
        self.calls.append(('stat', path))
        return {'name': 'note.txt', 'path': path, 'size': 4}, None

    def read_file_preview(
        self,
        source,
        path,
        *,
        max_bytes,
        offset,
        tail_lines,
    ):
        self.calls.append(('preview', path, max_bytes, offset, tail_lines))
        return {'content': 'note', 'size': 4}, None

    def read_file_for_edit(self, source, path):
        self.calls.append(('edit', path))
        return {
            'content': 'note',
            'size': 4,
            'encoding': 'utf-8',
            'newline': 'lf',
            'revision': 'a' * 64,
        }, None

    def read_binary_preview(self, source, path, *, max_size):
        self.calls.append(('binary-preview', path, max_size))
        return b'image', None

    def write_file_text(
        self,
        source,
        path,
        content,
        *,
        encoding,
        newline,
        allow_non_atomic=False,
        expected_revision=None,
        replace_strategy='atomic',
    ):
        self.calls.append((
            'save', path, content, encoding, newline, allow_non_atomic,
            expected_revision, replace_strategy,
        ))
        return FileWriteOutcome(success=True, revision='b' * 64)


def test_file_operation_handlers_use_one_source_service_boundary(app, monkeypatch):
    emitted, user = capture(monkeypatch)
    monkeypatch.setattr(
        socket_events,
        'log_file_source_operation',
        lambda *_args, **_kwargs: None,
    )
    backend = OperationBackend()
    source = make_source(
        'sftp-session:owned',
        tuple(FileCapability),
        backend,
    )
    service = FileService(
        SimpleNamespace(resolve=lambda source_id, user_id: source)
    )
    monkeypatch.setattr(socket_events, 'file_service', service)
    common = {
        'source_id': 'sftp-session:owned',
        'request_id': 'file-operation:owned',
    }

    socket_events.handle_create_directory.__wrapped__({
        **common,
        'remote_path': '/new',
    }, current_user=user)
    rename_result = socket_events.handle_rename_file.__wrapped__({
        **common,
        'old_path': '/old',
        'new_path': '/new',
    }, current_user=user)
    socket_events.handle_delete_item.__wrapped__({
        **common,
        'path': '/old-tree',
    }, current_user=user)
    socket_events.handle_get_home_directory.__wrapped__({
        **common,
        'request_id': 'home:1',
    }, current_user=user)
    socket_events.handle_check_exists.__wrapped__({
        **common,
        'path': '/note.txt',
    }, current_user=user)
    socket_events.handle_get_file_stat.__wrapped__({
        **common,
        'path': '/note.txt',
    }, current_user=user)
    socket_events.handle_preview_file.__wrapped__({
        **common,
        'path': '/note.txt',
        'max_bytes': 4096,
        'offset': 2,
        'tail_lines': 10,
    }, current_user=user)
    socket_events.handle_open_file_for_edit.__wrapped__({
        **common,
        'path': '/note.txt',
    }, current_user=user)
    with app.test_request_context('/socket.io'):
        socket_events.handle_download_file_binary.__wrapped__({
            **common,
            'remote_path': '/image.png',
            'for_preview': True,
        }, current_user=user)
        socket_events.handle_save_file.__wrapped__({
            **common,
            'path': '/note.txt',
            'content': 'saved',
            'encoding': 'utf-8',
            'newline': 'lf',
            'expected_revision': 'a' * 64,
        }, current_user=user)

    assert backend.calls == [
        ('mkdir', '/new'),
        ('exists', '/new'),
        ('rename', '/old', '/new', False),
        ('delete', '/old-tree', True, None, None),
        ('home',),
        ('exists', '/note.txt'),
        ('stat', '/note.txt'),
        ('preview', '/note.txt', 4096, 2, 10),
        ('edit', '/note.txt'),
        ('binary-preview', '/image.png', socket_events.config.MAX_EDITOR_FILE_SIZE),
        ('save', '/note.txt', 'saved', 'utf-8', 'lf', False, 'a' * 64, 'atomic'),
    ]
    assert [event for event, _payload in emitted] == [
        'directory_created',
        'file_renamed',
        'item_deleted',
        'home_directory',
        'file_exists_result',
        'file_stat_result',
        'preview_data',
        'edit_data',
        'file_download_ready_binary',
        'file_saved',
    ]
    assert all(
        payload.get('source_id') == 'sftp-session:owned'
        for _event, payload in emitted
    )
    assert rename_result == {
        'success': True,
        'source_id': 'sftp-session:owned',
        'old_path': '/old',
        'new_path': '/new',
        'request_id': 'file-operation:owned',
    }


def test_smb_editor_requests_per_save_recoverable_swap_consent(
    app,
    monkeypatch,
):
    emitted, user = capture(monkeypatch)
    audit_calls = []
    monkeypatch.setattr(
        socket_events,
        'log_file_source_operation',
        lambda **details: audit_calls.append(details),
    )

    class AtomicOnlyBackend(OperationBackend):
        def write_file_text(
            self,
            source,
            path,
            content,
            *,
            encoding,
            newline,
            allow_non_atomic=False,
            expected_revision=None,
            replace_strategy='atomic',
        ):
            self.calls.append((
                'save', allow_non_atomic, expected_revision, replace_strategy,
            ))
            return FileWriteOutcome(
                success=False,
                error='This SMB account cannot replace the file atomically.',
                code='SMB_RECOVERABLE_REPLACE_REQUIRED',
                revision=expected_revision,
            )

    backend = AtomicOnlyBackend()
    source = make_source(
        'smb-quick:owned',
        tuple(FileCapability),
        backend,
        kind='smb',
    )
    monkeypatch.setattr(
        socket_events,
        'file_service',
        FileService(SimpleNamespace(resolve=lambda source_id, user_id: source)),
    )
    common = {
        'source_id': 'smb-quick:owned',
        'request_id': 'save:smb:1',
        'path': '/note.txt',
        'content': 'saved',
        'encoding': 'utf-8',
        'newline': 'lf',
        'expected_revision': 'a' * 64,
    }

    with app.test_request_context('/socket.io'):
        socket_events.handle_save_file.__wrapped__(
            {**common, 'allow_non_atomic': True},
            current_user=user,
        )

    assert backend.calls == [('save', False, 'a' * 64, 'atomic')]
    assert len(audit_calls) == 1
    assert audit_calls[0] == {
        'username': 'operator',
        'operation': 'edit_save',
        'result': 'RECOVERABLE_REPLACE_REQUIRED',
        'filename': 'note.txt',
        'size': len(b'saved'),
        'ip_address': None,
        'destination_target_host': None,
        'destination_share': None,
        'destination_filename': None,
        'source_kind': 'smb',
        'target_host': 'host.test',
        'share': 'Share',
    }
    assert emitted[0] == ('error', {
        'error': 'This SMB account cannot replace the file atomically.',
        'code': 'SMB_RECOVERABLE_REPLACE_REQUIRED',
        'revision': 'a' * 64,
        'operation': 'save_file',
        'source_id': 'smb-quick:owned',
        'request_id': 'save:smb:1',
        'path': '/note.txt',
    })


def test_smb_editor_surfaces_recovery_artifacts_without_raw_paths(app, monkeypatch):
    emitted, user = capture(monkeypatch)
    monkeypatch.setattr(
        socket_events,
        'log_file_source_operation',
        lambda **_details: None,
    )
    class RecoveryBackend(OperationBackend):
        def write_file_text(self, *_args, **_kwargs):
            return FileWriteOutcome(
                success=False,
                error='Manual recovery is required.',
                code='SMB_RECOVERY_REQUIRED',
                recovery_leaves=(
                    '.note.txt.webssh-write-safe.tmp',
                    '.note.txt.webssh-recovery-safe.bak',
                ),
            )

    source = make_source(
        'smb-quick:owned',
        tuple(FileCapability),
        RecoveryBackend(),
        kind='smb',
    )
    monkeypatch.setattr(
        socket_events,
        'file_service',
        FileService(SimpleNamespace(resolve=lambda *_args: source)),
    )

    with app.test_request_context('/socket.io'):
        socket_events.handle_save_file.__wrapped__({
            'source_id': 'smb-quick:owned',
            'request_id': 'save:smb:recovery',
            'path': '/note.txt',
            'content': 'saved',
            'encoding': 'utf-8',
            'newline': 'lf',
            'expected_revision': 'a' * 64,
            'replace_strategy': 'recoverable_swap',
        }, current_user=user)

    assert emitted == [('error', {
        'error': 'Manual recovery is required.',
        'code': 'SMB_RECOVERY_REQUIRED',
        'recovery_leaves': [
            '.note.txt.webssh-write-safe.tmp',
            '.note.txt.webssh-recovery-safe.bak',
        ],
        'operation': 'save_file',
        'source_id': 'smb-quick:owned',
        'request_id': 'save:smb:recovery',
        'path': '/note.txt',
    })]


@pytest.mark.parametrize(
    ('old_path', 'new_path'),
    (
        ('/same', '/same'),
        ('/folder', '/folder/child'),
        ('/Folder', '/folder/child'),
        ('/Folder', '/folder/child'),
        ('/', '/target'),
        ('/source', '/../escape'),
    ),
)
def test_move_rejects_unsafe_relationships_without_mutation(
    monkeypatch,
    old_path,
    new_path,
):
    emitted, user = capture(monkeypatch)
    backend = OperationBackend()
    source = make_source(
        'smb-quick:owned', tuple(FileCapability), backend, kind='smb',
    )
    monkeypatch.setattr(
        socket_events,
        'file_service',
        FileService(SimpleNamespace(resolve=lambda *_args: source)),
    )

    result = socket_events.handle_rename_file.__wrapped__({
        'source_id': 'smb-quick:owned',
        'old_path': old_path,
        'new_path': new_path,
        'request_id': 'workspace:move:1',
    }, current_user=user)

    assert result['success'] is False
    assert result['code'] == 'INVALID_REQUEST'
    assert not any(call[0] == 'rename' for call in backend.calls)
    assert emitted[-1][0] == 'error'
    assert emitted[-1][1]['code'] == 'INVALID_REQUEST'


def test_move_reports_destination_conflict_without_replacement(monkeypatch):
    emitted, user = capture(monkeypatch)
    backend = OperationBackend()
    source = make_source(
        'smb-quick:owned', tuple(FileCapability), backend, kind='smb',
    )
    monkeypatch.setattr(
        socket_events,
        'file_service',
        FileService(SimpleNamespace(resolve=lambda *_args: source)),
    )

    result = socket_events.handle_rename_file.__wrapped__({
        'source_id': 'smb-quick:owned',
        'old_path': '/source.txt',
        'new_path': '/note.txt',
        'request_id': 'workspace:move:conflict',
    }, current_user=user)

    assert result == {
        'success': False,
        'code': 'CONFLICT',
        'error': 'A file or folder already exists at the destination.',
        'operation': 'rename_file',
        'source_id': 'smb-quick:owned',
        'old_path': '/source.txt',
        'new_path': '/note.txt',
        'request_id': 'workspace:move:conflict',
    }
    assert not any(call[0] == 'rename' for call in backend.calls)
    assert emitted[-1] == ('error', {
        **result,
        'path': '/source.txt',
    })


@pytest.mark.parametrize(
    'handler,payload,event',
    [
        (socket_events.handle_create_directory, {'remote_path': '/new'}, 'error'),
        (
            socket_events.handle_rename_file,
            {'old_path': '/old', 'new_path': '/new'},
            'error',
        ),
        (socket_events.handle_delete_item, {'path': '/old'}, 'error'),
        (
            socket_events.handle_get_home_directory,
            {'request_id': 'home:denied'},
            'error',
        ),
        (socket_events.handle_check_exists, {'path': '/old'}, 'error'),
        (socket_events.handle_get_file_stat, {'path': '/old'}, 'error'),
        (socket_events.handle_preview_file, {'path': '/old'}, 'preview_error'),
        (
            socket_events.handle_open_file_for_edit,
            {'path': '/old'},
            'edit_error',
        ),
        (
            socket_events.handle_download_file_binary,
            {'remote_path': '/old', 'for_preview': True},
            'error',
        ),
        (
            socket_events.handle_save_file,
            {'path': '/old', 'content': 'x'},
            'error',
        ),
    ],
)
def test_file_operation_handlers_return_uniform_source_failure(
    monkeypatch,
    handler,
    payload,
    event,
):
    emitted, user = capture(monkeypatch)
    service = FileService(
        SimpleNamespace(
            resolve=lambda _source_id, _user_id: (_ for _ in ()).throw(
                FileSourceUnavailable()
            )
        )
    )
    monkeypatch.setattr(socket_events, 'file_service', service)

    handler.__wrapped__({
        'source_id': 'sftp-session:foreign',
        'request_id': 'file-operation:foreign',
        **payload,
    }, current_user=user)

    assert len(emitted) == 1
    emitted_event, emitted_payload = emitted[0]
    assert emitted_event == event
    assert emitted_payload['error'] == 'File source unavailable'
    assert emitted_payload['code'] == 'SOURCE_UNAVAILABLE'
    assert emitted_payload['source_id'] == 'sftp-session:foreign'
