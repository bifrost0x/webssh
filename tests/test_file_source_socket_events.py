from types import SimpleNamespace

import pytest

from app import socket_events
from app.file_service import FileService
from app.file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceUnavailable,
    ResolvedFileSource,
)
from app.smb_backend import NonAtomicOverwriteRequired


class ListingBackend:
    def __init__(self):
        self.calls = []

    def list_directory(self, source, path):
        self.calls.append((source.source_id, path))
        return [{'name': 'config.yml'}], None


def make_source(source_id, capabilities, backend, *, kind='sftp'):
    return ResolvedFileSource(
        descriptor=FileSourceDescriptor(
            source_id=source_id,
            kind=kind,
            label='Owned source',
            endpoint='host.test:22',
            protocol='SFTP',
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
        return {'exists': True, 'is_dir': False, 'size': 4}, None

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
    ):
        self.calls.append((
            'save', path, content, encoding, newline, allow_non_atomic,
        ))
        return True, None


def test_file_operation_handlers_use_one_source_service_boundary(app, monkeypatch):
    emitted, user = capture(monkeypatch)
    monkeypatch.setattr(
        socket_events,
        'log_file_upload',
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
    socket_events.handle_rename_file.__wrapped__({
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
        }, current_user=user)

    assert backend.calls == [
        ('mkdir', '/new'),
        ('rename', '/old', '/new', False),
        ('delete', '/old-tree', True, None, None),
        ('home',),
        ('exists', '/note.txt'),
        ('stat', '/note.txt'),
        ('preview', '/note.txt', 4096, 2, 10),
        ('edit', '/note.txt'),
        ('binary-preview', '/image.png', socket_events.config.MAX_EDITOR_FILE_SIZE),
        ('save', '/note.txt', 'saved', 'utf-8', 'lf', False),
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


def test_smb_editor_requires_structured_explicit_non_atomic_consent(
    app,
    monkeypatch,
):
    emitted, user = capture(monkeypatch)
    monkeypatch.setattr(
        socket_events,
        'log_file_upload',
        lambda *_args, **_kwargs: None,
    )

    class ConsentBackend(OperationBackend):
        def write_file_text(
            self,
            source,
            path,
            content,
            *,
            encoding,
            newline,
            allow_non_atomic=False,
        ):
            self.calls.append(('save', allow_non_atomic))
            if allow_non_atomic is not True:
                raise NonAtomicOverwriteRequired(
                    'Atomic replacement requires delete permission'
                )
            return True, None

    backend = ConsentBackend()
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
    }

    with app.test_request_context('/socket.io'):
        socket_events.handle_save_file.__wrapped__(
            {**common, 'allow_non_atomic': 'true'},
            current_user=user,
        )
        socket_events.handle_save_file.__wrapped__(
            {**common, 'allow_non_atomic': True},
            current_user=user,
        )

    assert backend.calls == [('save', False), ('save', True)]
    assert emitted[0] == ('error', {
        'error': 'Atomic replacement needs delete permission. '
                 'A direct overwrite is less resilient to interruption.',
        'code': 'SMB_NON_ATOMIC_OVERWRITE_REQUIRED',
        'can_retry_non_atomic': True,
        'operation': 'save_file',
        'source_id': 'smb-quick:owned',
        'request_id': 'save:smb:1',
        'path': '/note.txt',
    })
    assert emitted[1] == ('file_saved', {
        'path': '/note.txt',
        'source_id': 'smb-quick:owned',
        'request_id': 'save:smb:1',
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
