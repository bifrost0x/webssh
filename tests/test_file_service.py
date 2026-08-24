from types import SimpleNamespace

import pytest

from app.file_service import FileService
from app.file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceKind,
    FileSourceUnavailable,
    ResolvedFileSource,
)


class RecordingBackend:
    def __init__(self):
        self.calls = []

    def list_directory(self, source, path):
        self.calls.append(('list', source.source_id, path))
        return [{'name': 'config.yml'}], None


def resolved_source(*capabilities, backend=None):
    backend = backend or RecordingBackend()
    return ResolvedFileSource(
        descriptor=FileSourceDescriptor(
            source_id='sftp-session:owned',
            kind='sftp',
            label='Owned source',
            endpoint='host.test:22',
            protocol='SFTP',
            capabilities=capabilities,
            ephemeral=False,
            security={},
        ),
        user_id='7',
        handle_id='owned',
        backend=backend,
    )


def test_file_service_resolves_ownership_and_capability_before_backend_call():
    backend = RecordingBackend()
    source = resolved_source(FileCapability.LIST, backend=backend)
    resolver = SimpleNamespace(resolve=lambda source_id, user_id: source)
    service = FileService(resolver)

    result = service.list_directory(
        'sftp-session:owned',
        user_id=7,
        path='/etc',
    )

    assert result == ([{'name': 'config.yml'}], None)
    assert backend.calls == [('list', 'sftp-session:owned', '/etc')]


def test_file_service_rejects_missing_capability_before_backend_call():
    backend = RecordingBackend()
    source = resolved_source(FileCapability.READ, backend=backend)
    resolver = SimpleNamespace(resolve=lambda source_id, user_id: source)
    service = FileService(resolver)

    with pytest.raises(FileSourceUnavailable) as exc:
        service.list_directory('sftp-session:owned', user_id=7, path='/etc')

    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'
    assert backend.calls == []


def test_file_service_preserves_uniform_resolver_failure():
    def unavailable(_source_id, _user_id):
        raise FileSourceUnavailable()

    service = FileService(SimpleNamespace(resolve=unavailable))

    with pytest.raises(FileSourceUnavailable) as exc:
        service.list_directory('sftp-session:foreign', user_id=7, path='/')

    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'
    assert str(exc.value) == 'File source unavailable'


def test_recursive_delete_requires_recursive_capability_before_backend_call():
    backend = RecordingBackend()
    backend.delete = lambda *_args, **_kwargs: backend.calls.append('delete')
    source = resolved_source(FileCapability.DELETE, backend=backend)
    resolver = SimpleNamespace(resolve=lambda source_id, user_id: source)
    service = FileService(resolver)

    with pytest.raises(FileSourceUnavailable):
        service.delete('smb-quick:owned', user_id=7, path='/reports')

    assert backend.calls == []
