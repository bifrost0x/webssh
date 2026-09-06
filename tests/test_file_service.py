from types import SimpleNamespace
from threading import Event, Thread

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


class RecordingListing:
    def __init__(self, pages):
        self.pages = list(pages)
        self.read_calls = []
        self.close_calls = 0

    def read_page(self, page_size):
        self.read_calls.append(page_size)
        page = self.pages.pop(0)
        return page, None, bool(self.pages)

    def close(self):
        self.close_calls += 1


class PagingBackend(RecordingBackend):
    def __init__(self, *listings):
        super().__init__()
        self.listings = list(listings)

    def open_directory_listing(self, source, path):
        self.calls.append(('open', source.source_id, path))
        return self.listings.pop(0), None


class BlockingOpenBackend(PagingBackend):
    def __init__(self, *listings):
        super().__init__(*listings)
        self.open_started = Event()
        self.allow_open = Event()

    def open_directory_listing(self, source, path):
        self.calls.append(('open', source.source_id, path))
        self.open_started.set()
        assert self.allow_open.wait(2)
        return self.listings.pop(0), None


class BlockingCloseListing(RecordingListing):
    def __init__(self, pages):
        super().__init__(pages)
        self.close_started = Event()
        self.allow_close = Event()

    def close(self):
        self.close_started.set()
        assert self.allow_close.wait(2)
        super().close()


class FakeTimer:
    def __init__(self, _interval, function, args):
        self.function = function
        self.args = args
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


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


def test_directory_pages_resume_one_backend_enumeration_with_opaque_cursor(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = RecordingListing([
        [{'name': 'one'}, {'name': 'two'}],
        [{'name': 'three'}],
    ])
    backend = PagingBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )

    first, error, cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        client_id='socket-a',
    )
    second, error2, next_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        cursor=cursor,
        client_id='socket-a',
    )

    assert error is None
    assert error2 is None
    assert first == [{'name': 'one'}, {'name': 'two'}]
    assert second == [{'name': 'three'}]
    assert isinstance(cursor, str) and cursor.startswith('v1.')
    assert next_cursor is None
    assert backend.calls == [('open', source.source_id, '/srv')]
    assert len(listing.read_calls) == 2
    assert listing.close_calls == 1


def test_directory_cursor_replay_tampering_and_binding_do_not_advance_listing(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = RecordingListing([
        [{'name': 'one'}],
        [{'name': 'two'}],
        [{'name': 'three'}],
    ])
    backend = PagingBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    _page, _error, cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        client_id='socket-a',
    )

    tampered = cursor[:-1] + ('0' if cursor[-1] != '0' else '1')
    for candidate, user_id, path, client_id in (
        (tampered, 7, '/srv', 'socket-a'),
        (cursor, 8, '/srv', 'socket-a'),
        (cursor, 7, '/other', 'socket-a'),
        (cursor, 7, '/srv', 'socket-b'),
    ):
        page, error, next_cursor = service.list_directory_page(
            source.source_id,
            user_id=user_id,
            path=path,
            cursor=candidate,
            client_id=client_id,
        )
        assert page is None
        assert error == 'Invalid or expired directory cursor'
        assert next_cursor is None

    page, error, next_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        cursor=cursor,
        client_id='socket-a',
    )
    assert error is None
    assert page == [{'name': 'two'}]
    assert len(listing.read_calls) == 2

    replay, replay_error, replay_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        cursor=cursor,
        client_id='socket-a',
    )
    assert replay is None
    assert replay_error == 'Invalid or expired directory cursor'
    assert replay_cursor is None
    assert len(listing.read_calls) == 2
    service.discard_directory_snapshots(user_id=7)
    assert listing.close_calls == 1


def test_directory_snapshot_expiry_closes_backend_listing(monkeypatch):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = RecordingListing([
        [{'name': 'one'}],
        [{'name': 'two'}],
    ])
    backend = PagingBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    _page, _error, cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/',
        client_id='socket-a',
    )
    snapshot_id, _offset, _signature = service._parse_directory_cursor(cursor)
    state = service._directory_snapshots[snapshot_id]

    service._expire_directory_snapshot(
        snapshot_id,
        state,
        state['last_used'],
    )

    assert service._directory_snapshots == {}
    assert listing.close_calls == 1
    page, error, next_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/',
        cursor=cursor,
        client_id='socket-a',
    )
    assert (page, error, next_cursor) == (
        None,
        'Invalid or expired directory cursor',
        None,
    )


def test_directory_snapshot_limits_evict_and_close_oldest_per_user(
    monkeypatch,
):
    import config
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_PER_USER', 1)
    first = RecordingListing([[{'name': 'a'}], [{'name': 'b'}]])
    second = RecordingListing([[{'name': 'c'}], [{'name': 'd'}]])
    backend = PagingBackend(first, second)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )

    service.list_directory_page(
        source.source_id, user_id=7, path='/one', client_id='socket-a'
    )
    service.list_directory_page(
        source.source_id, user_id=7, path='/two', client_id='socket-a'
    )

    assert first.close_calls == 1
    assert second.close_calls == 0
    assert len(service._directory_snapshots) == 1
    service.discard_directory_snapshots()
    assert second.close_calls == 1


def test_directory_snapshot_capacity_is_reserved_before_backend_open(
    monkeypatch,
):
    import config
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_PER_USER', 1)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_STATES', 1)
    listing = RecordingListing([[{'name': 'a'}], [{'name': 'b'}]])
    backend = BlockingOpenBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    results = []
    first = Thread(target=lambda: results.append(
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path='/one',
            client_id='socket-a',
        )
    ))
    first.start()
    assert backend.open_started.wait(1)

    blocked = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/two',
        client_id='socket-a',
    )

    assert blocked == (None, 'Too many active directory listings', None)
    assert backend.calls == [('open', source.source_id, '/one')]
    backend.allow_open.set()
    first.join(2)
    assert not first.is_alive()
    assert results[0][1] is None
    service.discard_directory_snapshots()
    assert listing.close_calls == 1


def test_directory_snapshot_capacity_remains_reserved_until_close_finishes(
    monkeypatch,
):
    import config
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_PER_USER', 1)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_STATES', 1)
    first_listing = BlockingCloseListing([
        [{'name': 'a'}],
        [{'name': 'b'}],
    ])
    second_listing = RecordingListing([[{'name': 'c'}]])
    backend = PagingBackend(first_listing, second_listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    _page, _error, cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/one',
        client_id='socket-a',
    )
    snapshot_id, _offset, _signature = service._parse_directory_cursor(cursor)
    state = service._directory_snapshots[snapshot_id]
    closer = Thread(target=lambda: service._expire_directory_snapshot(
        snapshot_id,
        state,
        state['last_used'],
    ))
    closer.start()
    assert first_listing.close_started.wait(1)

    blocked = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/two',
        client_id='socket-a',
    )

    assert blocked == (None, 'Too many active directory listings', None)
    assert backend.calls == [('open', source.source_id, '/one')]
    first_listing.allow_close.set()
    closer.join(2)
    assert not closer.is_alive()
    page, error, next_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/two',
        client_id='socket-a',
    )
    assert (page, error, next_cursor) == ([{'name': 'c'}], None, None)
    assert first_listing.close_calls == 1
    assert second_listing.close_calls == 1


def test_global_directory_capacity_does_not_evict_another_user(monkeypatch):
    import config
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_PER_USER', 2)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_STATES', 1)
    first_listing = RecordingListing([
        [{'name': 'a'}],
        [{'name': 'b'}],
    ])
    backend = PagingBackend(first_listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    page, error, cursor = service.list_directory_page(
        source.source_id,
        user_id=8,
        path='/owned-by-eight',
        client_id='socket-eight',
    )

    blocked = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/owned-by-seven',
        client_id='socket-seven',
    )

    assert page == [{'name': 'a'}]
    assert error is None
    assert cursor is not None
    assert blocked == (None, 'Too many active directory listings', None)
    assert backend.calls == [
        ('open', source.source_id, '/owned-by-eight'),
    ]
    assert first_listing.close_calls == 0
    service.discard_directory_snapshots(user_id=8)
    assert first_listing.close_calls == 1


def test_discard_cancels_opening_directory_snapshot(monkeypatch):
    import config
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_PER_USER', 1)
    monkeypatch.setattr(config, 'REMOTE_LISTING_SNAPSHOT_MAX_STATES', 1)
    listing = RecordingListing([[{'name': 'a'}], [{'name': 'b'}]])
    backend = BlockingOpenBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    results = []
    worker = Thread(target=lambda: results.append(
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path='/',
            client_id='socket-a',
        )
    ))
    worker.start()
    assert backend.open_started.wait(1)

    service.discard_directory_snapshots(user_id=7, client_id='socket-a')
    assert len(service._directory_snapshots) == 1
    backend.allow_open.set()
    worker.join(2)

    assert not worker.is_alive()
    assert results == [(None, 'Directory listing cancelled', None)]
    assert service._directory_snapshots == {}
    assert listing.close_calls == 1


def test_discard_directory_snapshots_is_scoped_to_socket(monkeypatch):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    first = RecordingListing([[{'name': 'a'}], [{'name': 'b'}]])
    second = RecordingListing([[{'name': 'c'}], [{'name': 'd'}]])
    backend = PagingBackend(first, second)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/one',
        client_id='socket-a',
    )
    service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/two',
        client_id='socket-b',
    )

    service.discard_directory_snapshots(
        user_id=7,
        client_id='socket-a',
    )

    assert first.close_calls == 1
    assert second.close_calls == 0
    assert len(service._directory_snapshots) == 1
    service.discard_directory_snapshots()
    assert second.close_calls == 1


def test_directory_pagination_has_no_eager_full_listing_fallback():
    backend = RecordingBackend()
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )

    result = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/',
        client_id='socket-a',
    )

    assert result == (None, 'Directory pagination unavailable', None)
    assert backend.calls == []
