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


class ChannelConstrainedPagingBackend(PagingBackend):
    def __init__(self, *listings):
        super().__init__(*listings)
        self.active_listing = None

    def open_directory_listing(self, source, path):
        if (
            self.active_listing is not None
            and self.active_listing.close_calls == 0
        ):
            return None, 'No channel slots available'
        listing, error = super().open_directory_listing(source, path)
        self.active_listing = listing
        return listing, error


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


class BlockingContinuationListing(RecordingListing):
    def __init__(self, pages):
        super().__init__(pages)
        self.continuation_started = Event()
        self.allow_continuation = Event()

    def read_page(self, page_size):
        if self.read_calls:
            self.continuation_started.set()
            assert self.allow_continuation.wait(2)
        return super().read_page(page_size)


class BlockingInitialPageListing(RecordingListing):
    def __init__(self, pages):
        super().__init__(pages)
        self.read_started = Event()
        self.allow_read = Event()

    def read_page(self, page_size):
        self.read_started.set()
        assert self.allow_read.wait(2)
        return super().read_page(page_size)


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


def test_directory_snapshot_cancel_requires_exact_cursor_owner_source_and_socket(
    monkeypatch,
):
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
        path='/srv',
        client_id='socket-a',
    )
    tampered = cursor[:-1] + ('0' if cursor[-1] != '0' else '1')

    for candidate, user_id, source_id, client_id in (
        (tampered, 7, source.source_id, 'socket-a'),
        (cursor, 8, source.source_id, 'socket-a'),
        (cursor, 7, 'sftp-session:other', 'socket-a'),
        (cursor, 7, source.source_id, 'socket-b'),
    ):
        assert service.cancel_directory_snapshot(
            candidate,
            user_id=user_id,
            source_id=source_id,
            client_id=client_id,
        ) is False
        assert listing.close_calls == 0

    assert service.cancel_directory_snapshot(
        cursor,
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is True
    assert listing.close_calls == 1
    assert service._directory_snapshots == {}
    assert service.cancel_directory_snapshot(
        cursor,
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is False
    assert listing.close_calls == 1


def test_directory_snapshot_cancel_waits_for_in_progress_exact_close(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = BlockingCloseListing([
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
        path='/srv',
        client_id='socket-a',
    )
    snapshot_id, _offset, _signature = service._parse_directory_cursor(
        cursor
    )
    state = service._directory_snapshots[snapshot_id]
    with service._directory_snapshot_lock:
        state['status'] = 'closing'

    cancellations = []
    cancellation = Thread(target=lambda: cancellations.append(
        service.cancel_directory_snapshot(
            cursor,
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    cancellation.start()
    cancellation.join(0.1)

    assert cancellation.is_alive()
    assert listing.close_calls == 0
    closer = Thread(target=lambda: service._close_directory_state(
        snapshot_id,
        state,
    ))
    closer.start()
    assert listing.close_started.wait(1)
    assert cancellation.is_alive()
    listing.allow_close.set()
    closer.join(2)
    cancellation.join(2)

    assert not closer.is_alive()
    assert not cancellation.is_alive()
    assert cancellations == [True]
    assert listing.close_calls == 1
    assert service._directory_snapshots == {}


def test_directory_request_cancel_requires_exact_request_owner_source_and_socket(
    monkeypatch,
):
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
    service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        client_id='socket-a',
        request_id='left:directory:1',
    )

    for request_id, user_id, source_id, client_id in (
        ('invalid request id', 7, source.source_id, 'socket-a'),
        ('left:directory:2', 7, source.source_id, 'socket-a'),
        ('left:directory:1', 8, source.source_id, 'socket-a'),
        ('left:directory:1', 7, 'sftp-session:other', 'socket-a'),
        ('left:directory:1', 7, source.source_id, 'socket-b'),
    ):
        assert service.cancel_directory_request(
            request_id,
            user_id=user_id,
            source_id=source_id,
            client_id=client_id,
        ) is False
        assert listing.close_calls == 0

    assert service.cancel_directory_request(
        'left:directory:1',
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is True
    assert listing.close_calls == 1
    assert service._directory_snapshots == {}
    assert service.cancel_directory_request(
        'left:directory:1',
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is False
    assert listing.close_calls == 1


def test_directory_request_cancel_does_not_cross_socket_snapshots(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    first = RecordingListing([[{'name': 'a'}], [{'name': 'b'}]])
    second = RecordingListing([[{'name': 'c'}], [{'name': 'd'}]])
    backend = PagingBackend(first, second)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    for client_id, path in (
        ('socket-a', '/one'),
        ('socket-b', '/two'),
    ):
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path=path,
            client_id=client_id,
            request_id='left:directory:shared',
        )

    assert service.cancel_directory_request(
        'left:directory:shared',
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is True
    assert first.close_calls == 1
    assert second.close_calls == 0
    assert len(service._directory_snapshots) == 1

    service.discard_directory_snapshots()
    assert second.close_calls == 1


def test_directory_request_cancel_marks_an_opening_snapshot_for_retirement(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = RecordingListing([[{'name': 'one'}], [{'name': 'two'}]])
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
            path='/srv',
            client_id='socket-a',
            request_id='left:directory:opening',
        )
    ))
    worker.start()
    assert backend.open_started.wait(1)

    assert service.cancel_directory_request(
        'left:directory:opening',
        user_id=7,
        source_id=source.source_id,
        client_id='socket-b',
    ) is False
    cancellations = []
    cancellation = Thread(target=lambda: cancellations.append(
        service.cancel_directory_request(
            'left:directory:opening',
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    cancellation.start()
    cancellation.join(0.1)
    assert tuple(service._directory_snapshots.values())[0]['status'] == (
        'cancelled'
    )
    assert cancellation.is_alive()
    assert listing.close_calls == 0

    backend.allow_open.set()
    worker.join(2)
    cancellation.join(2)

    assert not worker.is_alive()
    assert not cancellation.is_alive()
    assert cancellations == [True]
    assert results == [(None, 'Directory listing cancelled', None)]
    assert service._directory_snapshots == {}
    assert listing.close_calls == 1


def test_duplicate_opening_directory_cancels_do_not_add_waiters(monkeypatch):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = RecordingListing([[{'name': 'one'}], [{'name': 'two'}]])
    backend = BlockingOpenBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    worker = Thread(target=lambda: service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/srv',
        client_id='socket-a',
        request_id='left:directory:duplicates',
    ))
    worker.start()
    assert backend.open_started.wait(1)

    first_results = []
    first = Thread(target=lambda: first_results.append(
        service.cancel_directory_request(
            'left:directory:duplicates',
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    first.start()
    first.join(0.1)
    assert first.is_alive()

    duplicate_results = []
    duplicates = [
        Thread(target=lambda: duplicate_results.append(
            service.cancel_directory_request(
                'left:directory:duplicates',
                user_id=7,
                source_id=source.source_id,
                client_id='socket-a',
            )
        ))
        for _index in range(16)
    ]
    for duplicate in duplicates:
        duplicate.start()
    for duplicate in duplicates:
        duplicate.join(1)

    assert all(not duplicate.is_alive() for duplicate in duplicates)
    assert duplicate_results == [True] * 16
    assert first.is_alive()

    backend.allow_open.set()
    worker.join(2)
    first.join(2)
    assert not worker.is_alive()
    assert not first.is_alive()
    assert first_results == [True]
    assert listing.close_calls == 1


def test_duplicate_cursor_cancels_return_while_elected_close_is_slow(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = BlockingCloseListing([
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
        path='/srv',
        client_id='socket-a',
    )
    first_results = []
    first = Thread(target=lambda: first_results.append(
        service.cancel_directory_snapshot(
            cursor,
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    first.start()
    assert listing.close_started.wait(1)

    duplicate_results = []
    duplicates = [
        Thread(target=lambda: duplicate_results.append(
            service.cancel_directory_snapshot(
                cursor,
                user_id=7,
                source_id=source.source_id,
                client_id='socket-a',
            )
        ))
        for _index in range(16)
    ]
    for duplicate in duplicates:
        duplicate.start()
    for duplicate in duplicates:
        duplicate.join(1)

    assert all(not duplicate.is_alive() for duplicate in duplicates)
    assert duplicate_results == [True] * 16
    assert first.is_alive()

    listing.allow_close.set()
    first.join(2)
    assert not first.is_alive()
    assert first_results == [True]
    assert listing.close_calls == 1


def test_duplicate_cursor_cancels_return_while_terminal_page_closes(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = BlockingCloseListing([
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
        path='/srv',
        client_id='socket-a',
    )

    continuation_results = []
    continuation = Thread(target=lambda: continuation_results.append(
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path='/srv',
            cursor=cursor,
            client_id='socket-a',
        )
    ))
    continuation.start()
    assert listing.close_started.wait(1)

    duplicate_results = []
    duplicates = [
        Thread(target=lambda: duplicate_results.append(
            service.cancel_directory_snapshot(
                cursor,
                user_id=7,
                source_id=source.source_id,
                client_id='socket-a',
            )
        ))
        for _index in range(16)
    ]
    for duplicate in duplicates:
        duplicate.start()
    for duplicate in duplicates:
        duplicate.join(1)

    assert all(not duplicate.is_alive() for duplicate in duplicates)
    assert duplicate_results == [True] * 16
    assert continuation.is_alive()

    listing.allow_close.set()
    continuation.join(2)
    assert not continuation.is_alive()
    assert continuation_results == [([{'name': 'two'}], None, None)]
    assert listing.close_calls == 1


def test_directory_request_cancel_waits_for_initial_page_read_before_close(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = BlockingInitialPageListing([
        [{'name': 'one'}],
        [{'name': 'two'}],
    ])
    backend = PagingBackend(listing)
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    results = []
    worker = Thread(target=lambda: results.append(
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path='/srv',
            client_id='socket-a',
            request_id='left:directory:reading',
        )
    ))
    worker.start()
    assert listing.read_started.wait(1)

    cancellations = []
    cancellation = Thread(target=lambda: cancellations.append(
        service.cancel_directory_request(
            'left:directory:reading',
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    cancellation.start()
    cancellation.join(0.1)

    assert cancellation.is_alive()
    assert listing.close_calls == 0
    listing.allow_read.set()
    worker.join(2)
    cancellation.join(2)

    assert not worker.is_alive()
    assert not cancellation.is_alive()
    assert cancellations == [True]
    assert results == [(None, 'Directory listing cancelled', None)]
    assert service._directory_snapshots == {}
    assert listing.close_calls == 1


def test_directory_request_cancel_closes_before_fifo_replacement_opens(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    first_listing = RecordingListing([
        [{'name': 'one'}],
        [{'name': 'two'}],
    ])
    replacement_listing = RecordingListing([[{'name': 'replacement'}]])
    backend = ChannelConstrainedPagingBackend(
        first_listing,
        replacement_listing,
    )
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    first = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/old',
        client_id='socket-a',
        request_id='left:directory:old',
    )
    cancelled = service.cancel_directory_request(
        'left:directory:old',
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    )
    replacement = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/replacement',
        client_id='socket-a',
        request_id='left:directory:new',
    )

    assert first[0] == [{'name': 'one'}]
    assert first[1] is None
    assert first[2] is not None
    assert cancelled is True
    assert first_listing.close_calls == 1
    assert replacement == ([{'name': 'replacement'}], None, None)
    assert backend.calls == [
        ('open', source.source_id, '/old'),
        ('open', source.source_id, '/replacement'),
    ]
    assert replacement_listing.close_calls == 1


def test_directory_snapshot_cancel_racing_continuation_accepts_issued_cursor(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    listing = BlockingContinuationListing([
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
    continued = []
    cancelled = []
    continuation = Thread(target=lambda: continued.append(
        service.list_directory_page(
            source.source_id,
            user_id=7,
            path='/srv',
            cursor=cursor,
            client_id='socket-a',
        )
    ))
    continuation.start()
    assert listing.continuation_started.wait(1)
    cancellation = Thread(target=lambda: cancelled.append(
        service.cancel_directory_snapshot(
            cursor,
            user_id=7,
            source_id=source.source_id,
            client_id='socket-a',
        )
    ))
    cancellation.start()
    cancellation.join(0.1)
    assert cancellation.is_alive()

    duplicate_results = []
    duplicates = [
        Thread(target=lambda: duplicate_results.append(
            service.cancel_directory_snapshot(
                cursor,
                user_id=7,
                source_id=source.source_id,
                client_id='socket-a',
            )
        ))
        for _index in range(16)
    ]
    for duplicate in duplicates:
        duplicate.start()
    for duplicate in duplicates:
        duplicate.join(1)

    assert all(not duplicate.is_alive() for duplicate in duplicates)
    assert duplicate_results == [True] * 16

    listing.allow_continuation.set()
    continuation.join(2)
    cancellation.join(2)

    assert not continuation.is_alive()
    assert not cancellation.is_alive()
    assert cancelled == [True]
    assert continued[0][:2] == ([{'name': 'two'}], None)
    assert continued[0][2] is not None
    assert listing.close_calls == 1
    assert service._directory_snapshots == {}


def test_issued_cursor_cancel_closes_before_replacement_listing_opens(
    monkeypatch,
):
    import app.file_service as file_service_module

    monkeypatch.setattr(file_service_module, 'Timer', FakeTimer)
    first_listing = RecordingListing([
        [{'name': 'one'}],
        [{'name': 'two'}],
        [{'name': 'three'}],
    ])
    replacement_listing = RecordingListing([[{'name': 'replacement'}]])
    backend = ChannelConstrainedPagingBackend(
        first_listing,
        replacement_listing,
    )
    source = resolved_source(FileCapability.LIST, backend=backend)
    service = FileService(
        SimpleNamespace(resolve=lambda _source_id, _user_id: source)
    )
    _page, _error, first_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/old',
        client_id='socket-a',
    )
    continued, continuation_error, next_cursor = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/old',
        cursor=first_cursor,
        client_id='socket-a',
    )

    assert (continued, continuation_error) == ([{'name': 'two'}], None)
    assert next_cursor is not None
    assert service.cancel_directory_snapshot(
        first_cursor,
        user_id=7,
        source_id=source.source_id,
        client_id='socket-a',
    ) is True
    replacement = service.list_directory_page(
        source.source_id,
        user_id=7,
        path='/replacement',
        client_id='socket-a',
    )

    assert first_listing.close_calls == 1
    assert replacement == ([{'name': 'replacement'}], None, None)
    assert backend.calls == [
        ('open', source.source_id, '/old'),
        ('open', source.source_id, '/replacement'),
    ]
    assert replacement_listing.close_calls == 1


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
