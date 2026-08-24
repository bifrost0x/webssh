"""Disposable end-to-end checks against the encrypted Samba lab."""

from __future__ import annotations

import hashlib
import os
from threading import Event

from app.file_sources import ResolvedFileSource
from app.remote_transfer import TransferBudget, copy_remote_entry
from app.smb_backend import NonAtomicOverwriteRequired, SMBBackend
from app.smb_pool import SMBConnectionPool, SMBSourceError


def _required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required for the disposable SMB lab')
    return value


def run_checks():
    if os.environ.get('SMB_INTEGRATION') != '1':
        raise RuntimeError('Refusing to run outside the disposable SMB lab')

    host = _required('SMB_INTEGRATION_HOST')
    username = _required('SMB_INTEGRATION_USER')
    password = _required('SMB_INTEGRATION_PASSWORD')
    pool = SMBConnectionPool(allowed_targets=(host,), cleanup_interval=60)
    backend = SMBBackend(pool)

    try:
        try:
            pool.create_source(
                host=host,
                share='Docs',
                domain='',
                username=username,
                password='definitely-wrong',
                user_id='wrong-password-test',
                cancel_event=Event(),
            )
        except SMBSourceError as exc:
            assert exc.public_code == 'AUTHENTICATION_REQUIRED'
        else:
            raise AssertionError('wrong SMB password unexpectedly authenticated')

        descriptor = pool.create_source(
            host=host,
            share='Docs',
            domain='',
            username=username,
            password=password,
            user_id='integration-user',
            cancel_event=Event(),
        )
        assert pool.get_source(descriptor.source_id, 'other-user') is None
        source = ResolvedFileSource(
            descriptor=descriptor,
            user_id='integration-user',
            handle_id=descriptor.source_id.split(':', 1)[1],
            backend=backend,
        )

        listing, error = backend.list_directory(source, '/')
        assert error is None, error
        names = {item['name'] for item in listing}
        assert {'hello.txt', 'Überblick.txt'}.issubset(names)
        link = next((item for item in listing if item['name'] == 'escape-link'), None)
        if link is not None:
            assert link['is_dir'] is False

        payload = ('SMB 3.1.1 encrypted round trip — ' * 4096).encode('utf-8')
        with backend.open_atomic_writer(
            source,
            '/round-trip.bin',
            replace=False,
            cancel_event=Event(),
        ) as remote_file:
            for offset in range(0, len(payload), 65536):
                remote_file.write(payload[offset:offset + 65536])

        with backend.open_reader(source, '/round-trip.bin') as remote_file:
            downloaded = b''.join(iter(lambda: remote_file.read(65536), b''))
        assert hashlib.sha256(downloaded).digest() == hashlib.sha256(payload).digest()

        unicode_stat, error = backend.get_file_stat(source, '/Überblick.txt')
        assert error is None and unicode_stat['size'] > 0

        with backend.open_atomic_writer(
            source,
            '/atomic-edit.txt',
            replace=False,
            cancel_event=Event(),
        ) as remote_file:
            remote_file.write(b'before')
        assert backend.write_file_text(
            source,
            '/atomic-edit.txt',
            'after',
            encoding='utf-8',
            newline='lf',
        ) == (True, None)
        with backend.open_reader(source, '/atomic-edit.txt') as remote_file:
            assert remote_file.read() == b'after'

        protected_path = '/atomic-denied/replace-denied.txt'
        with backend.open_reader(source, protected_path) as remote_file:
            protected_original = remote_file.read()
        try:
            backend.write_file_text(
                source,
                protected_path,
                'direct overwrite requires consent',
                encoding='utf-8',
                newline='lf',
            )
        except NonAtomicOverwriteRequired:
            pass
        else:
            raise AssertionError(
                'delete-denied edit did not require explicit consent'
            )
        with backend.open_reader(source, protected_path) as remote_file:
            assert remote_file.read() == protected_original
        try:
            backend.write_file_text(
                source,
                protected_path,
                'legacy direct overwrite request',
                encoding='utf-8',
                newline='lf',
                allow_non_atomic=True,
            )
        except NonAtomicOverwriteRequired:
            pass
        else:
            raise AssertionError('legacy consent bypassed atomic replacement')
        with backend.open_reader(source, protected_path) as remote_file:
            assert remote_file.read() == protected_original

        assert backend.mkdir(source, '/recursive-source') == (True, None)
        assert backend.mkdir(source, '/recursive-source/nested') == (True, None)
        with backend.open_atomic_writer(
            source,
            '/recursive-source/nested/input.bin',
            replace=False,
            cancel_event=Event(),
        ) as remote_file:
            remote_file.write(payload)

        entries = list(backend.iter_tree(
            source,
            '/recursive-source',
            budget=TransferBudget(max_bytes=len(payload) * 2, max_members=100),
            cancel_event=Event(),
            follow_links=False,
        ))
        assert [entry['path'] for entry in entries] == [
            '/recursive-source/nested',
            '/recursive-source/nested/input.bin',
        ]

        copy_result = copy_remote_entry(
            source,
            '/recursive-source/nested/input.bin',
            source,
            '/copied-from-remote.bin',
            'error',
            TransferBudget(max_bytes=len(payload), max_members=10),
            Event(),
            None,
        )
        assert copy_result.bytes_transferred == len(payload)
        with backend.open_reader(source, '/copied-from-remote.bin') as remote_file:
            copied = b''.join(iter(lambda: remote_file.read(65536), b''))
        assert hashlib.sha256(copied).digest() == hashlib.sha256(payload).digest()

        denied, error = backend.list_directory(source, '/denied')
        assert denied is None and error == 'Permission denied', (denied, error)

        assert backend.delete(
            source,
            '/round-trip.bin',
            recursive=False,
            budget=None,
            cancel_event=Event(),
        ) == (True, None)
        assert backend.delete(
            source,
            '/atomic-edit.txt',
            recursive=False,
            budget=None,
            cancel_event=Event(),
        ) == (True, None)
        assert backend.delete(
            source,
            '/copied-from-remote.bin',
            recursive=False,
            budget=None,
            cancel_event=Event(),
        ) == (True, None)
        assert backend.delete(
            source,
            '/recursive-source',
            recursive=True,
            budget=TransferBudget(max_bytes=len(payload) * 2, max_members=100),
            cancel_event=Event(),
        ) == (True, None)
        listing, error = backend.list_directory(source, '/')
        assert error is None
        assert not any('.webssh-write-' in item['name'] for item in listing)

        live = pool.get_source(descriptor.source_id, 'integration-user')
        live.raw_connection = getattr(live.session, 'raw_connection')
        live.raw_connection.transport.close()
        assert pool.get_source(descriptor.source_id, 'integration-user') is None
    finally:
        pool.close_all_sources()


if __name__ == '__main__':
    run_checks()
    print('SMB integration checks passed')
