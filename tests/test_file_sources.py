from types import SimpleNamespace

import pytest

from app.file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceKind,
    FileSourceResolver,
    FileSourceUnavailable,
    SourceHoldSet,
    make_source_id,
    parse_source_id,
)


ALL_KINDS = (
    FileSourceKind.SFTP_SESSION,
    FileSourceKind.SFTP_QUICK,
    FileSourceKind.SMB_QUICK,
)


def descriptor(source_id='sftp-session:owned', *, security=None):
    return FileSourceDescriptor(
        source_id=source_id,
        kind='sftp',
        label='operator@example.test',
        endpoint='example.test:22',
        protocol='SFTP',
        capabilities=(FileCapability.LIST, FileCapability.READ),
        ephemeral=False,
        security=security or {'host_key_verified': True},
    )


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_source_id_round_trip_preserves_kind_and_opaque_handle(kind):
    source_id = make_source_id(kind, '550e8400-e29b-41d4-a716-446655440000')

    assert parse_source_id(source_id) == (
        kind,
        '550e8400-e29b-41d4-a716-446655440000',
    )


@pytest.mark.parametrize(
    'value',
    [
        None,
        '',
        'ssh:x',
        'sftp-session:',
        'smb-quick:../x',
        'smb-quick:x:y',
        'sftp-quick: space',
        f"sftp-quick:{'x' * 129}",
    ],
)
def test_parse_source_id_rejects_noncanonical_values(value):
    with pytest.raises(FileSourceUnavailable) as exc:
        parse_source_id(value)

    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'
    assert str(exc.value) == 'File source unavailable'


@pytest.mark.parametrize('handle_id', [None, '', '../x', 'x:y', 'x y'])
def test_make_source_id_rejects_unsafe_handles(handle_id):
    with pytest.raises(FileSourceUnavailable):
        make_source_id(FileSourceKind.SFTP_SESSION, handle_id)


def test_descriptor_exposes_only_public_fields_and_freezes_nested_values():
    security = {'host_key_verified': True}
    source = descriptor(security=security)
    security['host_key_verified'] = False

    assert source.to_public_dict() == {
        'source_id': 'sftp-session:owned',
        'kind': 'sftp',
        'label': 'operator@example.test',
        'endpoint': 'example.test:22',
        'protocol': 'SFTP',
        'capabilities': ['list', 'read'],
        'ephemeral': False,
        'security': {'host_key_verified': True},
    }
    with pytest.raises(TypeError):
        source.security['host_key_verified'] = False
    with pytest.raises(AttributeError):
        source.label = 'changed'


def test_smb_audit_identity_separates_host_and_share_without_credentials():
    from app.file_sources import file_source_audit_identity

    smb_descriptor = FileSourceDescriptor(
        source_id='smb-quick:owned',
        kind='smb',
        label='Docs on nas.example',
        endpoint='nas.example/Docs',
        protocol='SMB 3.1.1',
        capabilities=(FileCapability.READ,),
        ephemeral=True,
        security={'encrypted': True},
    )

    identity = file_source_audit_identity(
        SimpleNamespace(descriptor=smb_descriptor)
    )

    assert identity == {
        'source_kind': 'smb',
        'target_host': 'nas.example',
        'share': 'Docs',
    }
    assert 'username' not in identity
    assert 'password' not in identity


def test_resolver_returns_owned_source_with_registered_backend():
    backend = object()

    def lookup(handle_id, user_id):
        if (handle_id, user_id) == ('owned', '7'):
            return descriptor()
        return None

    resolver = FileSourceResolver(
        source_lookups={FileSourceKind.SFTP_SESSION: lookup},
        backends={FileSourceKind.SFTP_SESSION: backend},
    )

    resolved = resolver.resolve('sftp-session:owned', user_id=7)

    assert resolved.source_id == 'sftp-session:owned'
    assert resolved.kind is FileSourceKind.SFTP_SESSION
    assert resolved.handle_id == 'owned'
    assert resolved.user_id == '7'
    assert resolved.descriptor == descriptor()
    assert resolved.backend is backend


def test_resolver_hides_foreign_and_missing_sources():
    def lookup(handle_id, user_id):
        if (handle_id, user_id) == ('foreign', 'owner-b'):
            return descriptor('sftp-session:foreign')
        return None

    resolver = FileSourceResolver(
        source_lookups={FileSourceKind.SFTP_SESSION: lookup},
        backends={FileSourceKind.SFTP_SESSION: object()},
    )

    errors = []
    for source_id in ('sftp-session:foreign', 'sftp-session:missing'):
        with pytest.raises(FileSourceUnavailable) as exc:
            resolver.resolve(source_id, user_id='owner-a')
        errors.append((exc.value.public_code, str(exc.value)))

    assert errors == [
        ('SOURCE_UNAVAILABLE', 'File source unavailable'),
        ('SOURCE_UNAVAILABLE', 'File source unavailable'),
    ]


def test_resolver_fails_closed_for_unregistered_backend_and_mismatched_descriptor():
    without_backend = FileSourceResolver(
        source_lookups={
            FileSourceKind.SFTP_SESSION: lambda _handle, _user: descriptor()
        },
    )
    mismatched = FileSourceResolver(
        source_lookups={
            FileSourceKind.SFTP_SESSION: lambda _handle, _user: descriptor(
                'sftp-session:different'
            )
        },
        backends={FileSourceKind.SFTP_SESSION: object()},
    )

    for resolver in (without_backend, mismatched):
        with pytest.raises(FileSourceUnavailable) as exc:
            resolver.resolve('sftp-session:owned', user_id='7')
        assert exc.value.public_code == 'SOURCE_UNAVAILABLE'


def test_owns_checks_ownership_without_requiring_a_backend():
    resolver = FileSourceResolver(
        source_lookups={
            FileSourceKind.SFTP_SESSION: (
                lambda handle, user: descriptor()
                if (handle, user) == ('owned', '7')
                else None
            )
        },
    )

    assert resolver.owns('sftp-session:owned', 7) is True
    assert resolver.owns('sftp-session:owned', 8) is False
    assert resolver.owns('sftp-session:missing', 7) is False
    assert resolver.owns('not-a-source', 7) is False


def test_terminal_ownership_uses_the_namespaced_file_source_resolver(monkeypatch):
    from app import socket_events

    calls = []
    fake_resolver = SimpleNamespace(
        owns=lambda source_id, user_id: calls.append((source_id, user_id)) or True
    )
    monkeypatch.setattr(socket_events, 'file_source_resolver', fake_resolver)

    assert socket_events.verify_session_ownership('session-a', 7) is True
    assert calls == [('sftp-session:session-a', 7)]


def test_source_hold_release_is_idempotent_and_releases_every_source():
    released = []
    holds = SourceHoldSet(
        ('sftp-quick:source-a', 'sftp-quick:source-b'),
        (
            lambda: released.append('source-a'),
            lambda: released.append('source-b'),
        ),
    )

    assert holds.release() is True
    assert holds.release() is False
    assert released == ['source-b', 'source-a']


def test_resolver_acquires_owned_transfer_holds_atomically():
    acquired = []
    released = []

    def lookup(handle_id, user_id):
        if user_id != '7':
            return None
        return descriptor(f'sftp-session:{handle_id}')

    def acquire(handle_id, user_id):
        acquired.append((handle_id, user_id))
        return lambda: released.append(handle_id)

    resolver = FileSourceResolver(
        source_lookups={FileSourceKind.SFTP_SESSION: lookup},
        backends={FileSourceKind.SFTP_SESSION: object()},
        hold_acquirers={FileSourceKind.SFTP_SESSION: acquire},
    )

    holds = resolver.acquire_transfer_holds(
        7,
        ('sftp-session:source-a', 'sftp-session:source-b'),
    )

    assert holds.source_ids == (
        'sftp-session:source-a',
        'sftp-session:source-b',
    )
    assert acquired == [('source-a', '7'), ('source-b', '7')]
    assert holds.release() is True
    assert released == ['source-b', 'source-a']


def test_resolver_rolls_back_first_hold_when_second_source_is_unavailable():
    released = []

    def lookup(handle_id, user_id):
        if user_id == '7':
            return descriptor(f'sftp-session:{handle_id}')
        return None

    def acquire(handle_id, _user_id):
        if handle_id == 'source-b':
            raise FileSourceUnavailable()
        return lambda: released.append(handle_id)

    resolver = FileSourceResolver(
        source_lookups={FileSourceKind.SFTP_SESSION: lookup},
        backends={FileSourceKind.SFTP_SESSION: object()},
        hold_acquirers={FileSourceKind.SFTP_SESSION: acquire},
    )

    with pytest.raises(FileSourceUnavailable):
        resolver.acquire_transfer_holds(
            7,
            ('sftp-session:source-a', 'sftp-session:source-b'),
        )

    assert released == ['source-a']


def test_resolver_rejects_foreign_transfer_source_before_acquiring_hold():
    acquired = []
    resolver = FileSourceResolver(
        source_lookups={
            FileSourceKind.SFTP_SESSION: lambda _handle, _user: None
        },
        backends={FileSourceKind.SFTP_SESSION: object()},
        hold_acquirers={
            FileSourceKind.SFTP_SESSION: (
                lambda handle, user: acquired.append((handle, user))
            )
        },
    )

    with pytest.raises(FileSourceUnavailable):
        resolver.acquire_transfer_holds(7, ('sftp-session:foreign',))

    assert acquired == []
