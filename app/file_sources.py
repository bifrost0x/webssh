"""Owned, protocol-neutral file sources for the browser file workspace."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
import re
import threading
from types import MappingProxyType
from typing import Any

from .file_backend import FileBackend


class FileSourceKind(StrEnum):
    SFTP_SESSION = 'sftp-session'
    SFTP_QUICK = 'sftp-quick'
    SMB_QUICK = 'smb-quick'


class FileCapability(StrEnum):
    LIST = 'list'
    READ = 'read'
    WRITE = 'write'
    MKDIR = 'mkdir'
    RENAME = 'rename'
    DELETE = 'delete'
    PREVIEW = 'preview'
    EDIT = 'edit'
    RECURSIVE = 'recursive'
    REMOTE_TRANSFER = 'remote-transfer'


class FileSourceUnavailable(Exception):
    """Uniform public failure for invalid, missing, or foreign sources."""

    public_code = 'SOURCE_UNAVAILABLE'

    def __init__(self):
        super().__init__('File source unavailable')


_HANDLE_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z', re.ASCII)
_SOURCE_PROTOCOL = {
    FileSourceKind.SFTP_SESSION: 'sftp',
    FileSourceKind.SFTP_QUICK: 'sftp',
    FileSourceKind.SMB_QUICK: 'smb',
}
_PUBLIC_SECURITY_KEYS = frozenset({
    'encrypted',
    'host_key_verified',
    'secure_negotiate',
    'signed',
})
_PUBLIC_ACCESS_KEYS = frozenset({
    'list',
    'create_file',
    'create_directory',
    'delete_children',
})
_PUBLIC_ACCESS_STATES = frozenset({'granted', 'denied', 'unknown'})
SFTP_CAPABILITIES = (
    FileCapability.LIST,
    FileCapability.READ,
    FileCapability.WRITE,
    FileCapability.MKDIR,
    FileCapability.RENAME,
    FileCapability.DELETE,
    FileCapability.PREVIEW,
    FileCapability.EDIT,
    FileCapability.RECURSIVE,
    FileCapability.REMOTE_TRANSFER,
)


def _unavailable() -> FileSourceUnavailable:
    return FileSourceUnavailable()


def _validated_handle(handle_id: Any) -> str:
    if not isinstance(handle_id, str) or not _HANDLE_PATTERN.fullmatch(handle_id):
        raise _unavailable()
    return handle_id


def make_source_id(kind: FileSourceKind, handle_id: str) -> str:
    """Build one canonical namespaced source identifier."""
    if not isinstance(kind, FileSourceKind):
        raise _unavailable()
    return f'{kind.value}:{_validated_handle(handle_id)}'


def parse_source_id(source_id: str) -> tuple[FileSourceKind, str]:
    """Parse a source identifier without exposing why validation failed."""
    if not isinstance(source_id, str) or source_id.count(':') != 1:
        raise _unavailable()
    raw_kind, handle_id = source_id.split(':', 1)
    try:
        kind = FileSourceKind(raw_kind)
    except ValueError as exc:
        raise _unavailable() from exc
    return kind, _validated_handle(handle_id)


def _validated_public_text(value: Any, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError('invalid public file source text')
    return value


@dataclass(frozen=True)
class FileSourceDescriptor:
    """The complete and credential-free source representation sent to clients."""

    source_id: str
    kind: str
    label: str
    endpoint: str
    protocol: str
    capabilities: tuple[FileCapability, ...]
    ephemeral: bool
    security: Mapping[str, bool] = field(default_factory=dict)
    access: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self):
        source_kind, _handle_id = parse_source_id(self.source_id)
        expected_kind = _SOURCE_PROTOCOL[source_kind]
        if self.kind != expected_kind:
            raise ValueError('descriptor kind does not match source id')

        object.__setattr__(self, 'label', _validated_public_text(self.label))
        object.__setattr__(self, 'endpoint', _validated_public_text(self.endpoint))
        object.__setattr__(self, 'protocol', _validated_public_text(self.protocol, maximum=64))

        capabilities = tuple(FileCapability(value) for value in self.capabilities)
        if len(set(capabilities)) != len(capabilities):
            raise ValueError('duplicate file source capability')
        object.__setattr__(self, 'capabilities', capabilities)

        security = dict(self.security)
        if not set(security).issubset(_PUBLIC_SECURITY_KEYS):
            raise ValueError('unsupported public security field')
        if any(not isinstance(value, bool) for value in security.values()):
            raise ValueError('security fields must be boolean')
        object.__setattr__(self, 'security', MappingProxyType(security))

        access = dict(self.access)
        if not set(access).issubset(_PUBLIC_ACCESS_KEYS):
            raise ValueError('unsupported public access field')
        if any(value not in _PUBLIC_ACCESS_STATES for value in access.values()):
            raise ValueError('unsupported public access state')
        object.__setattr__(self, 'access', MappingProxyType(access))

        if not isinstance(self.ephemeral, bool):
            raise ValueError('ephemeral must be boolean')

    def to_public_dict(self) -> dict[str, Any]:
        return {
            'source_id': self.source_id,
            'kind': self.kind,
            'label': self.label,
            'endpoint': self.endpoint,
            'protocol': self.protocol,
            'capabilities': [capability.value for capability in self.capabilities],
            'ephemeral': self.ephemeral,
            'security': dict(self.security),
            'access': dict(self.access),
        }


@dataclass(frozen=True)
class ResolvedFileSource:
    """Server-only source details after ownership has been revalidated."""

    descriptor: FileSourceDescriptor
    user_id: str
    handle_id: str
    backend: FileBackend

    @property
    def source_id(self) -> str:
        return self.descriptor.source_id

    @property
    def kind(self) -> FileSourceKind:
        kind, _handle_id = parse_source_id(self.source_id)
        return kind


def file_source_audit_identity(source) -> dict[str, str | None]:
    """Return credential-free, structured target fields for audit records."""
    descriptor = source.descriptor
    if descriptor.kind == 'smb':
        target_host, separator, share = descriptor.endpoint.rpartition('/')
        if not separator or not target_host or not share:
            raise _unavailable()
        return {
            'source_kind': 'smb',
            'target_host': target_host,
            'share': share,
        }
    return {
        'source_kind': 'sftp',
        'target_host': descriptor.endpoint,
        'share': None,
    }


SourceLookup = Callable[[str, str], FileSourceDescriptor | None]
SourceHoldAcquirer = Callable[[str, str], Callable[[], None] | None]


class SourceHoldSet:
    """An idempotent group of source-lifetime holds."""

    __slots__ = ('_source_ids', '_release_callbacks', '_lock', '_released')

    def __init__(self, source_ids, release_callbacks=()):
        self._source_ids = tuple(source_ids)
        self._release_callbacks = tuple(release_callbacks)
        self._lock = threading.Lock()
        self._released = False

    @property
    def source_ids(self) -> tuple[str, ...]:
        return self._source_ids

    @property
    def released(self) -> bool:
        with self._lock:
            return self._released

    def release(self) -> bool:
        """Release all holds once, even if one callback fails."""
        with self._lock:
            if self._released:
                return False
            self._released = True
            callbacks = self._release_callbacks

        first_error = None
        for callback in reversed(callbacks):
            try:
                callback()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
        return True


def _canonical_user_id(user_id: int | str) -> str:
    if isinstance(user_id, bool) or user_id is None:
        raise _unavailable()
    value = str(user_id)
    if not value or len(value) > 128 or value != value.strip():
        raise _unavailable()
    return value


def _sftp_descriptor(
    kind: FileSourceKind,
    handle_id: str,
    *,
    host: Any,
    port: Any,
    username: Any,
    display_name: Any = None,
) -> FileSourceDescriptor:
    safe_host = str(host or 'unknown')
    safe_port = str(port or 22)
    safe_username = str(username or 'unknown')
    label = str(display_name) if display_name else f'{safe_username}@{safe_host}'
    return FileSourceDescriptor(
        source_id=make_source_id(kind, handle_id),
        kind='sftp',
        label=label,
        endpoint=f'{safe_host}:{safe_port}',
        protocol='SFTP',
        capabilities=SFTP_CAPABILITIES,
        ephemeral=kind is FileSourceKind.SFTP_QUICK,
        security={'host_key_verified': True},
    )


def _lookup_sftp_session(handle_id: str, user_id: str):
    from . import ssh_manager
    from .models import SSHSession

    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(handle_id)
        if session and session.get('user_id') is not None:
            if str(session.get('user_id')) != user_id:
                return None
            metadata = dict(session)
        else:
            metadata = None

    if metadata is not None:
        return _sftp_descriptor(
            FileSourceKind.SFTP_SESSION,
            handle_id,
            host=metadata.get('host'),
            port=metadata.get('port'),
            username=metadata.get('username'),
            display_name=metadata.get('display_name'),
        )

    ssh_session = SSHSession.query.filter_by(session_id=handle_id).first()
    if ssh_session is None or str(ssh_session.user_id) != user_id:
        return None
    return _sftp_descriptor(
        FileSourceKind.SFTP_SESSION,
        handle_id,
        host=ssh_session.host,
        port=ssh_session.port,
        username=ssh_session.username,
        display_name=ssh_session.display_name,
    )


def _lookup_sftp_quick(handle_id: str, user_id: str):
    from . import connection_pool

    info = connection_pool.temp_connection_pool.get_connection_info(handle_id)
    if info is None or str(info.get('user_id')) != user_id:
        return None
    return _sftp_descriptor(
        FileSourceKind.SFTP_QUICK,
        handle_id,
        host=info.get('host'),
        port=info.get('port'),
        username=info.get('username'),
    )


def _acquire_sftp_quick_hold(handle_id: str, user_id: str):
    from . import connection_pool

    pool = connection_pool.temp_connection_pool
    if not pool.acquire_hold(handle_id, user_id):
        raise _unavailable()
    return lambda: pool.release_hold(handle_id, user_id)


def _lookup_smb_quick(handle_id: str, user_id: str):
    from . import smb_pool

    source = smb_pool.smb_connection_pool.get_source(handle_id, user_id)
    return source.descriptor if source is not None else None


def _acquire_smb_quick_hold(handle_id: str, user_id: str):
    from . import smb_pool

    pool = smb_pool.smb_connection_pool
    if not pool.acquire_hold(handle_id, user_id):
        raise _unavailable()
    return lambda: pool.release_hold(handle_id, user_id)


class FileSourceResolver:
    """Resolve opaque source IDs through a fresh ownership check every time."""

    def __init__(
        self,
        *,
        source_lookups: Mapping[FileSourceKind, SourceLookup] | None = None,
        backends: Mapping[FileSourceKind, FileBackend] | None = None,
        hold_acquirers: Mapping[
            FileSourceKind, SourceHoldAcquirer
        ] | None = None,
    ):
        self._lock = threading.RLock()
        use_default_source_lookups = source_lookups is None
        if use_default_source_lookups:
            source_lookups = {
                FileSourceKind.SFTP_SESSION: _lookup_sftp_session,
                FileSourceKind.SFTP_QUICK: _lookup_sftp_quick,
                FileSourceKind.SMB_QUICK: _lookup_smb_quick,
            }
        self._source_lookups = dict(source_lookups)
        self._backends = dict(backends) if backends is not None else {}
        if hold_acquirers is None:
            hold_acquirers = (
                {
                    FileSourceKind.SFTP_QUICK: _acquire_sftp_quick_hold,
                    FileSourceKind.SMB_QUICK: _acquire_smb_quick_hold,
                }
                if use_default_source_lookups
                else {}
            )
        self._hold_acquirers = dict(hold_acquirers)

    def register_source_kind(
        self,
        kind: FileSourceKind,
        *,
        lookup: SourceLookup,
        backend: FileBackend,
        hold_acquirer: SourceHoldAcquirer | None = None,
    ) -> None:
        if not isinstance(kind, FileSourceKind) or not callable(lookup) or backend is None:
            raise ValueError('invalid file source registration')
        with self._lock:
            self._source_lookups[kind] = lookup
            self._backends[kind] = backend
            if hold_acquirer is None:
                self._hold_acquirers.pop(kind, None)
            else:
                self._hold_acquirers[kind] = hold_acquirer

    def register_backend(self, kind: FileSourceKind, backend: FileBackend) -> None:
        if not isinstance(kind, FileSourceKind) or backend is None:
            raise ValueError('invalid file backend registration')
        with self._lock:
            self._backends[kind] = backend

    def _owned_descriptor(
        self,
        source_id: str,
        user_id: int | str,
    ) -> tuple[FileSourceKind, str, str, FileSourceDescriptor]:
        kind, handle_id = parse_source_id(source_id)
        canonical_user_id = _canonical_user_id(user_id)
        with self._lock:
            lookup = self._source_lookups.get(kind)
        if lookup is None:
            raise _unavailable()
        try:
            descriptor = lookup(handle_id, canonical_user_id)
        except Exception as exc:
            raise _unavailable() from exc
        if not isinstance(descriptor, FileSourceDescriptor):
            raise _unavailable()
        if descriptor.source_id != source_id or descriptor.kind != _SOURCE_PROTOCOL[kind]:
            raise _unavailable()
        return kind, handle_id, canonical_user_id, descriptor

    def owns(self, source_id: str, user_id: int | str) -> bool:
        """Return only an ownership decision, including for non-file SSH callers."""
        try:
            self._owned_descriptor(source_id, user_id)
        except FileSourceUnavailable:
            return False
        return True

    def resolve(self, source_id: str, user_id: int | str) -> ResolvedFileSource:
        kind, handle_id, canonical_user_id, descriptor = self._owned_descriptor(
            source_id,
            user_id,
        )
        with self._lock:
            backend = self._backends.get(kind)
        if backend is None:
            raise _unavailable()
        return ResolvedFileSource(
            descriptor=descriptor,
            user_id=canonical_user_id,
            handle_id=handle_id,
            backend=backend,
        )

    def acquire_transfer_holds(
        self,
        user_id: int | str,
        source_ids,
    ) -> SourceHoldSet:
        """Validate and retain one or two owned transfer sources atomically."""
        if isinstance(source_ids, (str, bytes)):
            raise _unavailable()
        try:
            requested_source_ids = tuple(source_ids)
        except TypeError as exc:
            raise _unavailable() from exc
        if not 1 <= len(requested_source_ids) <= 2:
            raise _unavailable()

        canonical_user_id = _canonical_user_id(user_id)
        unique_source_ids = tuple(dict.fromkeys(requested_source_ids))
        callbacks = []
        try:
            for source_id in unique_source_ids:
                resolved = self.resolve(source_id, canonical_user_id)
                with self._lock:
                    acquirer = self._hold_acquirers.get(resolved.kind)
                if acquirer is None:
                    continue
                callback = acquirer(resolved.handle_id, canonical_user_id)
                if callback is not None and not callable(callback):
                    raise _unavailable()
                if callback is not None:
                    callbacks.append(callback)
        except Exception as exc:
            try:
                SourceHoldSet(unique_source_ids, callbacks).release()
            except Exception:
                pass
            if isinstance(exc, FileSourceUnavailable):
                raise
            raise _unavailable() from exc
        return SourceHoldSet(unique_source_ids, callbacks)


file_source_resolver = FileSourceResolver()
