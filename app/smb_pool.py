"""User-isolated lifetime management for ephemeral SMB file sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
import time
import uuid

import config

from .file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceKind,
    make_source_id,
    parse_source_id,
)
from .quota_manager import QuotaExceeded, QuotaKind, quota_manager, release_reservation
from .smb_network_policy import resolve_allowed_smb_target
from .smb_paths import SMBPath, SMBPathRejected, SMBShareName
from .smb_protocol import SMBProtocolClient, SMBProtocolError
from .smb_diagnostics import build_smb_diagnostic, copy_smb_diagnostic


SMB_CAPABILITIES = (
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


class SMBSourceError(Exception):
    """Stable, non-sensitive SMB source lifecycle error."""

    def __init__(
        self,
        public_code,
        message='SMB source unavailable',
        *,
        diagnostic_phase='unknown',
        diagnostic_exception_type=None,
        diagnostic_nt_status=None,
    ):
        super().__init__(message)
        self.public_code = public_code
        diagnostic = build_smb_diagnostic(
            phase=diagnostic_phase,
            exception_type=diagnostic_exception_type,
            nt_status=diagnostic_nt_status,
        )
        self.diagnostic_phase = diagnostic['diagnostic_phase']
        self.diagnostic_exception_type = diagnostic[
            'diagnostic_exception_type'
        ]
        self.diagnostic_nt_status = diagnostic['diagnostic_nt_status']

    @classmethod
    def from_protocol_error(cls, error, *, phase=None):
        diagnostic = copy_smb_diagnostic(error, phase=phase)
        return cls(error.public_code, **diagnostic)


@dataclass
class SMBSource:
    descriptor: FileSourceDescriptor
    user_id: str
    host: str
    target_ip: str
    share: SMBShareName
    username: str
    control_session: object
    transfer_session: object
    quota_reservation: object
    created_at: float
    last_used: float
    hold_count: int = 0
    close_requested: bool = False
    control_lock: RLock = field(default_factory=RLock, repr=False)
    transfer_lock: RLock = field(default_factory=RLock, repr=False)

    @property
    def source_id(self):
        return self.descriptor.source_id

    @property
    def session(self):
        """Compatibility alias for interactive operations during migration."""
        return self.control_session

    @property
    def lock(self):
        """Compatibility alias for interactive operations during migration."""
        return self.control_lock


def _canonical_user_id(user_id):
    if user_id is None or isinstance(user_id, bool):
        raise SMBSourceError('INVALID_REQUEST')
    value = str(user_id)
    if not value or value != value.strip() or len(value) > 128:
        raise SMBSourceError('INVALID_REQUEST')
    return value


def _credential_text(value, *, field_name, maximum, optional=False):
    if optional and (value is None or value == ''):
        return ''
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise SMBSourceError('INVALID_REQUEST', f'Invalid {field_name}')
    return value


class SMBConnectionPool:
    """Own one non-reconnecting protocol session per SMB source."""

    def __init__(
        self,
        *,
        protocol_client=None,
        target_resolver=resolve_allowed_smb_target,
        allowed_targets=None,
        quota_manager=quota_manager,
        cleanup_interval=300,
        connect_timeout=None,
        io_idle_timeout=None,
        clock=time.time,
    ):
        self._protocol_client = protocol_client or SMBProtocolClient()
        self._target_resolver = target_resolver
        self._allowed_targets = tuple(
            config.SMB_ALLOWED_TARGETS
            if allowed_targets is None
            else allowed_targets
        )
        self._quota_manager = quota_manager
        self.cleanup_interval = cleanup_interval
        self.connect_timeout = (
            config.SMB_CONNECT_TIMEOUT_SECONDS
            if connect_timeout is None
            else connect_timeout
        )
        self.io_idle_timeout = (
            config.SMB_IO_IDLE_TIMEOUT_SECONDS
            if io_idle_timeout is None
            else io_idle_timeout
        )
        self._clock = clock
        self._lock = RLock()
        self._sources = {}
        self._cleanup_lifecycle = None
        self.cleanup_handle = None

    @property
    def source_count(self):
        with self._lock:
            return len(self._sources)

    @staticmethod
    def _handle_id(source_id):
        if not isinstance(source_id, str):
            return None
        if ':' not in source_id:
            return source_id
        try:
            kind, handle_id = parse_source_id(source_id)
        except Exception:
            return None
        return handle_id if kind is FileSourceKind.SMB_QUICK else None

    @staticmethod
    def _session_alive(session):
        connection = getattr(session, 'raw_connection', None)
        transport = getattr(connection, 'transport', None)
        return bool(transport is not None and transport.connected)

    def create_source(
        self,
        *,
        host,
        share,
        domain,
        username,
        password,
        user_id,
        cancel_event=None,
    ):
        if cancel_event is not None and cancel_event.is_set():
            raise SMBSourceError('CONNECT_CANCELLED')

        canonical_user_id = _canonical_user_id(user_id)
        try:
            share_name = SMBShareName.parse(share)
        except SMBPathRejected as exc:
            raise SMBSourceError('INVALID_REQUEST') from exc
        clean_username = _credential_text(
            username,
            field_name='username',
            maximum=256,
        )
        clean_domain = _credential_text(
            domain,
            field_name='domain',
            maximum=255,
            optional=True,
        )
        if '\\' in clean_username or '/' in clean_username:
            raise SMBSourceError('INVALID_REQUEST')
        if any(character in clean_domain for character in ('\\', '/', '@')):
            raise SMBSourceError('INVALID_REQUEST')
        local_password = _credential_text(
            password,
            field_name='password',
            maximum=4096,
        )
        protocol_username = (
            f'{clean_domain}\\{clean_username}' if clean_domain else clean_username
        )

        reservation = None
        control_session = None
        transfer_session = None
        stored = False
        diagnostic_phase = 'lifecycle'
        try:
            reservation = self._quota_manager.reserve(
                QuotaKind.QUICK_CONNECTION,
                canonical_user_id,
            )
            if cancel_event is not None and cancel_event.is_set():
                raise SMBSourceError('CONNECT_CANCELLED')
            diagnostic_phase = 'target_resolution'
            target = self._target_resolver(host, self._allowed_targets)
            diagnostic_phase = 'transport_negotiate'
            try:
                control_session = self._protocol_client.connect(
                    target_ip=target.ip,
                    canonical_host=target.hostname,
                    username=protocol_username,
                    password=local_password,
                    timeout=self.connect_timeout,
                    io_idle_timeout=self.io_idle_timeout,
                    cancel_event=cancel_event,
                )
            except SMBProtocolError as exc:
                raise SMBSourceError.from_protocol_error(exc) from exc
            if cancel_event is not None and cancel_event.is_set():
                raise SMBSourceError('CONNECT_CANCELLED')

            diagnostic_phase = 'share_access'
            try:
                root_unc = SMBPath.parse('/').to_unc(target.ip, share_name)
                root_access = control_session.inspect_directory_access(
                    root_unc
                )
            except SMBProtocolError as exc:
                raise SMBSourceError.from_protocol_error(
                    exc,
                    phase='share_access',
                ) from exc
            if cancel_event is not None and cancel_event.is_set():
                raise SMBSourceError('CONNECT_CANCELLED')

            diagnostic_phase = 'transport_negotiate'
            try:
                transfer_session = self._protocol_client.connect(
                    target_ip=target.ip,
                    canonical_host=target.hostname,
                    username=protocol_username,
                    password=local_password,
                    timeout=self.connect_timeout,
                    io_idle_timeout=self.io_idle_timeout,
                    cancel_event=cancel_event,
                )
            except SMBProtocolError as exc:
                raise SMBSourceError.from_protocol_error(exc) from exc
            if cancel_event is not None and cancel_event.is_set():
                raise SMBSourceError('CONNECT_CANCELLED')

            diagnostic_phase = 'share_access'
            try:
                # Validate that the independent transfer lane can reach the
                # same approved share before publishing the source.
                transfer_session.inspect_directory_access(
                    root_unc
                )
            except SMBProtocolError as exc:
                raise SMBSourceError.from_protocol_error(
                    exc,
                    phase='share_access',
                ) from exc
            if cancel_event is not None and cancel_event.is_set():
                raise SMBSourceError('CONNECT_CANCELLED')

            diagnostic_phase = 'lifecycle'
            handle_id = uuid.uuid4().hex
            source_id = make_source_id(FileSourceKind.SMB_QUICK, handle_id)
            descriptor = FileSourceDescriptor(
                source_id=source_id,
                kind='smb',
                label=f'{share_name} on {target.hostname}',
                endpoint=f'{target.hostname}/{share_name}',
                protocol='SMB 3.1.1',
                capabilities=SMB_CAPABILITIES,
                ephemeral=True,
                security={
                    'encrypted': True,
                    'signed': True,
                    'secure_negotiate': True,
                },
                access=root_access,
            )
            now = self._clock()
            source = SMBSource(
                descriptor=descriptor,
                user_id=canonical_user_id,
                host=target.hostname,
                target_ip=target.ip,
                share=share_name,
                username=protocol_username,
                control_session=control_session,
                transfer_session=transfer_session,
                quota_reservation=reservation,
                created_at=now,
                last_used=now,
            )
            with self._lock:
                lifecycle = self._cleanup_lifecycle
                if lifecycle is not None and not lifecycle.accepting_work():
                    raise SMBSourceError('RUNTIME_SHUTTING_DOWN')
                self._sources[handle_id] = source
                stored = True
            return descriptor
        except QuotaExceeded as exc:
            raise SMBSourceError('QUOTA_EXCEEDED') from exc
        except SMBSourceError:
            raise
        except SMBProtocolError as exc:
            raise SMBSourceError.from_protocol_error(exc) from exc
        except ValueError as exc:
            diagnostic = build_smb_diagnostic(
                phase=diagnostic_phase,
                exception=exc,
            )
            raise SMBSourceError('TARGET_NOT_ALLOWED', **diagnostic) from exc
        except Exception as exc:
            diagnostic = build_smb_diagnostic(
                phase=diagnostic_phase,
                exception=exc,
            )
            raise SMBSourceError('CONNECTION_FAILED', **diagnostic) from exc
        finally:
            local_password = None
            password = None
            if not stored:
                for session in (transfer_session, control_session):
                    if session is None:
                        continue
                    try:
                        session.close()
                    except Exception:
                        pass
                release_reservation(reservation)

    def _detach(self, predicate, *, defer_held=False):
        detached = []
        with self._lock:
            for handle_id, source in list(self._sources.items()):
                if not predicate(handle_id, source):
                    continue
                if defer_held and source.hold_count > 0:
                    source.close_requested = True
                    continue
                detached.append(self._sources.pop(handle_id))
        return detached

    @staticmethod
    def _close_detached(sources):
        for source in sources:
            closed = set()
            for session in (
                source.transfer_session,
                source.control_session,
            ):
                identity = id(session)
                if identity in closed:
                    continue
                closed.add(identity)
                try:
                    session.close()
                except Exception:
                    pass
            release_reservation(source.quota_reservation)

    @classmethod
    def _source_alive(cls, source):
        return (
            cls._session_alive(source.control_session)
            and cls._session_alive(source.transfer_session)
        )

    def get_source(self, source_id, user_id):
        handle_id = self._handle_id(source_id)
        try:
            canonical_user_id = _canonical_user_id(user_id)
        except SMBSourceError:
            return None
        if handle_id is None:
            return None

        stale = None
        with self._lock:
            source = self._sources.get(handle_id)
            if source is None or source.user_id != canonical_user_id:
                return None
            if not self._source_alive(source):
                stale = self._sources.pop(handle_id)
            else:
                # A deferred close must remain resolvable by the transfer that
                # already owns a hold. New holds are rejected above once close
                # has been requested, so no new transfer can extend its life.
                source.last_used = self._clock()
                return source
        self._close_detached((stale,))
        return None

    def acquire_hold(self, source_id, user_id):
        handle_id = self._handle_id(source_id)
        try:
            canonical_user_id = _canonical_user_id(user_id)
        except SMBSourceError:
            return False
        with self._lock:
            source = self._sources.get(handle_id)
            if (
                source is None
                or source.user_id != canonical_user_id
                or source.close_requested
                or not self._source_alive(source)
            ):
                return False
            source.hold_count += 1
            return True

    def release_hold(self, source_id, user_id):
        handle_id = self._handle_id(source_id)
        try:
            canonical_user_id = _canonical_user_id(user_id)
        except SMBSourceError:
            return False
        detached = []
        with self._lock:
            source = self._sources.get(handle_id)
            if (
                source is None
                or source.user_id != canonical_user_id
                or source.hold_count <= 0
            ):
                return False
            source.hold_count -= 1
            if source.hold_count == 0 and source.close_requested:
                detached.append(self._sources.pop(handle_id))
        self._close_detached(detached)
        return True

    def request_close(self, source_id, user_id=None):
        handle_id = self._handle_id(source_id)
        canonical_user_id = None
        if user_id is not None:
            try:
                canonical_user_id = _canonical_user_id(user_id)
            except SMBSourceError:
                return 'unavailable'
        detached = []
        with self._lock:
            source = self._sources.get(handle_id)
            if (
                source is None
                or (
                    canonical_user_id is not None
                    and source.user_id != canonical_user_id
                )
            ):
                return 'unavailable'
            if source.hold_count > 0:
                source.close_requested = True
                return 'deferred'
            detached.append(self._sources.pop(handle_id))
        self._close_detached(detached)
        return 'closed'

    def close_all_user_sources(self, user_id):
        try:
            canonical_user_id = _canonical_user_id(user_id)
        except SMBSourceError:
            return 0
        detached = self._detach(
            lambda _handle_id, source: source.user_id == canonical_user_id
        )
        self._close_detached(detached)
        return len(detached)

    def close_all_sources(self):
        detached = self._detach(lambda _handle_id, _source: True)
        self._close_detached(detached)
        return len(detached)

    def cleanup_expired(self):
        now = self._clock()
        detached = self._detach(
            lambda _handle_id, source: (
                now - source.last_used > self.cleanup_interval
                or not self._source_alive(source)
            ),
            defer_held=True,
        )
        self._close_detached(detached)
        return len(detached)

    def _cleanup_loop(self, cancel_event):
        try:
            while not cancel_event.wait(60):
                self.cleanup_expired()
        finally:
            self.close_all_sources()

    def bind_lifecycle(self, lifecycle):
        with self._lock:
            if self._cleanup_lifecycle is lifecycle and self.cleanup_handle:
                return self.cleanup_handle
            if self.cleanup_handle is not None:
                self.cleanup_handle.cancel()
            self._cleanup_lifecycle = lifecycle
            self.cleanup_handle = lifecycle.start_job(
                'smb_source_cleanup',
                self._cleanup_loop,
                defer_cancel_until_callbacks=True,
            )
            return self.cleanup_handle


smb_connection_pool = SMBConnectionPool()


def bind_smb_connection_pool(lifecycle):
    global smb_connection_pool

    if smb_connection_pool._cleanup_lifecycle is lifecycle:
        return smb_connection_pool
    previous = smb_connection_pool
    if previous.cleanup_handle is not None:
        previous.cleanup_handle.cancel()
    previous.close_all_sources()
    smb_connection_pool = SMBConnectionPool()
    smb_connection_pool.bind_lifecycle(lifecycle)
    return smb_connection_pool
