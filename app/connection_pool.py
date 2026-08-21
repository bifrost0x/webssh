"""
Temporary Connection Pool Module

Manages short-lived SSH/SFTP connections for file transfers without requiring
an active terminal session. Connections are automatically cleaned up after a timeout.

Features:
- Create temporary SSH+SFTP connections
- Automatic cleanup of expired connections
- Connection limit per user
- Thread-safe operations
"""

import time
import uuid
import threading
import paramiko
from datetime import datetime
import config
from .host_key_store import HostKeyStore
from .network_policy import open_validated_socket, resolve_allowed_target
from .ssh_key_loader import load_private_key as _load_private_key
from .ssh_errors import SSHConnectionError
from .paramiko_channels import open_sftp_client
from .audit_logger import log_info, log_warning, log_error, log_debug
from .quota_manager import (
    QuotaExceeded,
    QuotaKind,
    quota_manager,
    release_reservation,
)


class TemporaryConnectionPool:
    """Manages short-lived SSH connections for file transfers."""

    def __init__(
        self, cleanup_interval=300, max_connections_per_user=None
    ):
        """
        Initialize the connection pool.

        Args:
            cleanup_interval (int): Seconds before inactive connection is closed
            max_connections_per_user: Deprecated compatibility argument. The
                central QUOTA_QUICK_CONNECTION_PER_USER setting always wins.
        """
        del max_connections_per_user
        self.connections = {}
        self.cleanup_interval = cleanup_interval
        self.lock = threading.Lock()
        self.quota_manager = quota_manager
        self.cleanup_handle = None
        self._cleanup_lifecycle = None

    def bind_lifecycle(self, lifecycle):
        """Run this pool's cleanup loop through one app-owned lifecycle."""
        with self.lock:
            if self._cleanup_lifecycle is lifecycle and self.cleanup_handle:
                return self.cleanup_handle
            if self.cleanup_handle is not None:
                self.cleanup_handle.cancel()
            self._cleanup_lifecycle = lifecycle
            self.cleanup_handle = lifecycle.start_job(
                'temporary_connection_cleanup',
                self._cleanup_loop,
                defer_cancel_until_callbacks=True,
            )
            return self.cleanup_handle

    def create_connection(self, host, port, username, password=None, key_path=None, key_content=None, user_id=None):
        """
        Create a temporary SSH+SFTP connection.

        Args:
            host (str): SSH server hostname
            port (int): SSH server port
            username (str): SSH username
            password (str, optional): SSH password
            key_path (str, optional): Path to SSH private key file - DEPRECATED
            key_content (str, optional): Decrypted SSH private key content (preferred)
            user_id (str): Application user ID (for tracking)

        Returns:
            tuple: (connection_id: str or None, error: str or None)
        """
        lifecycle = self._cleanup_lifecycle
        if lifecycle is not None and not lifecycle.accepting_work():
            return None, "Runtime is shutting down"

        try:
            host_key_store = HostKeyStore(
                user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR
            )
        except (TypeError, ValueError):
            return None, "User identity is required"
        user_id = str(host_key_store.user_id)

        try:
            reservation = self.quota_manager.reserve(
                QuotaKind.QUICK_CONNECTION, user_id
            )
        except QuotaExceeded:
            return None, "Maximum number of quick connections reached"

        client = None
        sftp = None
        validated_socket = None
        connection_stored = False
        try:
            target = resolve_allowed_target(
                host,
                port,
                allow_internal=not config.BLOCK_INTERNAL_SSH,
            )
            host = target.hostname
            port = target.port
            validated_socket = open_validated_socket(target, 10)
            client = paramiko.SSHClient()
            host_key_store.load_into(client)
            client.set_missing_host_key_policy(
                host_key_store.missing_key_policy()
            )

            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': 10,
                'sock': validated_socket,
                'look_for_keys': False,
                'allow_agent': False
            }

            if key_content:
                connect_kwargs['pkey'] = _load_private_key(key_content)
            elif key_path:
                connect_kwargs['key_filename'] = key_path
                if password:
                    connect_kwargs['passphrase'] = password
            elif password:
                connect_kwargs['password'] = password
            else:
                return None, "Either password or SSH key is required"

            client.connect(**connect_kwargs)

            transport = client.get_transport()
            if transport:
                transport.set_keepalive(30)

            sftp = open_sftp_client(
                transport,
                timeout=config.SSH_CONNECT_TIMEOUT,
                operation_timeout=config.SFTP_OPERATION_TIMEOUT,
            )

            conn_id = uuid.uuid4().hex

            with self.lock:
                lifecycle = self._cleanup_lifecycle
                if (
                    lifecycle is not None
                    and not lifecycle.accepting_work()
                ):
                    return None, "Runtime is shutting down"
                self.connections[conn_id] = {
                    'client': client,
                    'sftp': sftp,
                    'created_at': time.time(),
                    'last_used': time.time(),
                    'user_id': user_id,
                    'host': host,
                    'port': port,
                    'username': username,
                    'quota_reservation': reservation,
                }
                connection_stored = True

            log_info(f"Temporary connection created: {conn_id}", user=username, host=f"{host}:{port}")
            return conn_id, None

        except paramiko.BadHostKeyException:
            log_warning(
                "Pool SSH host key changed",
                host=f"{host}:{port}",
            )
            return None, SSHConnectionError(
                "SSH host key changed",
                code="host_key_changed",
                context="target",
            )
        except paramiko.AuthenticationException:
            return None, "Authentication failed: Invalid username or password"
        except ValueError as e:
            return None, str(e)
        except paramiko.SSHException as e:
            # Keep the raw error in the server log only; a generic client message
            # avoids leaking remote details that could aid host/port scanning.
            log_warning("Pool SSH connection failed", host=f"{host}:{port}", error=str(e))
            return None, "SSH connection failed"
        except TimeoutError:
            return None, "Connection timeout: Could not reach server"
        except Exception as e:
            log_error("Pool connection error", host=f"{host}:{port}", error=str(e))
            return None, "Connection failed"
        finally:
            if not connection_stored:
                release_reservation(reservation)
                if sftp is not None:
                    try:
                        sftp.close()
                    except Exception:
                        pass
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
                if validated_socket is not None:
                    try:
                        validated_socket.close()
                    except Exception:
                        pass

    def get_sftp_client(self, connection_id):
        """
        Get SFTP client for an existing temporary connection.
        Opens a NEW SFTP channel each time to avoid threading issues.

        Args:
            connection_id (str): Connection ID from create_connection

        Returns:
            tuple: (sftp_client or None, error: str or None)
        """
        stale_connection = None
        with self.lock:
            conn = self.connections.get(connection_id)
            if conn is None:
                return None, "Connection not found or expired"

            try:
                transport = conn['client'].get_transport()
                if transport is None or not transport.is_active():
                    stale_connection = self.connections.pop(connection_id)
                else:
                    conn['last_used'] = time.time()
            except Exception:
                stale_connection = self.connections.pop(connection_id)

        if stale_connection is not None:
            self._close_detached_connections(
                ((connection_id, stale_connection),)
            )
            return None, "Connection has been closed"

        try:
            sftp = open_sftp_client(
                transport,
                timeout=config.SSH_CONNECT_TIMEOUT,
                operation_timeout=config.SFTP_OPERATION_TIMEOUT,
            )
            return sftp, None
        except Exception as e:
            return None, f"Failed to open SFTP channel: {str(e)}"

    def close_connection(self, connection_id):
        """
        Close a specific temporary connection.

        Args:
            connection_id (str): Connection ID to close

        Returns:
            bool: True if connection was closed, False if not found
        """
        detached = self._detach_connections(
            lambda candidate_id, _conn: candidate_id == connection_id
        )
        self._close_detached_connections(detached)
        return bool(detached)

    def _detach_connections(self, predicate=None):
        """Atomically remove matching records before any blocking cleanup."""
        with self.lock:
            detached = []
            for connection_id, conn in list(self.connections.items()):
                if predicate is None or predicate(connection_id, conn):
                    detached.append((connection_id, self.connections.pop(
                        connection_id
                    )))
            return detached

    def _close_detached_connections(self, detached_connections):
        """Release detached resources without holding the pool registry lock."""
        for connection_id, conn in detached_connections:
            try:
                from .sftp_handler import close_sftp_cache
                close_sftp_cache(connection_id)
            except Exception:
                pass

            for resource_name in ('sftp', 'client'):
                resource = conn.get(resource_name)
                if resource is None:
                    continue
                try:
                    resource.close()
                except Exception as exc:
                    log_warning(
                        "Error closing connection resource",
                        connection_id=connection_id,
                        resource=resource_name,
                        error=str(exc),
                    )
            release_reservation(conn.get('quota_reservation'))
            log_debug(f"Temporary connection closed: {connection_id}")

    def cleanup_expired(self):
        """
        Close all connections that have exceeded the cleanup interval.

        Returns:
            int: Number of connections cleaned up
        """
        current_time = time.time()
        expired = self._detach_connections(
            lambda _connection_id, conn: (
                current_time - conn['last_used'] > self.cleanup_interval
            )
        )
        self._close_detached_connections(expired)

        if expired:
            log_info(f"Cleaned up {len(expired)} expired temporary connection(s)")

        return len(expired)

    def _cleanup_loop(self, cancel_event):
        """Periodically clean up expired connections until lifecycle shutdown."""
        try:
            while not cancel_event.wait(60):
                try:
                    self.cleanup_expired()
                except Exception as e:
                    log_error("Error in cleanup loop", error=str(e))
        finally:
            self.close_all_connections()

    def get_connection_info(self, connection_id):
        """
        Get information about a connection.

        Args:
            connection_id (str): Connection ID

        Returns:
            dict or None: Connection info or None if not found
        """
        with self.lock:
            if connection_id not in self.connections:
                return None

            conn = self.connections[connection_id]
            return {
                'connection_id': connection_id,
                'host': conn['host'],
                'port': conn['port'],
                'username': conn['username'],
                'created_at': datetime.fromtimestamp(conn['created_at']).isoformat(),
                'last_used': datetime.fromtimestamp(conn['last_used']).isoformat(),
                'age_seconds': time.time() - conn['created_at'],
                'idle_seconds': time.time() - conn['last_used'],
                'user_id': conn['user_id']
            }

    def get_ssh_client(self, connection_id):
        """Return the live SSH client for an internal pool consumer."""
        with self.lock:
            conn = self.connections.get(connection_id)
            if conn is None:
                return None
            client = conn.get('client')
            transport = client.get_transport() if client is not None else None
            if transport is None or not transport.is_active():
                return None
            conn['last_used'] = time.time()
            return client

    def close_all_user_connections(self, user_id):
        """
        Close all connections for a specific user.

        Args:
            user_id (str): User ID

        Returns:
            int: Number of connections closed
        """
        detached = self._detach_connections(
            lambda _connection_id, conn: conn['user_id'] == user_id
        )
        self._close_detached_connections(detached)
        return len(detached)

    def close_all_connections(self):
        """Close every pooled connection before this pool is discarded."""
        detached = self._detach_connections()
        self._close_detached_connections(detached)
        return len(detached)

    def __del__(self):
        """Cleanup when pool is destroyed."""
        self.close_all_connections()

temp_connection_pool = TemporaryConnectionPool()


def bind_temp_connection_pool(lifecycle):
    """Bind the module-global pool to the lifecycle of the current app factory."""
    global temp_connection_pool

    if temp_connection_pool._cleanup_lifecycle is lifecycle:
        return temp_connection_pool

    previous_pool = temp_connection_pool
    if previous_pool.cleanup_handle is not None:
        previous_pool.cleanup_handle.cancel()
    previous_pool.close_all_connections()

    temp_connection_pool = TemporaryConnectionPool()
    temp_connection_pool.bind_lifecycle(lifecycle)
    return temp_connection_pool
