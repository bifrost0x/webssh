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
from datetime import datetime, timedelta
import config
from .ssh_manager import PersistentHostKeyPolicy
from .ssh_utils import parse_private_key
from .audit_logger import log_info, log_warning, log_error, log_debug

class TemporaryConnectionPool:
    """Manages short-lived SSH connections for file transfers."""

    def __init__(self, cleanup_interval=300, max_connections_per_user=3):
        """
        Initialize the connection pool.

        Args:
            cleanup_interval (int): Seconds before inactive connection is closed
            max_connections_per_user (int): Maximum concurrent connections per user
        """
        self.connections = {}
        self.cleanup_interval = cleanup_interval
        self.max_connections_per_user = max_connections_per_user
        self.lock = threading.Lock()

        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

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
        with self.lock:
            user_connections = [
                c for c in self.connections.values()
                if c['user_id'] == user_id
            ]

            if len(user_connections) >= self.max_connections_per_user:
                return None, f"Maximum {self.max_connections_per_user} connections per user exceeded"

        try:
            client = paramiko.SSHClient()
            if config.KNOWN_HOSTS_FILE.exists():
                client.load_host_keys(str(config.KNOWN_HOSTS_FILE))
            client.set_missing_host_key_policy(PersistentHostKeyPolicy(config.KNOWN_HOSTS_FILE))

            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': 10,
                'look_for_keys': False,
                'allow_agent': False
            }

            if key_content:
                pkey = parse_private_key(key_content)
                connect_kwargs['pkey'] = pkey
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

            sftp = client.open_sftp()

            conn_id = uuid.uuid4().hex

            with self.lock:
                self.connections[conn_id] = {
                    'client': client,
                    'sftp': sftp,
                    'created_at': time.time(),
                    'last_used': time.time(),
                    'user_id': user_id,
                    'host': host,
                    'port': port,
                    'username': username
                }

            log_info(f"Temporary connection created: {conn_id}", user=username, host=f"{host}:{port}")
            return conn_id, None

        except paramiko.AuthenticationException:
            return None, "Authentication failed: Invalid username or password"
        except paramiko.BadHostKeyException:
            log_warning("SECURITY: Host key mismatch detected (possible MITM attack)",
                        host=host, port=port)
            return None, (
                f"HOST KEY CHANGED for {host}:{port}! This could indicate a "
                "man-in-the-middle attack. If the server was legitimately "
                "reinstalled, remove the old key from known_hosts."
            )
        except paramiko.SSHException as e:
            return None, f"SSH error: {str(e)}"
        except TimeoutError:
            return None, "Connection timeout: Could not reach server"
        except Exception as e:
            return None, f"Connection error: {str(e)}"

    def get_sftp_client(self, connection_id):
        """
        Get SFTP client for an existing temporary connection.
        Opens a NEW SFTP channel each time to avoid threading issues.

        Args:
            connection_id (str): Connection ID from create_connection

        Returns:
            tuple: (sftp_client or None, error: str or None)
        """
        with self.lock:
            if connection_id not in self.connections:
                return None, "Connection not found or expired"

            conn = self.connections[connection_id]

            try:
                transport = conn['client'].get_transport()
                if transport is None or not transport.is_active():
                    self._close_connection(connection_id)
                    return None, "Connection has been closed"
            except Exception:
                self._close_connection(connection_id)
                return None, "Connection has been closed"

            conn['last_used'] = time.time()

            try:
                sftp = conn['client'].open_sftp()
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
        with self.lock:
            return self._close_connection(connection_id)

    def _close_connection(self, connection_id):
        """
        Internal method to close connection (must be called with lock held).

        Args:
            connection_id (str): Connection ID to close

        Returns:
            bool: True if closed, False if not found
        """
        if connection_id not in self.connections:
            return False

        conn = self.connections[connection_id]

        try:
            from .sftp_handler import close_sftp_cache
            close_sftp_cache(connection_id)
        except Exception:
            pass

        try:
            if conn['sftp']:
                conn['sftp'].close()
            if conn['client']:
                conn['client'].close()
        except Exception as e:
            log_warning("Error closing connection", connection_id=connection_id, error=str(e))

        del self.connections[connection_id]
        log_debug(f"Temporary connection closed: {connection_id}")

        return True

    def cleanup_expired(self):
        """
        Close all connections that have exceeded the cleanup interval.

        Returns:
            int: Number of connections cleaned up
        """
        current_time = time.time()
        expired = []

        with self.lock:
            for conn_id, conn in self.connections.items():
                age = current_time - conn['last_used']
                if age > self.cleanup_interval:
                    expired.append(conn_id)

            for conn_id in expired:
                self._close_connection(conn_id)

        if expired:
            log_info(f"Cleaned up {len(expired)} expired temporary connection(s)")

        return len(expired)

    def _cleanup_loop(self):
        """Background thread that periodically cleans up expired connections."""
        while True:
            time.sleep(60)
            try:
                self.cleanup_expired()
            except Exception as e:
                log_error("Error in cleanup loop", error=str(e))

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

    def close_all_user_connections(self, user_id):
        """
        Close all connections for a specific user.

        Args:
            user_id (str): User ID

        Returns:
            int: Number of connections closed
        """
        user_connections = []

        with self.lock:
            for conn_id, conn in self.connections.items():
                if conn['user_id'] == user_id:
                    user_connections.append(conn_id)

            for conn_id in user_connections:
                self._close_connection(conn_id)

        return len(user_connections)

    def __del__(self):
        """Cleanup when pool is destroyed."""
        with self.lock:
            for conn_id in list(self.connections.keys()):
                self._close_connection(conn_id)

temp_connection_pool = TemporaryConnectionPool()
