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
        self.connections = {}  # {connection_id: {client, sftp, created_at, user_id, host}}
        self.cleanup_interval = cleanup_interval
        self.max_connections_per_user = max_connections_per_user
        self.lock = threading.Lock()

        # Start cleanup thread
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
            # Check connection limit for this user
            user_connections = [
                c for c in self.connections.values()
                if c['user_id'] == user_id
            ]

            if len(user_connections) >= self.max_connections_per_user:
                return None, f"Maximum {self.max_connections_per_user} connections per user exceeded"

        try:
            # Create SSH client with secure host key verification
            client = paramiko.SSHClient()
            # SECURITY FIX: Use PersistentHostKeyPolicy instead of AutoAddPolicy
            # to prevent MITM attacks by verifying and storing host keys
            if config.KNOWN_HOSTS_FILE.exists():
                client.load_host_keys(str(config.KNOWN_HOSTS_FILE))
            client.set_missing_host_key_policy(PersistentHostKeyPolicy(config.KNOWN_HOSTS_FILE))

            # Connect with timeout - support both password and key auth
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': 10,
                'look_for_keys': False,
                'allow_agent': False
            }

            if key_content:
                # Use decrypted key content (preferred - keys encrypted at rest)
                import io
                key_file = io.StringIO(key_content)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                except paramiko.ssh_exception.SSHException:
                    key_file.seek(0)
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key(key_file)
                    except paramiko.ssh_exception.SSHException:
                        key_file.seek(0)
                        try:
                            pkey = paramiko.ECDSAKey.from_private_key(key_file)
                        except paramiko.ssh_exception.SSHException:
                            key_file.seek(0)
                            pkey = paramiko.DSSKey.from_private_key(key_file)
                connect_kwargs['pkey'] = pkey
                if password:
                    # Password might be the key passphrase (handled during key loading)
                    pass
            elif key_path:
                # Legacy: Use SSH key file path
                connect_kwargs['key_filename'] = key_path
                if password:
                    connect_kwargs['passphrase'] = password
            elif password:
                # Use password authentication
                connect_kwargs['password'] = password
            else:
                return None, "Either password or SSH key is required"

            client.connect(**connect_kwargs)

            # Open SFTP channel
            sftp = client.open_sftp()

            # Generate connection ID
            conn_id = uuid.uuid4().hex

            # Store connection
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

            # Check if connection is still alive
            try:
                transport = conn['client'].get_transport()
                if transport is None or not transport.is_active():
                    self._close_connection(connection_id)
                    return None, "Connection has been closed"
            except Exception:
                # Connection is dead, remove it
                self._close_connection(connection_id)
                return None, "Connection has been closed"

            # Update last used time
            conn['last_used'] = time.time()

            # Open a NEW SFTP channel for this request
            # This avoids issues with reusing SFTP objects across threads
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
            # Close SFTP and SSH
            if conn['sftp']:
                conn['sftp'].close()
            if conn['client']:
                conn['client'].close()
        except Exception as e:
            log_warning(f"Error closing connection", connection_id=connection_id, error=str(e))

        # Remove from pool
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

            # Close expired connections
            for conn_id in expired:
                self._close_connection(conn_id)

        if expired:
            log_info(f"Cleaned up {len(expired)} expired temporary connection(s)")

        return len(expired)

    def _cleanup_loop(self):
        """Background thread that periodically cleans up expired connections."""
        while True:
            time.sleep(60)  # Run cleanup every minute
            try:
                self.cleanup_expired()
            except Exception as e:
                log_error(f"Error in cleanup loop", error=str(e))

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

    def get_all_connections(self, user_id=None):
        """
        Get information about all connections, optionally filtered by user.

        Args:
            user_id (str, optional): Filter by user ID

        Returns:
            list: List of connection info dicts
        """
        with self.lock:
            connections = []
            for conn_id in self.connections:
                if user_id is None or self.connections[conn_id]['user_id'] == user_id:
                    info = self.get_connection_info(conn_id)
                    if info:
                        connections.append(info)

            return connections

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

            # Close all user connections
            for conn_id in user_connections:
                self._close_connection(conn_id)

        return len(user_connections)

    def __del__(self):
        """Cleanup when pool is destroyed."""
        with self.lock:
            for conn_id in list(self.connections.keys()):
                self._close_connection(conn_id)


# Global connection pool instance
temp_connection_pool = TemporaryConnectionPool()
