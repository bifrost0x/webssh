"""Bounded, agentless Linux statistics for an active SSH session."""

import socket
import time
from threading import Lock

from . import ssh_manager


DEFAULT_MAX_BYTES = 16 * 1024
DEFAULT_TIMEOUT = 2.0

_collector_locks = {}
_collector_locks_guard = Lock()


LINUX_STATS_COMMAND = r"""LC_ALL=C
awk 'NR == 1 { $1=""; sub(/^ /, ""); print "cpu=" $0; exit }' /proc/stat
awk '
  /^MemTotal:/ { print "mem_total_kib=" $2 }
  /^MemAvailable:/ { print "mem_available_kib=" $2 }
' /proc/meminfo
df -Pk / | awk 'NR == 2 {
  percent=$5; sub(/%$/, "", percent)
  print "disk_total_kib=" $2
  print "disk_used_kib=" $3
  print "disk_available_kib=" $4
  print "disk_percent=" percent
}'
awk '{ print "uptime_seconds=" $1; exit }' /proc/uptime
if [ -r /etc/os-release ]; then
  os_name=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1)
  os_name=${os_name#\"}; os_name=${os_name%\"}
  os_name=${os_name#\'}; os_name=${os_name%\'}
else
  os_name=Linux
fi
printf 'os_name=%s\n' "$os_name"
"""


def _non_negative_int(values, key):
    try:
        value = int(values[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'invalid {key}') from exc
    if value < 0:
        raise ValueError(f'invalid {key}')
    return value


def parse_linux_stats(text, *, max_bytes=DEFAULT_MAX_BYTES):
    """Parse the fixed collector output into a small, safe payload."""
    if not isinstance(text, str):
        raise ValueError('invalid stats payload')
    if len(text.encode('utf-8')) > max_bytes:
        raise ValueError('stats payload too large')

    values = {}
    for raw_line in text.splitlines():
        key, separator, value = raw_line.partition('=')
        if not separator:
            continue
        if key in {
            'cpu', 'mem_total_kib', 'mem_available_kib',
            'disk_total_kib', 'disk_used_kib', 'disk_available_kib',
            'disk_percent', 'uptime_seconds', 'os_name',
        }:
            values[key] = value.strip()

    try:
        cpu = [int(part) for part in values['cpu'].split()]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('invalid cpu') from exc
    if len(cpu) < 4 or any(value < 0 for value in cpu):
        raise ValueError('invalid cpu')

    mem_total = _non_negative_int(values, 'mem_total_kib')
    mem_available = _non_negative_int(values, 'mem_available_kib')
    if mem_total <= 0 or mem_available > mem_total:
        raise ValueError('invalid memory')

    disk_total = _non_negative_int(values, 'disk_total_kib')
    disk_used = _non_negative_int(values, 'disk_used_kib')
    disk_available = _non_negative_int(values, 'disk_available_kib')
    disk_percent = _non_negative_int(values, 'disk_percent')
    if (
        disk_total <= 0
        or disk_used > disk_total
        or disk_available > disk_total
        or disk_percent > 100
    ):
        raise ValueError('invalid disk')

    try:
        uptime_seconds = int(float(values['uptime_seconds']))
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError('invalid uptime') from exc
    if uptime_seconds < 0:
        raise ValueError('invalid uptime')

    os_name = values.get('os_name', '').strip()
    if not os_name or len(os_name) > 200:
        raise ValueError('invalid os name')

    return {
        'cpu': cpu,
        'memory': {
            'total_kib': mem_total,
            'available_kib': mem_available,
            'used_kib': mem_total - mem_available,
        },
        'disk': {
            'total_kib': disk_total,
            'used_kib': disk_used,
            'available_kib': disk_available,
            'percent': disk_percent,
        },
        'uptime_seconds': uptime_seconds,
        'os_name': os_name,
    }


def _lock_for_session(session_id):
    with _collector_locks_guard:
        return _collector_locks.setdefault(session_id, Lock())


def _release_session_lock(session_id, collector_lock):
    collector_lock.release()
    with _collector_locks_guard:
        if _collector_locks.get(session_id) is collector_lock:
            _collector_locks.pop(session_id, None)


def collect_linux_stats(session_id, *, timeout=DEFAULT_TIMEOUT,
                        max_bytes=DEFAULT_MAX_BYTES):
    """Collect one Linux sample without touching the interactive PTY."""
    if not isinstance(session_id, str) or not session_id:
        return None, 'unavailable'

    collector_lock = _lock_for_session(session_id)
    if not collector_lock.acquire(blocking=False):
        return None, 'busy'

    channel = None
    try:
        with ssh_manager.sessions_lock:
            session = ssh_manager.sessions.get(session_id)
            if not session or not session.get('connected'):
                return None, 'unavailable'
            client = session.get('client')

        transport = client.get_transport() if client else None
        if not transport or not transport.is_active():
            return None, 'unavailable'

        channel = ssh_manager._open_exec_channel(
            transport,
            LINUX_STATS_COMMAND,
            timeout=timeout,
        )
        deadline = time.monotonic() + timeout
        output = bytearray()

        while True:
            if channel.recv_ready():
                chunk = channel.recv(min(4096, max_bytes + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_bytes:
                    return None, 'unavailable'
                continue
            if channel.exit_status_ready():
                break
            if time.monotonic() >= deadline:
                return None, 'unavailable'
            time.sleep(0.02)

        while channel.recv_ready():
            chunk = channel.recv(min(4096, max_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_bytes:
                return None, 'unavailable'

        if channel.recv_exit_status() != 0:
            return None, 'unavailable'

        try:
            text = output.decode('utf-8', errors='strict')
            return parse_linux_stats(text, max_bytes=max_bytes), None
        except (UnicodeDecodeError, ValueError):
            return None, 'unavailable'
    except (OSError, socket.timeout):
        return None, 'unavailable'
    except Exception:
        return None, 'unavailable'
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        _release_session_lock(session_id, collector_lock)
