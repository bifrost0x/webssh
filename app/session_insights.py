"""Bounded, agentless Linux diagnostics for an active SSH session."""

import math
import socket
import time
from threading import Lock

from paramiko import SSHException

from . import ssh_manager


DEFAULT_MAX_BYTES = 16 * 1024
DEFAULT_TIMEOUT = 2.0
REQUEST_RATE_LIMIT = '30 per minute'

_collector_locks = {}
_collector_locks_guard = Lock()


LINUX_STATS_COMMAND = r"""LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
export LC_ALL PATH
if [ -r /proc/stat ] && command -v awk >/dev/null 2>&1; then
  awk 'NR == 1 { $1=""; sub(/^ /, ""); print "cpu=" $0; exit }' /proc/stat 2>/dev/null
fi
if [ -r /proc/meminfo ] && command -v awk >/dev/null 2>&1; then
  awk '
    /^MemTotal:/ { print "mem_total_kib=" $2 }
    /^MemAvailable:/ { print "mem_available_kib=" $2 }
  ' /proc/meminfo 2>/dev/null
fi
if command -v df >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
  df -Pk / 2>/dev/null | awk 'NR == 2 {
    percent=$5; sub(/%$/, "", percent)
    print "disk_total_kib=" $2
    print "disk_used_kib=" $3
    print "disk_available_kib=" $4
    print "disk_percent=" percent
  }'
fi
if [ -r /proc/uptime ] && command -v awk >/dev/null 2>&1; then
  awk '{ print "uptime_seconds=" $1; exit }' /proc/uptime 2>/dev/null
fi
if [ -r /etc/os-release ] && command -v awk >/dev/null 2>&1; then
  os_name=$(awk -F= '/^PRETTY_NAME=/ { sub(/^PRETTY_NAME=/, ""); print; exit }' /etc/os-release 2>/dev/null)
  os_name=${os_name#\"}; os_name=${os_name%\"}
  os_name=${os_name#\'}; os_name=${os_name%\'}
elif command -v uname >/dev/null 2>&1; then
  os_name=$(uname -srm 2>/dev/null)
else
  os_name=
fi
[ -n "$os_name" ] && printf 'os_name=%s\n' "$os_name"
:
"""


LINUX_DIAGNOSTICS_COMMAND = LINUX_STATS_COMMAND + r"""
if [ -r /proc/meminfo ] && command -v awk >/dev/null 2>&1; then
  awk '
    /^SwapTotal:/ { print "swap_total_kib=" $2 }
    /^SwapFree:/ { print "swap_free_kib=" $2 }
  ' /proc/meminfo 2>/dev/null
fi
if [ -r /proc/loadavg ] && command -v awk >/dev/null 2>&1; then
  awk '{
    print "load_1=" $1
    print "load_5=" $2
    print "load_15=" $3
  }' /proc/loadavg 2>/dev/null
fi
if [ -r /proc/stat ] && command -v awk >/dev/null 2>&1; then
  awk '/^cpu[0-9]+ / { count++ } END {
    if (count > 0) print "cpu_count=" count
  }' /proc/stat 2>/dev/null
fi
if [ -r /proc/net/dev ] && command -v awk >/dev/null 2>&1; then
  awk -F '[: ]+' 'NR > 2 {
    if ($2 != "lo") {
      received += $3
      transmitted += $11
    }
  } END {
    print "network_received_bytes=" received + 0
    print "network_transmitted_bytes=" transmitted + 0
  }' /proc/net/dev 2>/dev/null
fi

process_probe=$(ps -p $$ -o pid= 2>&1)
process_status=$?
if [ "$process_status" -eq 0 ]; then
  ps -e -o stat= 2>/dev/null | awk '
    { total++ }
    substr($1, 1, 1) == "Z" { zombies++ }
    END {
      print "process_total=" total + 0
      print "process_zombies=" zombies + 0
    }'
  ps -e -o pid=,user=,comm=,pcpu=,pmem= --sort=-pcpu 2>/dev/null \
    | awk 'NR <= 5 {
        printf "process_cpu=%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5
      }'
  ps -e -o pid=,user=,comm=,pcpu=,pmem= --sort=-pmem 2>/dev/null \
    | awk 'NR <= 5 {
        printf "process_memory=%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5
      }'
elif printf '%s' "$process_probe" | grep -Eqi \
    'permission denied|access denied|not authorized|authorization denied'; then
  printf 'permission_denied=processes\n'
fi
:

"""


_SINGLE_KEYS = {
    'cpu', 'mem_total_kib', 'mem_available_kib',
    'disk_total_kib', 'disk_used_kib', 'disk_available_kib',
    'disk_percent', 'uptime_seconds', 'os_name',
    'load_1', 'load_5', 'load_15', 'cpu_count',
    'swap_total_kib', 'swap_free_kib',
    'network_received_bytes', 'network_transmitted_bytes',
    'process_total', 'process_zombies',
}
_MULTI_KEYS = {
    'process_cpu', 'process_memory', 'permission_denied',
}
_PERMISSION_SCOPES = ('processes',)


def _optional_int(values, key, *, maximum=None):
    try:
        value = int(values[key])
    except (KeyError, TypeError, ValueError):
        return None
    if value < 0 or (maximum is not None and value > maximum):
        return None
    return value


def _optional_float(values, key, *, maximum=1_000_000):
    try:
        value = float(values[key])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(value) or value < 0 or value > maximum:
        return None
    return value


def _safe_text(value, *, maximum):
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        return None
    return normalized


def _parse_process_rows(rows):
    parsed = []
    for row in rows[:5]:
        parts = row.split('|')
        if len(parts) != 5:
            continue
        pid = _optional_int({'pid': parts[0]}, 'pid', maximum=2_147_483_647)
        user = _safe_text(parts[1], maximum=64)
        command = _safe_text(parts[2], maximum=128)
        cpu_percent = _optional_float({'value': parts[3]}, 'value', maximum=100_000)
        memory_percent = _optional_float({'value': parts[4]}, 'value', maximum=100)
        if None in (pid, user, command, cpu_percent, memory_percent) or pid == 0:
            continue
        parsed.append({
            'pid': pid,
            'user': user,
            'command': command,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
        })
    return parsed


def parse_linux_stats(text, *, max_bytes=DEFAULT_MAX_BYTES):
    """Parse the fixed collector output into a small, safe payload."""
    if not isinstance(text, str):
        raise ValueError('invalid stats payload')
    if len(text.encode('utf-8')) > max_bytes:
        raise ValueError('stats payload too large')

    values = {}
    repeated = {key: [] for key in _MULTI_KEYS}
    for raw_line in text.splitlines():
        key, separator, value = raw_line.partition('=')
        if not separator:
            continue
        if key in _SINGLE_KEYS:
            values[key] = value.strip()
        elif key in _MULTI_KEYS and len(repeated[key]) < 16:
            repeated[key].append(value.strip())

    result = {}

    try:
        cpu = [int(part) for part in values.get('cpu', '').split()]
    except (TypeError, ValueError):
        cpu = []
    if len(cpu) >= 4 and all(value >= 0 for value in cpu):
        result['cpu'] = cpu

    mem_total = _optional_int(
        values, 'mem_total_kib', maximum=2 ** 63 - 1
    )
    mem_available = _optional_int(
        values, 'mem_available_kib', maximum=2 ** 63 - 1
    )
    if (
        mem_total is not None
        and mem_available is not None
        and mem_total > 0
        and mem_available <= mem_total
    ):
        result['memory'] = {
            'total_kib': mem_total,
            'available_kib': mem_available,
            'used_kib': mem_total - mem_available,
        }

    disk_total = _optional_int(
        values, 'disk_total_kib', maximum=2 ** 63 - 1
    )
    disk_used = _optional_int(
        values, 'disk_used_kib', maximum=2 ** 63 - 1
    )
    disk_available = _optional_int(
        values, 'disk_available_kib', maximum=2 ** 63 - 1
    )
    disk_percent = _optional_int(values, 'disk_percent', maximum=100)
    if (
        disk_total is not None
        and disk_used is not None
        and disk_available is not None
        and disk_percent is not None
        and disk_total > 0
        and disk_used <= disk_total
        and disk_available <= disk_total
    ):
        result['disk'] = {
            'total_kib': disk_total,
            'used_kib': disk_used,
            'available_kib': disk_available,
            'percent': disk_percent,
        }

    uptime_value = _optional_float(
        values, 'uptime_seconds', maximum=2 ** 63 - 1
    )
    if uptime_value is not None:
        result['uptime_seconds'] = int(uptime_value)

    os_name = _safe_text(values.get('os_name'), maximum=200)
    if os_name is not None:
        result['os_name'] = os_name

    load_values = (
        _optional_float(values, 'load_1'),
        _optional_float(values, 'load_5'),
        _optional_float(values, 'load_15'),
    )
    cpu_count = _optional_int(values, 'cpu_count', maximum=1_000_000)
    if all(value is not None for value in load_values) and cpu_count:
        result['load'] = {
            'one': load_values[0],
            'five': load_values[1],
            'fifteen': load_values[2],
            'cpu_count': cpu_count,
        }

    swap_total = _optional_int(values, 'swap_total_kib', maximum=2 ** 63 - 1)
    swap_free = _optional_int(values, 'swap_free_kib', maximum=2 ** 63 - 1)
    if swap_total is not None and swap_free is not None and swap_free <= swap_total:
        result['swap'] = {
            'total_kib': swap_total,
            'available_kib': swap_free,
            'used_kib': swap_total - swap_free,
        }

    received = _optional_int(
        values, 'network_received_bytes', maximum=2 ** 64 - 1
    )
    transmitted = _optional_int(
        values, 'network_transmitted_bytes', maximum=2 ** 64 - 1
    )
    if received is not None and transmitted is not None:
        result['network'] = {
            'received_bytes': received,
            'transmitted_bytes': transmitted,
        }

    process_total = _optional_int(values, 'process_total', maximum=10_000_000)
    process_zombies = _optional_int(values, 'process_zombies', maximum=10_000_000)
    top_cpu = _parse_process_rows(repeated['process_cpu'])
    top_memory = _parse_process_rows(repeated['process_memory'])
    if (
        process_total is not None
        and process_zombies is not None
        and process_zombies <= process_total
        and (top_cpu or top_memory)
    ):
        result['processes'] = {
            'total': process_total,
            'zombies': process_zombies,
            'top_cpu': top_cpu,
            'top_memory': top_memory,
        }

    permissions = []
    for scope in repeated['permission_denied']:
        if scope in _PERMISSION_SCOPES and scope not in permissions:
            permissions.append(scope)
    if permissions:
        result['permission_denied'] = permissions

    if not result:
        raise ValueError('no supported metrics')

    return result


def _acquire_session_lock(session_id):
    with _collector_locks_guard:
        entry = _collector_locks.setdefault(
            session_id,
            {'lock': Lock(), 'references': 0},
        )
        entry['references'] += 1
        collector_lock = entry['lock']

    if collector_lock.acquire(blocking=False):
        return collector_lock

    with _collector_locks_guard:
        entry = _collector_locks.get(session_id)
        if entry and entry['lock'] is collector_lock:
            entry['references'] -= 1
            if entry['references'] == 0:
                _collector_locks.pop(session_id, None)
    return None


def _release_session_lock(session_id, collector_lock):
    with _collector_locks_guard:
        entry = _collector_locks.get(session_id)
        collector_lock.release()
        if entry and entry['lock'] is collector_lock:
            entry['references'] -= 1
            if entry['references'] == 0:
                _collector_locks.pop(session_id, None)


def collect_linux_stats(session_id, *, timeout=DEFAULT_TIMEOUT,
                        max_bytes=DEFAULT_MAX_BYTES,
                        include_diagnostics=False):
    """Collect one Linux sample without touching the interactive PTY."""
    if not isinstance(session_id, str) or not session_id:
        return None, 'transient'

    collector_lock = _acquire_session_lock(session_id)
    if collector_lock is None:
        return None, 'busy'

    channel = None
    try:
        with ssh_manager.sessions_lock:
            session = ssh_manager.sessions.get(session_id)
            if not session or not session.get('connected'):
                return None, 'transient'
            client = session.get('client')

        transport = client.get_transport() if client else None
        if not transport or not transport.is_active():
            return None, 'transient'

        command = (
            LINUX_DIAGNOSTICS_COMMAND
            if include_diagnostics is True
            else LINUX_STATS_COMMAND
        )
        channel = ssh_manager._open_exec_channel(
            transport,
            command,
            timeout=timeout,
        )
        deadline = time.monotonic() + timeout
        output = bytearray()

        def parse_output():
            try:
                text = output.decode('utf-8', errors='strict')
                return parse_linux_stats(text, max_bytes=max_bytes), None
            except (UnicodeDecodeError, ValueError):
                return None, 'unsupported'

        while True:
            if channel.recv_ready():
                chunk = channel.recv(min(4096, max_bytes + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_bytes:
                    return None, 'unsupported'
                continue
            if channel.exit_status_ready():
                break
            if time.monotonic() >= deadline:
                if output:
                    return parse_output()
                return None, 'transient'
            time.sleep(0.02)

        while channel.recv_ready():
            chunk = channel.recv(min(4096, max_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_bytes:
                return None, 'unsupported'

        if channel.recv_exit_status() != 0:
            return None, 'unsupported'

        return parse_output()
    except SSHException:
        return None, 'transient'
    except (OSError, socket.timeout):
        return None, 'transient'
    except Exception:
        return None, 'transient'
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        _release_session_lock(session_id, collector_lock)
