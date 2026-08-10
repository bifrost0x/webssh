"""Bounded, agentless Linux diagnostics for an active SSH session."""

import math
import re
import socket
import time
from threading import Lock

from . import ssh_manager


DEFAULT_MAX_BYTES = 16 * 1024
DEFAULT_TIMEOUT = 2.0
REQUEST_RATE_LIMIT = '30 per minute'

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


LINUX_DIAGNOSTICS_COMMAND = LINUX_STATS_COMMAND + r"""
awk '
  /^SwapTotal:/ { print "swap_total_kib=" $2 }
  /^SwapFree:/ { print "swap_free_kib=" $2 }
' /proc/meminfo
awk '{
  print "load_1=" $1
  print "load_5=" $2
  print "load_15=" $3
}' /proc/loadavg
awk '/^cpu[0-9]+ / { count++ } END {
  if (count > 0) print "cpu_count=" count
}' /proc/stat
awk -F '[: ]+' 'NR > 2 {
  if ($2 != "lo") {
    received += $3
    transmitted += $11
  }
} END {
  print "network_received_bytes=" received + 0
  print "network_transmitted_bytes=" transmitted + 0
}' /proc/net/dev

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

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemd_state=$(systemctl show --property=SystemState --value 2>&1)
  systemd_state_status=$?
  systemd_units=$(systemctl list-units --type=service --all --no-legend --no-pager 2>&1)
  systemd_units_status=$?
  if [ "$systemd_state_status" -eq 0 ] && [ "$systemd_units_status" -eq 0 ]; then
    printf 'systemd_state=%s\n' "$systemd_state"
    printf '%s\n' "$systemd_units" | awk '
      $3 == "active" { running++ }
      $3 == "failed" { failed++ }
      END {
        print "systemd_running=" running + 0
        print "systemd_failed=" failed + 0
      }'
    printf '%s\n' "$systemd_units" | awk '$3 == "failed" && count < 5 {
      print "systemd_failed_unit=" $1
      count++
    }'
  elif printf '%s\n%s' "$systemd_state" "$systemd_units" | grep -Eqi \
      'permission denied|access denied|not authorized|authorization denied|authentication is required'; then
    printf 'permission_denied=systemd\n'
  fi
fi

if command -v docker >/dev/null 2>&1; then
  docker_version=$(docker version --format '{{.Server.Version}}' 2>&1)
  docker_status=$?
  if [ "$docker_status" -eq 0 ] && [ -n "$docker_version" ]; then
    printf 'docker_version=%s\n' "$docker_version"
    docker ps -q 2>/dev/null | awk 'NF { count++ } END {
      print "docker_running=" count + 0
    }'
    docker ps -aq 2>/dev/null | awk 'NF { count++ } END {
      print "docker_total=" count + 0
    }'
    docker ps --format '{{.Names}}|{{.Status}}' 2>/dev/null | head -n 5 \
      | sed 's/^/docker_container=/'
  elif printf '%s' "$docker_version" | grep -Eqi \
      'permission denied|access denied|not authorized|authorization denied|got permission denied'; then
    printf 'permission_denied=docker\n'
  fi
fi
"""


_SINGLE_KEYS = {
    'cpu', 'mem_total_kib', 'mem_available_kib',
    'disk_total_kib', 'disk_used_kib', 'disk_available_kib',
    'disk_percent', 'uptime_seconds', 'os_name',
    'load_1', 'load_5', 'load_15', 'cpu_count',
    'swap_total_kib', 'swap_free_kib',
    'network_received_bytes', 'network_transmitted_bytes',
    'process_total', 'process_zombies',
    'systemd_state', 'systemd_running', 'systemd_failed',
    'docker_version', 'docker_running', 'docker_total',
}
_MULTI_KEYS = {
    'process_cpu', 'process_memory', 'systemd_failed_unit',
    'docker_container', 'permission_denied',
}
_PERMISSION_SCOPES = ('processes', 'systemd', 'docker')
_UNIT_NAME = re.compile(r'^[A-Za-z0-9@_.:-]{1,200}$')
_CONTAINER_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


def _non_negative_int(values, key):
    try:
        value = int(values[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'invalid {key}') from exc
    if value < 0:
        raise ValueError(f'invalid {key}')
    return value


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

    result = {
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

    systemd_state = _safe_text(values.get('systemd_state'), maximum=32)
    systemd_running = _optional_int(values, 'systemd_running', maximum=10_000_000)
    systemd_failed = _optional_int(values, 'systemd_failed', maximum=10_000_000)
    failed_units = [
        unit for unit in repeated['systemd_failed_unit'][:5]
        if _UNIT_NAME.fullmatch(unit)
    ]
    if (
        systemd_state is not None
        and re.fullmatch(r'[a-z-]+', systemd_state)
        and systemd_running is not None
        and systemd_failed is not None
        and (systemd_failed == 0 or failed_units)
    ):
        result['systemd'] = {
            'state': systemd_state,
            'running': systemd_running,
            'failed': systemd_failed,
            'failed_units': failed_units,
        }

    docker_version = _safe_text(values.get('docker_version'), maximum=64)
    docker_running = _optional_int(values, 'docker_running', maximum=10_000_000)
    docker_total = _optional_int(values, 'docker_total', maximum=10_000_000)
    containers = []
    for row in repeated['docker_container'][:5]:
        name, separator, status = row.partition('|')
        status = _safe_text(status, maximum=160)
        if separator and _CONTAINER_NAME.fullmatch(name) and status is not None:
            containers.append({'name': name, 'status': status})
    if (
        docker_version is not None
        and docker_running is not None
        and docker_total is not None
        and docker_running <= docker_total
    ):
        result['docker'] = {
            'version': docker_version,
            'running': docker_running,
            'total': docker_total,
            'containers': containers,
        }

    permissions = []
    for scope in repeated['permission_denied']:
        if scope in _PERMISSION_SCOPES and scope not in permissions:
            permissions.append(scope)
    if permissions:
        result['permission_denied'] = permissions

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
        return None, 'unavailable'

    collector_lock = _acquire_session_lock(session_id)
    if collector_lock is None:
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
