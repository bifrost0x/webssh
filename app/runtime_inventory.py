"""Bounded runtime inventory collection for active SSH sessions."""

import re
import socket
import time
from threading import Lock

from . import ssh_manager


DEFAULT_TIMEOUT = 2.0
DEFAULT_MAX_BYTES = 64 * 1024
MAX_SYSTEMD_SERVICES = 200
MAX_DOCKER_CONTAINERS = 50
REQUEST_RATE_LIMIT = '10 per minute'

_UNIT_NAME = re.compile(r'^[A-Za-z0-9@_.:-]{1,200}$')
_CONTAINER_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
_SYSTEMD_MANAGER_STATES = {
    'starting', 'running', 'degraded', 'maintenance',
    'stopping', 'offline', 'unknown',
}
_SYSTEMD_LOAD_STATES = {'loaded', 'not-found', 'masked', 'error', 'bad-setting'}
_ACTIVE_STATES = {
    'active', 'reloading', 'inactive', 'failed', 'activating',
    'deactivating', 'maintenance',
}
_PERMISSION_SCOPES = ('systemd', 'docker')

_collector_locks = {}
_collector_locks_guard = Lock()


RUNTIME_INVENTORY_COMMAND = r"""LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  inventory_stderr_dir=$(mktemp -d 2>/dev/null)
  if [ -n "$inventory_stderr_dir" ]; then
    systemd_state=$(systemctl show --property=SystemState --value \
      2>"$inventory_stderr_dir/systemd_state")
    systemd_state_status=$?
    systemd_state_stderr=$(cat "$inventory_stderr_dir/systemd_state" 2>/dev/null)
    systemd_units=$(systemctl list-units --type=service --all --no-legend --no-pager --plain \
      2>"$inventory_stderr_dir/systemd_units")
    systemd_units_status=$?
    systemd_units_stderr=$(cat "$inventory_stderr_dir/systemd_units" 2>/dev/null)
    if [ "$systemd_state_status" -eq 0 ] && [ "$systemd_units_status" -eq 0 ]; then
      printf 'systemd_state=%s\n' "$systemd_state"
      printf '%s\n' "$systemd_units" | awk '
        NF {
          total++
          if ($3 == "active") active++
          if ($3 == "failed") failed++
          if (NF >= 4 && returned < 200) {
            unit[returned] = $1
            load[returned] = $2
            active_state[returned] = $3
            sub_state[returned] = $4
            description = $0
            sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", description)
            details[returned] = description
            returned++
          }
        }
        END {
          print "systemd_total=" total + 0
          print "systemd_active=" active + 0
          print "systemd_failed=" failed + 0
          print "systemd_returned=" returned + 0
          for (index = 0; index < returned; index++) {
            printf "systemd_service=%s|%s|%s|%s|%s\n", unit[index], load[index], active_state[index], sub_state[index], details[index]
          }
        }' 2>/dev/null
    elif printf '%s\n%s' "$systemd_state_stderr" "$systemd_units_stderr" | grep -Eqi \
        'permission denied|access denied|not authorized|authorization denied|authentication is required'; then
      printf 'permission_denied=systemd\n'
    fi
    rm -rf "$inventory_stderr_dir" 2>/dev/null
  fi
fi

if command -v docker >/dev/null 2>&1; then
  inventory_stderr_dir=$(mktemp -d 2>/dev/null)
  if [ -n "$inventory_stderr_dir" ]; then
    docker_version=$(DOCKER_CLIENT_TIMEOUT=1 docker version --format '{{.Server.Version}}' \
      2>"$inventory_stderr_dir/docker_version")
    docker_version_status=$?
    docker_version_stderr=$(cat "$inventory_stderr_dir/docker_version" 2>/dev/null)
    docker_running=$(DOCKER_CLIENT_TIMEOUT=1 docker ps -q \
      2>"$inventory_stderr_dir/docker_running")
    docker_running_status=$?
    docker_running_stderr=$(cat "$inventory_stderr_dir/docker_running" 2>/dev/null)
    docker_total=$(DOCKER_CLIENT_TIMEOUT=1 docker ps -aq \
      2>"$inventory_stderr_dir/docker_total")
    docker_total_status=$?
    docker_total_stderr=$(cat "$inventory_stderr_dir/docker_total" 2>/dev/null)
    docker_containers=$(DOCKER_CLIENT_TIMEOUT=1 docker ps -a --format '{{.Names}}|{{.Status}}' \
      2>"$inventory_stderr_dir/docker_containers")
    docker_containers_status=$?
    docker_containers_stderr=$(cat "$inventory_stderr_dir/docker_containers" 2>/dev/null)
    if [ "$docker_version_status" -eq 0 ] \
        && [ "$docker_running_status" -eq 0 ] \
        && [ "$docker_total_status" -eq 0 ] \
        && [ "$docker_containers_status" -eq 0 ] \
        && [ -n "$docker_version" ]; then
      printf 'docker_version=%s\n' "$docker_version"
      printf '%s\n' "$docker_total" | awk 'NF { count++ } END { print "docker_total=" count + 0 }' 2>/dev/null
      printf '%s\n' "$docker_running" | awk 'NF { count++ } END { print "docker_running=" count + 0 }' 2>/dev/null
      printf '%s\n' "$docker_containers" | awk 'NF && count < 50 { print "docker_container=" $0; count++ } END { print "docker_returned=" count + 0 }' 2>/dev/null
    elif printf '%s\n%s\n%s\n%s' "$docker_version_stderr" "$docker_running_stderr" "$docker_total_stderr" "$docker_containers_stderr" | grep -Eqi \
        'permission denied|access denied|not authorized|authorization denied|authentication is required|got permission denied'; then
      printf 'permission_denied=docker\n'
    fi
    rm -rf "$inventory_stderr_dir" 2>/dev/null
  fi
fi
"""


def _safe_text(value, *, maximum):
    if not isinstance(value, str):
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        return None
    return normalized


def _optional_count(values, key):
    try:
        value = int(values[key])
    except (KeyError, TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _parse_systemd(values, rows):
    state = values.get('systemd_state', '').strip()
    total = _optional_count(values, 'systemd_total')
    active = _optional_count(values, 'systemd_active')
    failed = _optional_count(values, 'systemd_failed')
    reported_returned = _optional_count(values, 'systemd_returned')
    if (
        state not in _SYSTEMD_MANAGER_STATES
        or None in (total, active, failed, reported_returned)
        or active > total
        or failed > total
        or active + failed > total
        or reported_returned > total
        or reported_returned > MAX_SYSTEMD_SERVICES
        or len(rows) != reported_returned
    ):
        return None

    services = []
    for row in rows:
        parts = row.split('|', 4)
        if len(parts) != 5:
            continue
        unit, load, active_state, sub, description = parts
        description = _safe_text(description, maximum=240)
        sub = _safe_text(sub, maximum=64)
        if (
            not _UNIT_NAME.fullmatch(unit)
            or load not in _SYSTEMD_LOAD_STATES
            or active_state not in _ACTIVE_STATES
            or description is None
            or sub is None
        ):
            continue
        services.append({
            'unit': unit,
            'load': load,
            'active': active_state,
            'sub': sub,
            'description': description,
        })

    returned = len(services)
    return {
        'state': state,
        'total': total,
        'active': active,
        'failed': failed,
        'returned': returned,
        'truncated': total > returned,
        'services': services,
    }


def _parse_docker(values, rows):
    version = _safe_text(values.get('docker_version', ''), maximum=64)
    total = _optional_count(values, 'docker_total')
    running = _optional_count(values, 'docker_running')
    reported_returned = _optional_count(values, 'docker_returned')
    if (
        version is None
        or None in (total, running, reported_returned)
        or running > total
        or reported_returned > total
        or reported_returned > MAX_DOCKER_CONTAINERS
        or len(rows) != reported_returned
    ):
        return None

    containers = []
    for row in rows:
        name, separator, status = row.partition('|')
        status = _safe_text(status, maximum=160)
        if not separator or not _CONTAINER_NAME.fullmatch(name) or status is None:
            continue
        containers.append({'name': name, 'status': status})

    returned = len(containers)
    return {
        'version': version,
        'total': total,
        'running': running,
        'returned': returned,
        'truncated': total > returned,
        'containers': containers,
    }


def parse_runtime_inventory(text, *, max_bytes=DEFAULT_MAX_BYTES):
    """Parse the fixed inventory output without exposing untrusted text."""
    if not isinstance(text, str):
        raise ValueError('invalid inventory payload')
    if len(text.encode('utf-8')) > max_bytes:
        raise ValueError('inventory payload too large')

    single_keys = {
        'systemd_state', 'systemd_total', 'systemd_active', 'systemd_failed',
        'systemd_returned', 'docker_version', 'docker_total', 'docker_running',
        'docker_returned',
    }
    values = {}
    service_rows = []
    container_rows = []
    permissions = []
    for raw_line in text.splitlines():
        key, separator, value = raw_line.partition('=')
        if not separator:
            continue
        if key in single_keys:
            values[key] = value
        elif key == 'systemd_service':
            service_rows.append(value)
        elif key == 'docker_container':
            container_rows.append(value)
        elif key == 'permission_denied':
            scope = value.strip()
            if scope in _PERMISSION_SCOPES and scope not in permissions:
                permissions.append(scope)

    result = {}
    systemd = _parse_systemd(values, service_rows)
    if systemd is not None:
        result['systemd'] = systemd
    docker = _parse_docker(values, container_rows)
    if docker is not None:
        result['docker'] = docker
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


def _drain_ready_output(channel, output, stderr_output, max_bytes):
    """Drain both Paramiko streams fairly under one combined size limit."""
    received = False
    for ready, receive, destination in (
        (channel.recv_ready, channel.recv, output),
        (channel.recv_stderr_ready, channel.recv_stderr, stderr_output),
    ):
        if not ready():
            continue
        remaining = max_bytes + 1 - len(output) - len(stderr_output)
        if remaining <= 0:
            return received, True
        chunk = receive(min(4096, remaining))
        if not chunk:
            continue
        destination.extend(chunk)
        received = True
        if len(output) + len(stderr_output) > max_bytes:
            return received, True
    return received, False


def collect_runtime_inventory(session_id, *, timeout=DEFAULT_TIMEOUT,
                              max_bytes=DEFAULT_MAX_BYTES):
    """Collect a bounded runtime inventory without touching the interactive PTY."""
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

        channel = ssh_manager._open_exec_channel(
            transport, RUNTIME_INVENTORY_COMMAND, timeout=timeout,
        )
        deadline = time.monotonic() + timeout
        output = bytearray()
        stderr_output = bytearray()

        while True:
            received, too_large = _drain_ready_output(
                channel, output, stderr_output, max_bytes,
            )
            if too_large:
                return None, 'unavailable'
            if received:
                continue
            if channel.exit_status_ready():
                break
            if time.monotonic() >= deadline:
                return None, 'unavailable'
            time.sleep(0.02)

        while True:
            received, too_large = _drain_ready_output(
                channel, output, stderr_output, max_bytes,
            )
            if too_large:
                return None, 'unavailable'
            if not received:
                break

        if channel.recv_exit_status() != 0:
            return None, 'unavailable'
        if stderr_output:
            return None, 'unavailable'
        return parse_runtime_inventory(
            output.decode('utf-8', errors='strict'), max_bytes=max_bytes,
        ), None
    except (OSError, socket.timeout, UnicodeDecodeError, ValueError):
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
