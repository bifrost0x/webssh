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

for inventory_utility in awk cat dd grep mkfifo mktemp rm rmdir; do
  command -v "$inventory_utility" >/dev/null 2>&1 || exit 0
done

inventory_dir=$(mktemp -d "${TMPDIR:-/tmp}/webssh-inventory.XXXXXX" 2>/dev/null) || exit 0
[ -n "$inventory_dir" ] || exit 0

cleanup_runtime_inventory() {
  for inventory_file in \
      stdout.pipe stderr.pipe \
      systemd_state.out systemd_state.err systemd_units.out systemd_units.err \
      docker_version.out docker_version.err docker_running.out docker_running.err \
      docker_total.out docker_total.err docker_containers.out docker_containers.err; do
    rm -f "$inventory_dir/$inventory_file" 2>/dev/null
  done
  rmdir "$inventory_dir" 2>/dev/null
}

trap 'cleanup_runtime_inventory' 0
trap 'exit 1' HUP INT TERM

capture_inventory_stderr() {
  dd bs=1 count=4096 of="$1" 2>/dev/null
  cat >/dev/null
}

capture_inventory_stdout() {
  case "$1" in
    systemd_state)
      awk '
        NF && !seen {
          value = substr($0, 1, 64)
          seen = 1
        }
        END {
          if (seen) print "systemd_state=" value
        }'
      ;;
    systemd_units)
      awk '
        NF {
          total++
          if ($3 == "active") active++
          if ($3 == "failed") failed++
          if (NF >= 4 && stored < 200) {
            unit[stored] = substr($1, 1, 200)
            load[stored] = substr($2, 1, 32)
            active_state[stored] = substr($3, 1, 32)
            sub_state[stored] = substr($4, 1, 64)
            description = $0
            sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", description)
            details[stored] = substr(description, 1, 240)
            stored++
          }
        }
        END {
          used = 0
          emitted = 0
          for (row = 0; row < stored; row++) {
            line = sprintf("systemd_service=%s|%s|%s|%s|%s", unit[row], load[row], active_state[row], sub_state[row], details[row])
            line_size = length(line) + 1
            if (used + line_size > 46080) break
            used += line_size
            emitted++
          }
          printf "systemd_total=%.0f\n", total + 0
          printf "systemd_active=%.0f\n", active + 0
          printf "systemd_failed=%.0f\n", failed + 0
          printf "systemd_returned=%.0f\n", emitted + 0
          for (row = 0; row < emitted; row++) {
            printf "systemd_service=%s|%s|%s|%s|%s\n", unit[row], load[row], active_state[row], sub_state[row], details[row]
          }
        }'
      ;;
    docker_version)
      awk '
        NF && !seen {
          value = substr($0, 1, 64)
          seen = 1
        }
        END {
          if (seen) print "docker_version=" value
        }'
      ;;
    docker_running)
      awk 'NF { count++ } END { printf "docker_running=%.0f\n", count + 0 }'
      ;;
    docker_total)
      awk 'NF { count++ } END { printf "docker_total=%.0f\n", count + 0 }'
      ;;
    docker_containers)
      awk '
        NF && stored < 50 {
          separator = index($0, "|")
          if (separator) {
            names[stored] = substr($0, 1, separator - 1)
            statuses[stored] = substr($0, separator + 1)
          } else {
            names[stored] = $0
            statuses[stored] = ""
          }
          names[stored] = substr(names[stored], 1, 128)
          statuses[stored] = substr(statuses[stored], 1, 160)
          stored++
        }
        END {
          used = 0
          emitted = 0
          for (row = 0; row < stored; row++) {
            line = sprintf("docker_container=%s|%s", names[row], statuses[row])
            line_size = length(line) + 1
            if (used + line_size > 12288) break
            used += line_size
            emitted++
          }
          printf "docker_returned=%.0f\n", emitted + 0
          for (row = 0; row < emitted; row++) {
            printf "docker_container=%s|%s\n", names[row], statuses[row]
          }
        }'
      ;;
    *)
      cat >/dev/null
      return 1
      ;;
  esac
}

run_bounded_inventory_command() {
  inventory_kind=$1
  inventory_stdout_file=$2
  inventory_stderr_file=$3
  shift 3
  rm -f "$inventory_dir/stdout.pipe" "$inventory_dir/stderr.pipe" \
    "$inventory_stdout_file" "$inventory_stderr_file" 2>/dev/null
  mkfifo "$inventory_dir/stdout.pipe" 2>/dev/null || return 125
  if ! mkfifo "$inventory_dir/stderr.pipe" 2>/dev/null; then
    rm -f "$inventory_dir/stdout.pipe" 2>/dev/null
    return 125
  fi

  capture_inventory_stdout "$inventory_kind" \
    <"$inventory_dir/stdout.pipe" >"$inventory_stdout_file" 2>/dev/null &
  inventory_stdout_pid=$!
  capture_inventory_stderr "$inventory_stderr_file" \
    <"$inventory_dir/stderr.pipe" &
  inventory_stderr_pid=$!

  "$@" >"$inventory_dir/stdout.pipe" 2>"$inventory_dir/stderr.pipe"
  inventory_command_status=$?
  wait "$inventory_stdout_pid"
  inventory_stdout_status=$?
  wait "$inventory_stderr_pid"
  inventory_stderr_status=$?
  rm -f "$inventory_dir/stdout.pipe" "$inventory_dir/stderr.pipe" 2>/dev/null

  if [ "$inventory_stdout_status" -ne 0 ] || [ "$inventory_stderr_status" -ne 0 ]; then
    return 125
  fi
  return "$inventory_command_status"
}

has_inventory_permission_error() {
  grep -Eiq 'permission denied|access denied|not authorized|authorization denied|authentication is required|got permission denied' "$@"
}

run_docker_inventory_command() {
  DOCKER_CLIENT_TIMEOUT=1 docker "$@"
}

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  run_bounded_inventory_command systemd_state \
    "$inventory_dir/systemd_state.out" "$inventory_dir/systemd_state.err" \
    systemctl show --property=SystemState --value
  systemd_state_status=$?
  run_bounded_inventory_command systemd_units \
    "$inventory_dir/systemd_units.out" "$inventory_dir/systemd_units.err" \
    systemctl list-units --type=service --all --no-legend --no-pager --plain
  systemd_units_status=$?
  if [ "$systemd_state_status" -eq 0 ] && [ "$systemd_units_status" -eq 0 ] \
      && [ -s "$inventory_dir/systemd_state.out" ]; then
    cat "$inventory_dir/systemd_state.out" "$inventory_dir/systemd_units.out"
  elif has_inventory_permission_error \
      "$inventory_dir/systemd_state.err" "$inventory_dir/systemd_units.err"; then
    printf 'permission_denied=systemd\n'
  fi
  rm -f "$inventory_dir/systemd_state.out" "$inventory_dir/systemd_state.err" \
    "$inventory_dir/systemd_units.out" "$inventory_dir/systemd_units.err" 2>/dev/null
fi

if command -v docker >/dev/null 2>&1; then
  run_bounded_inventory_command docker_version \
    "$inventory_dir/docker_version.out" "$inventory_dir/docker_version.err" \
    run_docker_inventory_command version --format '{{.Server.Version}}'
  docker_version_status=$?
  run_bounded_inventory_command docker_running \
    "$inventory_dir/docker_running.out" "$inventory_dir/docker_running.err" \
    run_docker_inventory_command ps -q
  docker_running_status=$?
  run_bounded_inventory_command docker_total \
    "$inventory_dir/docker_total.out" "$inventory_dir/docker_total.err" \
    run_docker_inventory_command ps -aq
  docker_total_status=$?
  run_bounded_inventory_command docker_containers \
    "$inventory_dir/docker_containers.out" "$inventory_dir/docker_containers.err" \
    run_docker_inventory_command ps -a --format '{{.Names}}|{{.Status}}'
  docker_containers_status=$?
  if [ "$docker_version_status" -eq 0 ] \
      && [ "$docker_running_status" -eq 0 ] \
      && [ "$docker_total_status" -eq 0 ] \
      && [ "$docker_containers_status" -eq 0 ] \
      && [ -s "$inventory_dir/docker_version.out" ]; then
    cat "$inventory_dir/docker_version.out" "$inventory_dir/docker_total.out" \
      "$inventory_dir/docker_running.out" "$inventory_dir/docker_containers.out"
  elif has_inventory_permission_error \
      "$inventory_dir/docker_version.err" "$inventory_dir/docker_running.err" \
      "$inventory_dir/docker_total.err" "$inventory_dir/docker_containers.err"; then
    printf 'permission_denied=docker\n'
  fi
  rm -f "$inventory_dir/docker_version.out" "$inventory_dir/docker_version.err" \
    "$inventory_dir/docker_running.out" "$inventory_dir/docker_running.err" \
    "$inventory_dir/docker_total.out" "$inventory_dir/docker_total.err" \
    "$inventory_dir/docker_containers.out" "$inventory_dir/docker_containers.err" 2>/dev/null
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
