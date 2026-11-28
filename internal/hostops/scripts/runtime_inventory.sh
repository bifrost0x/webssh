LC_ALL=C
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
        BEGIN { stored = 0 }
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
        BEGIN { stored = 0 }
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
