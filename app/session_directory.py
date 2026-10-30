"""Read the interactive shell's directory without writing to its PTY.

Linux/OpenSSH only: an exec channel and the PTY shell are children of the
same SSH connection process. Ambiguous or inaccessible processes fail closed.
tmux supplies its active pane PID instead. No remote startup files are changed.
"""

import re
import shlex
import time
from threading import Lock

from . import ssh_manager


PROBE = r'''
LC_ALL=C; export LC_ALL
command -v ps >/dev/null && command -v readlink >/dev/null || exit 1
__DIRECTORY_SELECT__
case "$directory_pid" in ''|*[!0-9]*) exit 1;; esac
# Follow the foreground process group, including a nested interactive shell.
directory_fg=$(ps -o tpgid= -p "$directory_pid" | tr -d ' ')
case "$directory_fg" in ''|*[!0-9]*) exit 1;; esac
directory_shell=$(ps -o comm= -p "$directory_fg")
directory_ready=0
case "$directory_shell" in bash|zsh|fish|sh|dash|ksh) directory_ready=1;; esac
if [ "$directory_ready" = 1 ]; then
  directory_pid=$directory_fg
else
  # A foreground command can belong to a nested shell. Keep that shell's
  # directory rather than falling back to the outer login shell.
  directory_walk=$directory_fg
  directory_found=0
  for directory_step in 1 2 3 4 5 6 7 8; do
    directory_walk=$(ps -o ppid= -p "$directory_walk" | tr -d ' ')
    case "$directory_walk" in ''|*[!0-9]*) exit 1;; esac
    directory_name=$(ps -o comm= -p "$directory_walk")
    case "$directory_name" in
      bash|zsh|fish|sh|dash|ksh)
        directory_pid=$directory_walk
        directory_shell=$directory_name
        directory_found=1
        break
        ;;
    esac
    [ "$directory_walk" != 1 ] || exit 1
  done
  [ "$directory_found" = 1 ] || exit 1
fi
directory_path=$(readlink -n "/proc/$directory_pid/cwd" && printf '.') || exit 1
directory_path=${directory_path%.}
printf 'webssh-directory\000%s\000%s\000%s\000%s\000' "$directory_pid" "$directory_ready" "$directory_shell" "$directory_path"
if [ "${directory_marker+x}" = x ]; then
  printf '%s\000%s\000' "${directory_paste-}" "$directory_marker"
elif [ "${directory_paste+x}" = x ]; then printf '%s\000' "$directory_paste"; fi
'''

DIRECT_SHELL = r'''
directory_parent=$(ps -o ppid= -p "$$" | tr -d ' ')
directory_pid=$(ps -o pid=,tty= --ppid "$directory_parent" | awk '$2 != "?" {print $1}')
'''


def probe_command(session):
    name = session.get('tmux_session_name')
    if session.get('use_tmux') and name:
        select = (
            "directory_pane=$(tmux display-message -p -t "
            + shlex.quote('=' + name + ':')
            + " '#{?pane_in_mode,0,#{?alternate_on,0,#{pane_pid}}}:#{bracket_paste_flag}:#{@webssh_sync_v1}') || exit 1\n"
            + 'directory_pid=${directory_pane%%:*}\n'
            + 'directory_rest=${directory_pane#*:}\n'
            + 'directory_marker=${directory_rest#*:}\n'
            + 'directory_paste=${directory_rest%%:*}\n'
            # Older tmux versions expand an unknown format to an empty value.
            # Keep directory following available without claiming prompt readiness.
            + 'case "$directory_paste" in 0|1) ;; "") unset directory_paste;; *) exit 1;; esac\n'
            + '[ "$directory_pid" != 0 ] || exit 1'
        )
    else:
        select = DIRECT_SHELL
    # The login shell may be fish/csh; explicitly interpret the probe as POSIX sh.
    return 'exec sh -c ' + shlex.quote(PROBE.replace('__DIRECTORY_SELECT__', select))


def parse_directory(payload):
    parts = payload.decode('utf-8', errors='strict').split('\0')
    if len(parts) not in {6, 7, 8} or parts[0] != 'webssh-directory' or parts[-1]:
        raise ValueError('Invalid directory response')
    if len(parts) == 7 and parts[5] not in {'0', '1'}:
        raise ValueError('Invalid pane prompt mode')
    if len(parts) == 8 and parts[5] not in {'', '0', '1'}:
        raise ValueError('Invalid pane prompt mode')
    pid, ready, shell, path = parts[1:5]
    if (not pid.isascii() or not pid.isdigit() or int(pid) <= 0
            or ready not in {'0', '1'}
            or shell not in {'bash', 'zsh', 'fish', 'sh', 'dash', 'ksh'}
            or not path.startswith('/')
            or len(path.encode('utf-8')) > 4096
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path)):
        raise ValueError('Unsupported directory')
    result = {
        'path': path,
        'shell_ready': ready == '1',
        'shell_id': pid,
        'shell': shell,
    }
    if len(parts) >= 7 and parts[5]:
        result['bracketed_paste'] = parts[5] == '1'
    if len(parts) == 8 and shell == 'bash':
        marker = re.fullmatch(r'([0-9]+):([1-9][0-9]{0,14}):([pcb])', parts[6])
        if parts[6] and not marker:
            raise ValueError('Invalid prompt marker')
        if marker and marker[1] == pid:
            result['prompt'] = {'generation': int(marker[2]), 'phase': marker[3]}
    return result


def collect_directory(session_id, timeout=2.0):
    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(session_id)
        if not session or not session.get('connected'):
            return None, 'disconnected'
        lock = session.setdefault('directory_probe_lock', Lock())
        if not lock.acquire(blocking=False):
            return None, 'busy'
        client = session.get('client')
    channel = None
    try:
        transport = client.get_transport() if client else None
        if not transport or not transport.is_active():
            return None, 'disconnected'
        channel = ssh_manager._open_exec_channel(
            transport, probe_command(session), timeout=timeout,
        )
        deadline = time.monotonic() + timeout
        output = bytearray()
        while True:
            if time.monotonic() >= deadline:
                return None, 'unavailable'
            if channel.recv_ready():
                chunk = channel.recv(8193 - len(output))
                if not chunk:
                    if channel.exit_status_ready():
                        break
                    time.sleep(0.02)
                    continue
                output.extend(chunk)
                if len(output) > 8192:
                    return None, 'unsupported'
            elif channel.exit_status_ready():
                break
            else:
                time.sleep(0.02)
        if channel.recv_exit_status() != 0:
            return None, 'unsupported'
        result = parse_directory(output)
        if session.get('use_tmux') and session.get('tmux_session_name'):
            # tmux itself uses the outer terminal's alternate screen. The
            # probe above separately rejects an alternate screen inside its pane.
            result['tmux'] = True
        return result, None
    except (ValueError, UnicodeError):
        return None, 'unsupported'
    except Exception:
        return None, 'unavailable'
    finally:
        try:
            if channel is not None:
                channel.close()
        finally:
            lock.release()
