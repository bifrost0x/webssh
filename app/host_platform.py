"""Small, read-only platform facts collected through an existing SSH transport."""
import re
import time

from .host_catalog import (
    PLATFORMS, SERVICES, MAX_SERVICES, NON_POSIX_PLATFORMS, CONTAINER_ACCESS, VIRT_KINDS,
    SERVICE_UNITS, SERVICE_UNIT_TEMPLATES, SERVICE_PATHS, SERVICE_SNAPS, SERVICE_IMAGES,
    FAMILIES, KERNEL_PLATFORMS, MARKER_PLATFORMS, OS_ID_PLATFORMS, VIRT_MAP,
)

# Catalog values end up unquoted inside the shell text below; quoting them all
# would push the wrapped probe past Dropbear's 9000-byte command limit. They are
# fixed strings, but a later edit must never be able to bring in shell syntax,
# so every one must be a plain literal word: no quotes, expansions, globs,
# tilde, '=' or whitespace, no leading '-', and no reserved word.
_SHELL_WORD = re.compile(r'[A-Za-z0-9/][A-Za-z0-9@_.:/+-]*')
_RESERVED_WORDS = frozenset({'if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'case', 'esac',
                             'while', 'until', 'for', 'in', 'function', 'select', 'time'})


def _shell_word(value):
    if not isinstance(value, str) or not _SHELL_WORD.fullmatch(value) or value in _RESERVED_WORDS:
        raise ValueError('Unsafe value in the identity probe: %r' % (value,))
    return value


def _shell_path(value):
    if not isinstance(value, str) or not value.startswith('/'):
        raise ValueError('Unsafe path in the identity probe: %r' % (value,))
    return _shell_word(value)


_IDENTITY_TEMPLATE = r"""LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/snap/bin
export LC_ALL PATH
found() { printf 'service=%s\n' "$1"; }
if [ -r /etc/os-release ]; then
  head -c 2048 /etc/os-release 2>/dev/null | awk -F= '$1 ~ /^(ID|ID_LIKE|VERSION_ID|VARIANT_ID)$/ && !seen[$1]++ { print substr($0, 1, 200) }'
fi
printf 'kernel=%s\n' "$(uname -s 2>/dev/null)"
if [ -r /proc/device-tree/model ]; then
  printf 'model='; head -c 160 /proc/device-tree/model 2>/dev/null | tr -d '\000-\037'; printf '\n'
fi
if [ -r /etc/pve/.version ] || [ -d /usr/share/pve-manager ]; then printf 'marker=proxmox\n';
elif [ -r /conf/config.xml ] && [ -d /usr/local/opnsense ]; then printf 'marker=opnsense\n';
elif [ -r /etc/version ]; then
  head -c 256 /etc/version 2>/dev/null | awk '/^TrueNAS-/ { print "marker=truenas"; exit }'
fi
if [ -d /usr/share/proxmox-backup ] || [ -d /etc/proxmox-backup ]; then printf 'marker=proxmoxbackup\n'; fi
pf=/etc/platform
if head -c 256 "$pf" 2>/dev/null | grep -q pfSense; then printf 'marker=pfsense\n'; fi
if [ -e /etc/unraid-version ]; then printf 'marker=unraid\n'; fi
if [ -r /etc.defaults/VERSION ] && head -c 2048 /etc.defaults/VERSION 2>/dev/null | grep -qi synology; then printf 'marker=synology\n'; fi
if [ -e /etc/config/uLinux.conf ]; then printf 'marker=qnap\n'; fi
if [ -e /etc/openwrt_release ]; then printf 'marker=openwrt\n'; fi
if { [ -d /opt/vyatta ] && [ ! -e /usr/libexec/vyos ] && ! head -c 256 /opt/vyatta/etc/version 2>/dev/null | grep -qi vyos; } || { [ -r /usr/lib/version ] && head -c 256 /usr/lib/version 2>/dev/null | grep -q UniFi; }; then printf 'marker=ubiquiti\n'; fi
virt=$(systemd-detect-virt 2>/dev/null | head -n 1 | cut -c1-32)
if [ -z "$virt" ] || [ "$virt" = none ]; then
  if [ -e /.dockerenv ]; then virt=docker
  elif [ -e /run/.containerenv ]; then virt=podman
  elif head -c 4096 /proc/1/cgroup 2>/dev/null | grep -q -e docker -e kubepods -e containerd; then virt=docker
  elif head -c 4096 /proc/1/cgroup 2>/dev/null | grep -q lxc; then virt=lxc
  fi
fi
if [ -n "$virt" ]; then printf 'virt=%s\n' "$virt"; fi
if command -v systemctl >/dev/null 2>&1; then
  target=$(systemctl get-default 2>/dev/null | head -n 1 | cut -c1-40)
  if [ -n "$target" ]; then printf 'target=%s\n' "$target"; fi
  systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | head -n 2000 | {
    wireguard=
    while read -r name rest; do
      name=${name%.service}
      case "$name" in
        wg-quick@*) wireguard=1 ;;
@UNITCASE@
@TEMPLATECASE@
      esac
    done
    if [ -n "$wireguard" ]; then found wireguard; fi
  } | sort -u
fi
if [ -r /etc/pve/qemu-server ] && [ -x /etc/pve/qemu-server ] && [ -r /etc/pve/lxc ] && [ -x /etc/pve/lxc ]; then
  printf 'guests=%s\n' "$(ls /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf 2>/dev/null | wc -l | tr -d ' ')"
fi
@PATHS@
@SNAPS@
images=
@ENGINES@
printf '%s\n' "$images" | sed '/^$/d' | sort -u | head -n 100 | cut -c1-120 | awk '{ used += length($0) + 7; if (used > 3000) exit; print "image=" $0 }'
:
"""

# Docker is only asked through a local daemon socket, named explicitly with -H:
# a plain "docker ps" follows docker contexts and DOCKER_HOST (ssh://, tcp://)
# to other hosts, and the podman-docker shim would start rootless podman.
# podman-docker also links docker.sock to the Podman API socket; such a link
# names Podman, which is then asked through that socket like its own.
_DOCKER_BLOCK = r"""dsock=
if [ -S /var/run/docker.sock ]; then dsock=/var/run/docker.sock
elif [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ]; then dsock=$XDG_RUNTIME_DIR/docker.sock
fi
psock=
if [ -n "$dsock" ] && [ -h "$dsock" ] && command -v readlink >/dev/null 2>&1; then
  case $(readlink "$dsock" 2>/dev/null | head -c 256) in
    *podman*) psock=$dsock; dsock= ;;
  esac
fi
if [ -n "$dsock" ]; then
  found docker
  if command -v docker >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    if out=$(timeout 1 docker -H "unix://$dsock" ps --format '{{.Image}}' 2>/dev/null); then
      printf 'engine=docker:ok\n'
      images=$(printf '%s\n%s' "$images" "$out")
    else
      printf 'engine=docker:denied\n'
    fi
  fi
fi"""

# Podman is only asked through an existing API socket (--remote): a plain
# "podman ps" would start a rootless runtime and create state in the user's home.
_PODMAN_BLOCK = r"""if [ -n "$psock" ] || command -v podman >/dev/null 2>&1; then
  sock=$psock
  if [ -z "$sock" ] && [ -S /run/podman/podman.sock ]; then sock=/run/podman/podman.sock
  elif [ -z "$sock" ] && [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then sock=$XDG_RUNTIME_DIR/podman/podman.sock
  fi
  found podman
  if [ -n "$sock" ] && command -v podman >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    if out=$(timeout 1 podman --remote --url "unix://$sock" ps --format '{{.Image}}' 2>/dev/null); then
      printf 'engine=podman:ok\n'
      images=$(printf '%s\n%s' "$images" "$out")
    else
      printf 'engine=podman:denied\n'
    fi
  fi
fi"""


# A line ending in one of these continues on the next; any other line ends a command.
_CONTINUED = re.compile(r'(?:^|\s)(?:then|do|else|in)$|[{|;&]$')


def _one_line(script):
    """Join a script into one line, with '; ' where a line ended a command.

    Refuses a script whose meaning the join would change: a comment, or a line
    that ends inside quotes, where the newline belongs to the quoted text.
    """
    parts = []
    for raw in script.split('\n'):
        line = raw.strip()
        if not line:
            continue
        quote, escaped, previous = None, False, ' '
        for char in line:
            if escaped:
                escaped = False
            elif quote == "'":
                quote = None if char == "'" else quote
            elif char == '\\':
                escaped = True
            elif quote == '"':
                quote = None if char == '"' else quote
            elif char in '\'"':
                quote = char
            elif char == '#' and previous in ' \t;|&(':
                raise ValueError('A comment cannot be joined into one line: %r' % line)
            previous = char
        if quote or escaped:
            raise ValueError('A quoted newline cannot be joined into one line: %r' % line)
        parts.append(line)
        parts.append(' ' if _CONTINUED.search(line) else '; ')
    return ''.join(parts[:-1])


def _identity_command(units, paths, snaps, templates=None):
    unit_patterns = '|'.join(_shell_word(unit) for unit in units)
    unit_case = ("        %s) printf 'unit=%%s\\n' \"$name\" ;;" % unit_patterns) if unit_patterns else ''
    # Instances of a templated unit (syncthing@alice) name their service directly.
    template_case = '\n'.join("        %s@*) found %s ;;" % (_shell_word(prefix), _shell_word(service))
                               for prefix, service in (templates or {}).items())
    [_shell_word(service) for service in (*units.values(), *(s for _, s in paths), *snaps.values())]
    by_service = {}
    for path, service in paths:
        by_service.setdefault(service, []).append(path)
    path_lines = '\n'.join(
        'if %s; then found %s; fi' % (' || '.join('[ -e %s ]' % _shell_path(path) for path in found), service)
        for service, found in by_service.items()
    )
    snap_lines = '\n'.join('[ -d /snap/%s ] && echo snap=%s' % (_shell_word(snap), snap) for snap in snaps)
    engines = _DOCKER_BLOCK + '\n' + _PODMAN_BLOCK
    return (_IDENTITY_TEMPLATE.replace('@UNITCASE@', unit_case).replace('@TEMPLATECASE@', template_case)
            .replace('@PATHS@', path_lines)
            .replace('@SNAPS@', snap_lines).replace('@ENGINES@', engines))


# One read-only probe for everything the host identity needs: os-release, kernel,
# board model, platform markers, virtualization, systemd target, guest count,
# known services and, where the SSH user may already talk to a Docker or Podman
# daemon (no sudo), the names of running images. Nothing is installed, changed
# or sourced; every file read is bounded. It is sent as one line, which csh
# and tcsh login shells need; IDENTITY_SCRIPT holds the same commands by line.
IDENTITY_SCRIPT = _identity_command(SERVICE_UNITS, SERVICE_PATHS, SERVICE_SNAPS, SERVICE_UNIT_TEMPLATES)
IDENTITY_COMMAND = _one_line(IDENTITY_SCRIPT)


def _posix_sh(script):
    """A command line that runs script under /bin/sh from any common login shell.

    sshd hands an exec request to the user's login shell, which may be fish,
    csh or tcsh. Single quotes keep their content literal in sh, bash, zsh,
    fish, csh and tcsh alike, except that fish also reads \\\\ and \\' inside
    them, zsh with RC_QUOTES reads '' as a quote, and csh and tcsh end the
    command at a newline. A one-line script without those sequences therefore
    reaches /bin/sh unchanged in all of them; csh history expansion does not
    apply to a command given with -c. nu has not been tried.
    """
    if ('\\\\' in script or "\\'" in script or "''" in script or '\n' in script or '\r' in script
            or script.startswith("'") or script.endswith(("'", '\\'))):
        raise ValueError('The script cannot be quoted for every login shell')
    return "exec /bin/sh -c '%s'" % script.replace("'", "'\\''")


IDENTITY_EXEC = _posix_sh(IDENTITY_COMMAND)

# Pending package updates and a required restart. WebSSH never runs this on its
# own: only a workflow the user starts or explicitly schedules executes it, and
# the overview takes its result from such a run. Reads only what the host
# already knows: no package metadata refresh, no lock, no sudo, and no file
# written, also as root (apt's planner log and binary caches are off). Neither
# apt-check nor dnf is asked: both write caches or logs even when only reading.
# Counts therefore lag behind the repositories until the host refreshes them
# itself; systems without apt report only the restart marker.
MAINTENANCE_COMMAND = r'''LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf 'reboot=yes\n';
elif [ -d /var/lib/dpkg ]; then printf 'reboot=no\n'; fi
command -v timeout >/dev/null 2>&1 || exit 0
command -v apt-get >/dev/null 2>&1 || exit 0
# Without downloaded package lists every count would read 0, so report none.
set -- /var/lib/apt/lists/*_Packages*
[ -e "$1" ] || exit 0
if simulated=$(timeout 6 apt-get -s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null); then
  printf 'apt=%s\n' "$(printf '%s\n' "$simulated" | grep -c '^Inst ')"
  printf 'aptsecurity=%s\n' "$(printf '%s\n' "$simulated" | grep '^Inst ' | grep -ci 'securi')"
fi
:
'''
_MAX_PACKAGE_COUNT = 100000

# The restart marker test of MAINTENANCE_COMMAND alone: no package manager,
# no sudo, no writes. It runs only where that marker was seen before, so its
# absence means a restart on any system. See recheck_reboot_hint.
REBOOT_HINT_COMMAND = r'''LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf 'reboot=yes\n';
else printf 'reboot=no\n'; fi
:
'''
# Matches the overview, which stops showing facts older than a week.
REBOOT_HINT_MAX_AGE_SECONDS = 7 * 24 * 3600


def parse_maintenance(text, *, max_bytes=1024):
    """Return {'reboot_required', 'updates', 'security_updates'}; unknown values stay None."""
    if not isinstance(text, str) or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('Invalid maintenance facts')
    if any(ord(char) < 32 and char not in '\n\r\t' for char in text):
        raise ValueError('Invalid maintenance facts')
    facts = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator and key not in facts:
            facts[key] = value.strip()

    def count(value):
        if value is None or not re.fullmatch(r'[0-9]{1,6}', value):
            return None
        number = int(value)
        return number if number <= _MAX_PACKAGE_COUNT else None

    reboot = {'yes': True, 'no': False}.get(facts.get('reboot'))
    updates = security = None
    if 'apt' in facts:
        updates, security = count(facts['apt']), count(facts.get('aptsecurity'))
    if updates is not None and security is not None and security > updates:
        security = updates
    return {'reboot_required': reboot, 'updates': updates, 'security_updates': security}


def valid_maintenance(value):
    if not isinstance(value, dict) or set(value) - {'reboot_required', 'updates', 'security_updates', 'checked_at'}:
        return False
    if value.get('reboot_required') is not None and type(value['reboot_required']) is not bool:
        return False
    for field in ('updates', 'security_updates'):
        number = value.get(field)
        if number is not None and (type(number) is not int or not 0 <= number <= _MAX_PACKAGE_COUNT):
            return False
    checked = value.get('checked_at')
    return checked is None or (not isinstance(checked, bool) and isinstance(checked, (int, float)))


# Identity facts change; a saved host is probed again at most once a week.
IDENTITY_REFRESH_SECONDS = 7 * 24 * 3600
# A channel that printed nothing before the deadline is asked again sooner.
SILENT_RETRY_SECONDS = 24 * 3600


def valid_services(value):
    return (isinstance(value, list) and len(value) <= MAX_SERVICES
            and all(isinstance(item, str) and item in SERVICES for item in value))


_OS_RELEASE_KEYS = ('ID', 'ID_LIKE', 'VERSION_ID', 'VARIANT_ID')
_SINGLE_KEYS = frozenset({*_OS_RELEASE_KEYS, 'kernel', 'model', 'virt', 'target', 'guests'})
_REPEATED_KEYS = frozenset({'marker', 'service', 'unit', 'snap', 'image', 'engine'})
_MAX_FACT_LENGTH = 200
_CONTROL = re.compile(r'[\x00-\x08\x0a-\x1f\x7f-\x9f]')
# ANSI CSI (ESC [ ... final byte) and OSC (ESC ] ... BEL or ESC \) sequences.
_TERMINAL_SEQUENCE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)')
_OS_ID = re.compile(r'[a-z0-9._-]{1,32}')
_OS_VERSION = re.compile(r'[0-9][0-9A-Za-z._-]{0,15}')
_PI_MODEL = re.compile(r'Raspberry Pi [A-Za-z0-9 .+()-]{1,120}')
_GUESTS = re.compile(r'[0-9]{1,4}')
_ENGINES = {'docker:ok': ('docker', 'ok'), 'docker:denied': ('docker', 'denied'),
            'podman:ok': ('podman', 'ok'), 'podman:denied': ('podman', 'denied')}


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def parse_identity(text, *, max_bytes=8192):
    """Map IDENTITY_COMMAND output to catalog ids, enums and checked patterns.

    Anything that does not map is dropped. Output without a kernel line did not
    come from the probe (forced command, menu, banner) and reports 'unavailable'.
    """
    if not isinstance(text, str) or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('Invalid identity facts')
    single, repeated, duplicates = {}, {}, set()
    # Only '\n' ends a line: str.splitlines() would also split on U+2028 and
    # similar characters a hostile value could carry.
    for line in text.split('\n'):
        line = line[:-1] if line.endswith('\r') else line
        # The probe never prints C0, DEL or C1 controls. A line with one came
        # from a shell startup file (coloured greetings) or is hostile; it is
        # dropped whole, so no control character can start a new key.
        if _CONTROL.search(line):
            continue
        key, separator, value = line.partition('=')
        value = value.strip()
        if not separator or len(value) > _MAX_FACT_LENGTH:
            continue
        if key in _SINGLE_KEYS:
            if key in single:
                duplicates.add(key)
            single[key] = _unquote(value) if key in _OS_RELEASE_KEYS else value
        elif key in _REPEATED_KEYS:
            repeated.setdefault(key, []).append(value)
    result = {
        'state': 'unavailable', 'platform': None, 'family': None, 'os_id': None, 'os_version': None,
        'virt': None, 'graphical': None, 'guests': None, 'services': [], 'container_access': None,
    }
    if 'kernel' not in single:
        return result
    # A key the probe prints once but that came twice cannot be trusted either way.
    facts = {key: value for key, value in single.items() if key not in duplicates}

    os_id = facts.get('ID', '')
    os_id = os_id if _OS_ID.fullmatch(os_id) else ''
    family = next((FAMILIES[token] for token in facts.get('ID_LIKE', '').split() if token in FAMILIES), None)
    markers = set(repeated.get('marker', ()))
    released = OS_ID_PLATFORMS.get(os_id) or family
    platform = next((MARKER_PLATFORMS[marker] for marker in MARKER_PLATFORMS if marker in markers), None)
    if platform is None and _PI_MODEL.fullmatch(facts.get('model', '')):
        platform = 'raspberrypi'
    if platform is None:
        platform = released or KERNEL_PLATFORMS.get(facts.get('kernel'))
    stored_os_id = os_id if os_id and os_id not in OS_ID_PLATFORMS else None

    # VERSION_ID numbers the system os-release names. On Proxmox, TrueNAS or a
    # Raspberry Pi board that is the base distribution (Debian 12, FreeBSD 14),
    # not the platform shown, so it is kept only next to its own system.
    version = facts.get('VERSION_ID', '') if (released and released == platform) or stored_os_id else ''
    guests = facts.get('guests', '')
    target = facts.get('target')
    result.update({
        'state': 'detected',
        'platform': platform,
        'family': family,
        'os_id': stored_os_id,
        'os_version': version if _OS_VERSION.fullmatch(version) else None,
        'virt': VIRT_MAP.get(facts.get('virt')),
        'graphical': (target == 'graphical.target') if target else None,
        'guests': int(guests) if _GUESTS.fullmatch(guests) else None,
    })

    services, access = set(), set()
    for value in repeated.get('service', ()):
        if value in SERVICES:
            services.add(value)
    for value in repeated.get('unit', ()):
        if value in SERVICE_UNITS:
            services.add(SERVICE_UNITS[value])
    for value in repeated.get('snap', ()):
        if value in SERVICE_SNAPS:
            services.add(SERVICE_SNAPS[value])
    for value in repeated.get('image', ()):
        image = value.lower()
        match = next((name for name, pattern in SERVICE_IMAGES if pattern.search(image)), None)
        if match:
            services.add(match)
    for value in repeated.get('engine', ()):
        if value in _ENGINES:
            engine, state = _ENGINES[value]
            services.add(engine)
            access.add(state)
    result['services'] = sorted(services)[:MAX_SERVICES]
    # 'denied' also covers a stopped daemon or a timeout; one readable engine is enough for 'ok'.
    if 'ok' in access:
        result['container_access'] = 'ok'
    elif access:
        result['container_access'] = 'denied'
    return result


def _member(catalog):
    return lambda item: isinstance(item, str) and item in catalog


def _pattern(pattern):
    return lambda item: isinstance(item, str) and pattern.fullmatch(item) is not None


# What parse_identity may report per key besides None; 'state' and 'services' are checked apart.
_IDENTITY_VALUES = {
    'platform': _member(PLATFORMS),
    'family': _member(frozenset(FAMILIES.values())),
    'os_id': _pattern(_OS_ID),
    'os_version': _pattern(_OS_VERSION),
    'virt': _member(VIRT_KINDS),
    'graphical': lambda item: type(item) is bool,
    'guests': lambda item: type(item) is int and 0 <= item <= 9999,
    'container_access': _member(CONTAINER_ACCESS),
}
_IDENTITY_KEYS = frozenset({'state', 'services', *_IDENTITY_VALUES})


def valid_identity_value(key, value):
    """True for a value other than None that parse_identity can report under key."""
    check = _IDENTITY_VALUES.get(key)
    return check is not None and value is not None and check(value)


def valid_identity(value):
    """True only for a parse_identity result: every key present, every value from its catalog or pattern."""
    if not isinstance(value, dict) or set(value) != _IDENTITY_KEYS or value['state'] not in ('detected', 'unavailable'):
        return False
    return valid_services(value['services']) and all(
        value[key] is None or check(value[key]) for key, check in _IDENTITY_VALUES.items())


def _has_probe_line(text):
    for line in text.split('\n'):
        line = line[:-1] if line.endswith('\r') else line
        key, separator, _ = line.partition('=')
        if separator and not _CONTROL.search(line) and (key in _SINGLE_KEYS or key in _REPEATED_KEYS):
            return True
    return False


def _identity_at_deadline(output):
    """Decide a probe answer that had not ended when the deadline passed.

    The probe prints os-release and its kernel line within milliseconds. With
    a complete kernel line, or any other complete line in the probe's own
    key=value form, it is our probe that hung (pmxcfs, D-Bus, a stale network
    mount, a container query), and what comes after that step is missing: no
    fact is stored, and the probe is asked again after a day, not on every
    login, so a host that always hangs does not collect a stuck shell per
    connection. Other readable text is a forced command or menu that waits
    and is not asked again this week. A channel that stayed silent, or
    printed only control sequences, may also be a login shell that starts
    slowly and is asked again after a day.
    """
    if not output:
        return None, 'silent'
    complete = output[:output.rfind(b'\n') + 1]
    try:
        identity = parse_identity(complete.decode('utf-8'))
        text = output.decode('utf-8', errors='replace')
    except (UnicodeDecodeError, ValueError):
        return None, 'unsupported'
    if identity['state'] == 'detected' or _has_probe_line(complete.decode('utf-8')):
        return None, 'stalled'
    # Nothing printable besides colour, cursor or window title sequences (a
    # startup file preparing the terminal): no menu or message was shown yet.
    if not _CONTROL.sub('', _TERMINAL_SEQUENCE.sub('', text)).strip():
        return None, 'silent'
    return None, 'unsupported'


def collect_identity(session_id, *, cancel_event=None):
    from .session_insights import collect_linux_stats
    return collect_linux_stats(
        session_id, timeout=4.0, max_bytes=8192,
        command=IDENTITY_EXEC, parser=parse_identity,
        allow_partial=False, cancel_event=cancel_event,
        on_deadline=_identity_at_deadline,
    )


def endpoint(profile):
    from .network_policy import canonicalize_hostname
    try:
        host = canonicalize_hostname(profile.get('host'))
    except ValueError:
        return None
    username = profile.get('username')
    port = profile.get('port', 22)
    if not isinstance(username, str) or not username or type(port) is not int or not 1 <= port <= 65535:
        return None
    return (host, port, username, profile.get('jump_host_id') or None,
            profile.get('socks_proxy_id') or None)


def identity_needed(profile, now=None):
    """Probe only saved hosts in automatic mode, at most once a week.

    Detection opens an extra exec channel. On keys with a forced command
    (authorized_keys command=, sshd ForceCommand) the server runs that command
    instead, so the probe must not repeat on every connection, also when its
    answer was unusable. A manual icon turns probing off, and so does a login
    greeting from a system without a POSIX shell.
    """
    if not isinstance(profile, dict) or profile.get('platform_icon', 'auto') not in (None, 'auto'):
        return False
    if profile.get('greeting_platform') in NON_POSIX_PLATFORMS:
        return False
    # 'server' came from the old platform probe; the identity probe never reports it.
    if profile.get('detected_platform') == 'server' and 'detection_state' not in profile:
        return True
    checked = profile.get('platform_checked_at')
    if isinstance(checked, bool) or not isinstance(checked, (int, float)):
        return True
    current = time.time() if now is None else now
    return not 0 <= current - checked < IDENTITY_REFRESH_SECONDS


def reboot_hint_needs_check(profile, now=None):
    """True only while the overview shows a restart hint from a check the user ran."""
    facts = profile.get('detected_maintenance') if isinstance(profile, dict) else None
    if not isinstance(facts, dict) or facts.get('reboot_required') is not True or facts.get('recheck_stopped'):
        return False
    checked = facts.get('checked_at')
    if isinstance(checked, bool) or not isinstance(checked, (int, float)):
        return False
    age = (time.time() if now is None else now) - checked
    return -24 * 3600 <= age <= REBOOT_HINT_MAX_AGE_SECONDS


def parse_reboot_hint(text, *, max_bytes=64):
    """Accept exactly the one line REBOOT_HINT_COMMAND prints; banners or extra lines are not an answer."""
    if not isinstance(text, str) or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('Invalid restart marker answer')
    answer = {'reboot=yes': True, 'reboot=no': False}.get(text.strip())
    if answer is None:
        raise ValueError('Invalid restart marker answer')
    return answer


def collect_reboot_hint(session_id, *, cancel_event=None):
    from .session_insights import collect_linux_stats
    return collect_linux_stats(
        session_id, timeout=1.5, max_bytes=64,
        command=REBOOT_HINT_COMMAND, parser=parse_reboot_hint,
        allow_partial=False, cancel_event=cancel_event,
    )


def recheck_reboot_hint(session_id, user_id, publish, *, cancel_event=None):
    """Reread only the restart marker on login while a restart hint is shown.

    Hosts without a hint are never asked anything. The hint exists only after
    the user ran or scheduled the Updates and restart status check, which read
    the same marker over the same login, so this repeats a read the user
    already chose. Exactly "reboot=no" lowers the hint, exactly "reboot=yes"
    keeps it for the next login. Any other answer may come from a forced
    command (authorized_keys command=, ForceCommand) that the server runs in
    place of ours, so the recheck stops for this hint until the next full
    check. All failures leave the PTY alone.
    """
    from . import ssh_manager, profile_manager
    try:
        with ssh_manager.sessions_lock:
            session = ssh_manager.sessions.get(session_id)
            if not session or session.get('user_id') != user_id or not session.get('connected'):
                return
            expected = endpoint(session)
            profile_id = session.get('profile_id')
        if expected is None or not profile_id or (cancel_event is not None and cancel_event.is_set()):
            return
        profile = profile_manager.get_profile(user_id, profile_id)
        if not profile or endpoint(profile) != expected or not reboot_hint_needs_check(profile):
            return
        checked_at = profile['detected_maintenance']['checked_at']
        answer, error = collect_reboot_hint(session_id, cancel_event=cancel_event)
        # Busy means another sample held the session; nothing reached the host.
        if error == 'busy' or answer is True or (cancel_event is not None and cancel_event.is_set()):
            return
        with ssh_manager.sessions_lock:
            current = ssh_manager.sessions.get(session_id)
            if current is not session or not current.get('connected') or endpoint(current) != expected:
                return
        if answer is False and not error:
            if profile_manager.settle_reboot_hint(user_id, profile_id, expected, checked_at, cleared=True):
                publish({'profile_id': profile_id})
            return
        profile_manager.settle_reboot_hint(user_id, profile_id, expected, checked_at, cleared=False)
    except Exception:
        return


def detect_connected_platform(session_id, user_id, publish, *, cancel_event=None):
    """Optional weekly work per saved host; all failures leave the PTY alone."""
    from . import ssh_manager, profile_manager
    try:
        with ssh_manager.sessions_lock:
            session = ssh_manager.sessions.get(session_id)
            if not session or session.get('user_id') != user_id or not session.get('connected'):
                return
            expected = endpoint(session)
            if expected is None:
                return
            profile_id = session.get('profile_id')
        if cancel_event is not None and cancel_event.is_set():
            return
        # Quick connections have nowhere to keep a result; saved hosts keep it
        # until their address, port, user or route changes.
        profile = profile_manager.get_profile(user_id, profile_id) if profile_id else None
        if not identity_needed(profile):
            return
        identity, error = collect_identity(session_id, cancel_event=cancel_event)
        checked_at = time.time()
        # Silence may be a slow shell start and a stall a hung mount; both are
        # asked again after a day by recording the check as that much older.
        if error in ('silent', 'stalled'):
            checked_at -= IDENTITY_REFRESH_SECONDS - SILENT_RETRY_SECONDS
        if error == 'stalled':
            identity = None
        elif error in ('unsupported', 'silent'):
            # The host answered, but not with the probe's output: a forced
            # command, a menu or a shell without the tools. Asking again on
            # every login would only run that command again.
            identity = {key: None for key in _IDENTITY_KEYS} | {'state': 'unavailable', 'services': []}
        elif error or not valid_identity(identity):
            return
        with ssh_manager.sessions_lock:
            current = ssh_manager.sessions.get(session_id)
            if (current is not session or not current.get('connected') or endpoint(current) != expected
                    or (cancel_event is not None and cancel_event.is_set())):
                return
            if identity is not None and identity['platform'] is not None:
                current['detected_platform'] = identity['platform']
        if identity is None:
            # Only the attempt is recorded; stored facts stay as they are.
            profile_manager.record_identity_attempt(user_id, profile_id, expected, now=checked_at)
            return
        # Silence may only be a slow shell: it does not undo an earlier detection.
        if not profile_manager.cache_detected_facts(user_id, profile_id, expected, identity=identity, now=checked_at,
                                                    keep_detected=error == 'silent'):
            return
        if identity['state'] != 'detected':
            return
        payload = {'session_id': session_id, 'profile_id': profile_id, 'services': list(identity['services']),
                   'identity': dict(identity, services=list(identity['services']))}
        if identity['platform'] is not None:
            payload['platform'] = identity['platform']
        publish(payload)
    except Exception:
        return
