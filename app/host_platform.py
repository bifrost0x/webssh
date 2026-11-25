"""Small, read-only platform facts collected through an existing SSH transport."""
import re
import time

from .host_catalog import (
    PLATFORMS, SERVICES, MAX_SERVICES, SERVICE_UNITS as _SERVICE_UNITS, SERVICE_IMAGES as _SERVICE_IMAGES,  # noqa: F401
    SERVICE_UNITS, SERVICE_PATHS, SERVICE_SNAPS, SERVICE_IMAGES,
    FAMILIES, KERNEL_PLATFORMS, MARKER_PLATFORMS, OS_ID_PLATFORMS, VIRT_MAP,
)

PLATFORM_COMMAND = r'''LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
if [ -r /etc/os-release ]; then
  head -c 2048 /etc/os-release 2>/dev/null | awk '/^(ID|VARIANT_ID)=/ { print }'
fi
printf 'kernel=%s\n' "$(uname -s 2>/dev/null)"
if [ -r /proc/device-tree/model ]; then
  printf 'model='; head -c 160 /proc/device-tree/model 2>/dev/null | tr -d '\000'; printf '\n'
fi
if [ -r /etc/pve/.version ] || [ -d /usr/share/pve-manager ]; then printf 'marker=proxmox\n';
elif [ -r /conf/config.xml ] && [ -d /usr/local/opnsense ]; then printf 'marker=opnsense\n';
elif [ -r /etc/version ]; then
  head -c 256 /etc/version 2>/dev/null | awk '/^TrueNAS-/ { print "marker=truenas"; exit }'
fi
:
'''


# Services and apps a host runs. Kept separate from the platform probe: it
# also asks a Docker or Podman daemon the SSH user may already use, without
# sudo, and lists only image names. Nothing is installed, changed or sourced.
SERVICES_COMMAND = r'''LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/snap/bin
export LC_ALL PATH
found() { printf 'service=%s\n' "$1"; }
if command -v docker >/dev/null 2>&1 || [ -S /var/run/docker.sock ]; then found docker; fi
if command -v podman >/dev/null 2>&1; then found podman; fi
if command -v systemctl >/dev/null 2>&1; then
  for unit in nginx apache2 httpd caddy mariadb mysql postgresql smbd k3s; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then found "unit:$unit"; fi
  done
  if systemctl list-units --state=active --no-legend --plain 'wg-quick@*' 2>/dev/null | grep -q .; then found wireguard; fi
fi
if [ -f /var/www/nextcloud/occ ] || [ -f /var/www/html/nextcloud/occ ] || [ -d /snap/nextcloud ]; then found nextcloud; fi
if command -v pihole >/dev/null 2>&1 || [ -d /etc/pihole ]; then found pihole; fi
if command -v timeout >/dev/null 2>&1; then
  for engine in docker podman; do
    if command -v "$engine" >/dev/null 2>&1; then
      timeout 2 "$engine" ps --format '{{.Image}}' 2>/dev/null | head -n 30 | cut -c1-120 | sed 's/^/image=/'
    fi
  done
fi
:
'''

# Catalog values end up inside the shell text below. They are fixed strings, but
# a later edit must never be able to bring in shell syntax, so every one is
# checked against a conservative pattern and then single-quoted.
_SHELL_WORD = re.compile(r'[A-Za-z0-9@_.:/+-]+')


def _shell_word(value):
    if not isinstance(value, str) or not _SHELL_WORD.fullmatch(value):
        raise ValueError('Unsafe value in the identity probe: %r' % (value,))
    return "'%s'" % value


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
if [ -d /opt/vyatta ] || { [ -r /usr/lib/version ] && head -c 256 /usr/lib/version 2>/dev/null | grep -q UniFi; }; then printf 'marker=ubiquiti\n'; fi
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
      esac
    done
    if [ -n "$wireguard" ]; then found wireguard; fi
  }
fi
if [ -d /etc/pve ] && [ -r /etc/pve ]; then
  printf 'guests=%s\n' "$(ls /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf 2>/dev/null | wc -l | tr -d ' ')"
fi
@PATHS@
@SNAPS@
images=
@ENGINES@
printf '%s\n' "$images" | sed '/^$/d' | sort -u | head -n 100 | cut -c1-120 | awk '{ used += length($0) + 7; if (used > 3000) exit; print "image=" $0 }'
:
"""

_DOCKER_BLOCK = r"""if command -v docker >/dev/null 2>&1 || [ -S /var/run/docker.sock ]; then found docker; fi
if command -v docker >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  if out=$(timeout 2 docker ps --format '{{.Image}}' 2>/dev/null); then
    printf 'engine=docker:ok\n'
    images="$images
$out"
  else
    printf 'engine=docker:denied\n'
  fi
fi"""

# Podman is only asked through an existing API socket (--remote): a plain
# "podman ps" would start a rootless runtime and create state in the user's home.
_PODMAN_BLOCK = r"""if command -v podman >/dev/null 2>&1; then
  sock=
  if [ -S /run/podman/podman.sock ]; then sock=/run/podman/podman.sock
  elif [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then sock=$XDG_RUNTIME_DIR/podman/podman.sock
  fi
  if [ -z "$sock" ]; then found podman
  elif command -v timeout >/dev/null 2>&1; then
    if out=$(timeout 2 podman --remote --url "unix://$sock" ps --format '{{.Image}}' 2>/dev/null); then
      printf 'engine=podman:ok\n'
      images="$images
$out"
    else
      printf 'engine=podman:denied\n'
    fi
  fi
fi"""


def _identity_command(units, paths, snaps):
    unit_patterns = '|'.join(_shell_word(unit) for unit in units)
    unit_case = ("        %s) printf 'unit=%%s\\n' \"$name\" ;;" % unit_patterns) if unit_patterns else ''
    [_shell_word(service) for service in (*units.values(), *(s for _, s in paths), *snaps.values())]
    by_service = {}
    for path, service in paths:
        by_service.setdefault(service, []).append(path)
    path_lines = '\n'.join(
        'if %s; then found %s; fi' % (' || '.join('[ -e %s ]' % _shell_word(path) for path in found), service)
        for service, found in by_service.items()
    )
    snap_lines = '\n'.join(
        "if [ -d %s ]; then printf 'snap=%%s\\n' %s; fi" % (_shell_word('/snap/' + snap), _shell_word(snap))
        for snap in snaps
    )
    engines = _DOCKER_BLOCK + '\n' + _PODMAN_BLOCK
    return (_IDENTITY_TEMPLATE.replace('@UNITCASE@', unit_case).replace('@PATHS@', path_lines)
            .replace('@SNAPS@', snap_lines).replace('@ENGINES@', engines))


# One read-only probe for everything the host identity needs: os-release, kernel,
# board model, platform markers, virtualization, systemd target, guest count,
# known services and, where the SSH user may already talk to a Docker or Podman
# daemon (no sudo), the names of running images. Nothing is installed, changed
# or sourced; every file read is bounded.
IDENTITY_COMMAND = _identity_command(SERVICE_UNITS, SERVICE_PATHS, SERVICE_SNAPS)

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


# Services change; a saved host is checked again at most once a week.
SERVICE_REFRESH_SECONDS = 7 * 24 * 3600
_SERVICE_FLAGS = {'docker', 'podman', 'nextcloud', 'pihole', 'wireguard'}


def parse_services(text, *, max_bytes=6144):
    """Map the fixed service facts to known names; anything else is ignored."""
    if not isinstance(text, str) or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('Invalid service facts')
    if any(ord(char) < 32 and char not in '\n\r\t' for char in text):
        raise ValueError('Invalid service facts')
    found = set()
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        value = value.strip()
        if not separator or len(value) > 160:
            continue
        if key == 'service':
            if value in _SERVICE_FLAGS:
                found.add(value)
            elif value.startswith('unit:') and value[5:] in _SERVICE_UNITS:
                found.add(_SERVICE_UNITS[value[5:]])
        elif key == 'image':
            image = value.lower()
            match = next((name for name, pattern in _SERVICE_IMAGES if pattern.search(image)), None)
            if match:
                found.add(match)
    return sorted(found)[:MAX_SERVICES]


def valid_services(value):
    return (isinstance(value, list) and len(value) <= MAX_SERVICES
            and all(isinstance(item, str) and item in SERVICES for item in value))


def parse_platform(text, *, max_bytes=4096):
    if not isinstance(text, str) or len(text.encode('utf-8')) > max_bytes:
        raise ValueError('Invalid platform facts')
    if any(ord(char) < 32 and char not in '\n\r\t' for char in text):
        raise ValueError('Invalid platform facts')
    facts = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in {'ID', 'VARIANT_ID', 'kernel', 'model', 'marker'}:
            continue
        if key in facts or len(value) > 256:
            raise ValueError('Invalid platform facts')
        facts[key] = value.strip().strip('\"\'')
    marker = facts.get('marker')
    if marker in {'proxmox', 'opnsense', 'truenas'}:
        return marker
    if re.fullmatch(r'Raspberry Pi [A-Za-z0-9 .+()-]{1,120}', facts.get('model', '')):
        return 'raspberrypi'
    identity = facts.get('ID', '')
    aliases = {'haos': 'homeassistant', 'truenas': 'truenas', 'alpine': 'alpinelinux', 'arch': 'archlinux'}
    if identity in aliases:
        return aliases[identity]
    if identity in {'ubuntu', 'debian', 'fedora'}:
        return identity
    return {'Linux': 'linux', 'Darwin': 'apple', 'FreeBSD': 'freebsd'}.get(facts.get('kernel'), 'server')


_OS_RELEASE_KEYS = ('ID', 'ID_LIKE', 'VERSION_ID', 'VARIANT_ID')
_SINGLE_KEYS = frozenset({*_OS_RELEASE_KEYS, 'kernel', 'model', 'virt', 'target', 'guests'})
_MAX_FACT_LENGTH = 200
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
    if any(ord(char) < 32 and char not in '\n\r\t' for char in text):
        raise ValueError('Invalid identity facts')
    single, repeated, duplicates = {}, {}, set()
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        value = value.strip()
        if not separator or len(value) > _MAX_FACT_LENGTH:
            continue
        if key in _SINGLE_KEYS:
            if key in single:
                duplicates.add(key)
            single[key] = _unquote(value) if key in _OS_RELEASE_KEYS else value
        elif key in {'marker', 'service', 'unit', 'snap', 'image', 'engine'}:
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
    platform = next((MARKER_PLATFORMS[marker] for marker in MARKER_PLATFORMS if marker in markers), None)
    if platform is None and _PI_MODEL.fullmatch(facts.get('model', '')):
        platform = 'raspberrypi'
    if platform is None:
        platform = OS_ID_PLATFORMS.get(os_id) or family or KERNEL_PLATFORMS.get(facts.get('kernel'))

    version = facts.get('VERSION_ID', '')
    guests = facts.get('guests', '')
    target = facts.get('target')
    result.update({
        'state': 'detected',
        'platform': platform,
        'family': family,
        'os_id': os_id if os_id and os_id not in OS_ID_PLATFORMS else None,
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
    # 'denied' also covers a stopped daemon or a timeout: some containers could not be read.
    if 'denied' in access:
        result['container_access'] = 'denied'
    elif access:
        result['container_access'] = 'ok'
    elif not services & {'docker', 'podman'}:
        result['container_access'] = 'none'
    return result


def collect_services(session_id, *, cancel_event=None):
    from .session_insights import collect_linux_stats
    return collect_linux_stats(
        session_id, timeout=4.0, max_bytes=6144,
        command=SERVICES_COMMAND, parser=parse_services,
        allow_partial=False, cancel_event=cancel_event,
    )


def collect_platform(session_id, *, cancel_event=None):
    from .session_insights import collect_linux_stats
    return collect_linux_stats(
        session_id, timeout=1.5, max_bytes=4096,
        command=PLATFORM_COMMAND, parser=parse_platform,
        allow_partial=False, cancel_event=cancel_event,
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

def needs_detection(profile, now=None):
    """Probe only saved hosts in automatic mode without a result or a recent service check.

    Detection opens extra exec channels. On keys with a forced command
    (authorized_keys command=, sshd ForceCommand) the server runs that command
    instead, so the probe must not repeat on every connection: the platform is
    read once, services at most once a week. A manual icon turns probing off.
    """
    return bool(platform_needed(profile) or services_needed(profile, now))


def platform_needed(profile):
    if not isinstance(profile, dict) or profile.get('platform_icon', 'auto') not in (None, 'auto'):
        return False
    return profile.get('detected_platform') not in PLATFORMS


def services_needed(profile, now=None):
    if not isinstance(profile, dict) or profile.get('platform_icon', 'auto') not in (None, 'auto'):
        return False
    checked = profile.get('services_checked_at')
    if isinstance(checked, bool) or not isinstance(checked, (int, float)):
        return True
    current = time.time() if now is None else now
    return not 0 <= current - checked < SERVICE_REFRESH_SECONDS


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
    """Optional once-per-host work; all failures leave the PTY alone."""
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
        if not needs_detection(profile):
            return
        platform = None
        if platform_needed(profile):
            platform, error = collect_platform(session_id, cancel_event=cancel_event)
            if error or platform not in PLATFORMS:
                platform = None
        services = None
        if services_needed(profile) and not (cancel_event is not None and cancel_event.is_set()):
            services, error = collect_services(session_id, cancel_event=cancel_event)
            if error or not valid_services(services):
                services = None
        if platform is None and services is None:
            return
        with ssh_manager.sessions_lock:
            current = ssh_manager.sessions.get(session_id)
            if (current is not session or not current.get('connected') or endpoint(current) != expected
                    or (cancel_event is not None and cancel_event.is_set())):
                return
            if platform is not None:
                current['detected_platform'] = platform
        if not profile_manager.cache_detected_facts(user_id, profile_id, expected, platform=platform, services=services):
            return
        payload = {'session_id': session_id, 'profile_id': profile_id}
        if platform is not None:
            payload['platform'] = platform
        if services is not None:
            payload['services'] = services
        publish(payload)
    except Exception:
        return
