"""Small, read-only platform facts collected through an existing SSH transport."""
import re
import time

PLATFORMS = frozenset({
    'server', 'proxmox', 'raspberrypi', 'homeassistant', 'truenas',
    'opnsense', 'ubuntu', 'debian', 'fedora', 'archlinux', 'alpinelinux',
    'linux', 'apple', 'freebsd', 'docker',
})

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


SERVICES = frozenset({
    'docker', 'podman', 'nginx', 'apache', 'caddy', 'mariadb', 'postgresql', 'samba', 'k3s',
    'wireguard', 'nextcloud', 'pihole', 'homeassistant', 'jellyfin', 'plex', 'portainer',
    'traefik', 'vaultwarden', 'immich', 'gitea', 'paperless', 'grafana', 'adguard',
    'uptimekuma', 'nginxproxymanager',
})
MAX_SERVICES = 16
# Services change; a saved host is checked again at most once a week.
SERVICE_REFRESH_SECONDS = 7 * 24 * 3600
_SERVICE_FLAGS = {'docker', 'podman', 'nextcloud', 'pihole', 'wireguard'}
_SERVICE_UNITS = {
    'nginx': 'nginx', 'apache2': 'apache', 'httpd': 'apache', 'caddy': 'caddy', 'mariadb': 'mariadb',
    'mysql': 'mariadb', 'postgresql': 'postgresql', 'smbd': 'samba', 'k3s': 'k3s',
}
# First match wins; specific names come before generic ones.
_SERVICE_IMAGES = (
    ('nginxproxymanager', re.compile(r'nginx-proxy-manager')),
    ('nextcloud', re.compile(r'nextcloud')),
    ('homeassistant', re.compile(r'home-?assistant')),
    ('jellyfin', re.compile(r'jellyfin')),
    ('plex', re.compile(r'(^|/)(plex|pms-docker)')),
    ('portainer', re.compile(r'portainer')),
    ('traefik', re.compile(r'traefik')),
    ('vaultwarden', re.compile(r'vaultwarden|bitwarden')),
    ('immich', re.compile(r'immich')),
    ('gitea', re.compile(r'gitea|forgejo')),
    ('paperless', re.compile(r'paperless')),
    ('grafana', re.compile(r'grafana')),
    ('pihole', re.compile(r'pi-?hole')),
    ('adguard', re.compile(r'adguard')),
    ('uptimekuma', re.compile(r'uptime-kuma')),
    ('mariadb', re.compile(r'(^|/)(mariadb|mysql)(:|@|$)')),
    ('postgresql', re.compile(r'(^|/)postgres(ql)?(:|@|$)')),
    ('nginx', re.compile(r'(^|/)nginx(:|@|$)')),
    ('caddy', re.compile(r'(^|/)caddy(:|@|$)')),
)


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
