"""Small, read-only platform facts collected through an existing SSH transport."""
import re

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
    return (host, port, username, profile.get('jump_host_id') or None)

def detect_connected_platform(session_id, user_id, publish, *, cancel_event=None):
    """Optional once-per-connection work; all failures leave the PTY alone."""
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
        platform, error = collect_platform(session_id, cancel_event=cancel_event)
        if error or platform not in PLATFORMS:
            return
        with ssh_manager.sessions_lock:
            current = ssh_manager.sessions.get(session_id)
            if (current is not session or not current.get('connected') or endpoint(current) != expected
                    or (cancel_event is not None and cancel_event.is_set())):
                return
            current['detected_platform'] = platform
        if profile_id and not profile_manager.cache_detected_platform(user_id, profile_id, expected, platform):
            return
        publish({'session_id': session_id, 'profile_id': profile_id, 'platform': platform})
    except Exception:
        return
