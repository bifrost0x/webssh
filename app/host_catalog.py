"""Fixed catalogs for host identity detection.

Everything a remote host reports is mapped onto the ids defined here; nothing
the host prints is stored or shown directly.
"""
import re

PLATFORMS = frozenset({
    'server', 'proxmox', 'raspberrypi', 'homeassistant', 'truenas',
    'opnsense', 'ubuntu', 'debian', 'fedora', 'archlinux', 'alpinelinux',
    'linux', 'apple', 'freebsd', 'docker',
    'proxmoxbackup', 'rockylinux', 'almalinux', 'redhat', 'centos', 'opensuse',
    'nixos', 'manjaro', 'endeavouros', 'linuxmint', 'popos', 'kalilinux',
    'gentoo', 'voidlinux', 'unraid', 'synology', 'qnap', 'openwrt', 'pfsense',
    'windows', 'mikrotik', 'cisco', 'ubiquiti', 'embedded',
})

# Recognised from a login banner only; no POSIX probe runs on them.
NON_POSIX_PLATFORMS = frozenset({'windows', 'mikrotik', 'cisco'})

# Ids the POSIX probe never reports. 'embedded' (dropbear) is only a banner hint:
# dropbear also serves ordinary POSIX hosts, so it must not suppress the probe.
BANNER_ONLY_PLATFORMS = NON_POSIX_PLATFORMS | {'embedded'}

# os-release ID
OS_ID_PLATFORMS = {
    'ubuntu': 'ubuntu', 'debian': 'debian', 'fedora': 'fedora',
    'rocky': 'rockylinux', 'almalinux': 'almalinux', 'rhel': 'redhat', 'centos': 'centos',
    'opensuse': 'opensuse', 'opensuse-leap': 'opensuse', 'opensuse-tumbleweed': 'opensuse',
    'sles': 'opensuse', 'sled': 'opensuse',
    'nixos': 'nixos', 'manjaro': 'manjaro', 'endeavouros': 'endeavouros',
    'linuxmint': 'linuxmint', 'pop': 'popos', 'kali': 'kalilinux',
    'gentoo': 'gentoo', 'void': 'voidlinux', 'arch': 'archlinux', 'alpine': 'alpinelinux',
    'haos': 'homeassistant', 'truenas': 'truenas', 'openwrt': 'openwrt',
    'raspbian': 'raspberrypi', 'freebsd': 'freebsd',
}

# os-release ID_LIKE token
FAMILIES = {
    'debian': 'debian', 'ubuntu': 'ubuntu', 'rhel': 'redhat', 'fedora': 'fedora',
    'centos': 'redhat', 'suse': 'opensuse', 'opensuse': 'opensuse', 'arch': 'archlinux',
    'alpine': 'alpinelinux', 'gentoo': 'gentoo',
}

# Read-only probe marker -> platform
MARKER_PLATFORMS = {
    'proxmox': 'proxmox', 'proxmoxbackup': 'proxmoxbackup', 'truenas': 'truenas',
    'opnsense': 'opnsense', 'pfsense': 'pfsense', 'unraid': 'unraid',
    'synology': 'synology', 'qnap': 'qnap', 'openwrt': 'openwrt', 'ubiquiti': 'ubiquiti',
}

# uname -s
KERNEL_PLATFORMS = {'Linux': 'linux', 'Darwin': 'apple', 'FreeBSD': 'freebsd'}

VIRT_KINDS = frozenset({'bare-metal', 'vm', 'lxc', 'container', 'wsl'})
VIRT_MAP = {
    'none': 'bare-metal',
    'kvm': 'vm', 'qemu': 'vm', 'vmware': 'vm', 'microsoft': 'vm', 'oracle': 'vm',
    'xen': 'vm', 'bochs': 'vm', 'parallels': 'vm', 'bhyve': 'vm',
    'amazon': 'vm', 'google': 'vm', 'vm-other': 'vm', 'apple': 'vm', 'powervm': 'vm',
    'zvm': 'vm', 'acrn': 'vm', 'qnx': 'vm', 'sre': 'vm',
    'lxc': 'lxc', 'lxc-libvirt': 'lxc', 'openvz': 'lxc', 'systemd-nspawn': 'lxc',
    'docker': 'container', 'podman': 'container', 'rkt': 'container',
    'wsl': 'wsl',
}
CONTAINER_ACCESS = frozenset({'ok', 'denied', 'none'})

ROLES = frozenset({
    'hypervisor', 'backup', 'storage', 'container', 'docs', 'photos', 'media', 'cloud',
    'smarthome', 'network', 'monitoring', 'dev', 'passwords', 'database', 'web',
    'workstation', 'server',
})

SERVICES = frozenset({
    # existing
    'docker', 'podman', 'nginx', 'apache', 'caddy', 'mariadb', 'postgresql', 'samba', 'k3s',
    'wireguard', 'nextcloud', 'pihole', 'homeassistant', 'jellyfin', 'plex', 'portainer',
    'traefik', 'vaultwarden', 'immich', 'gitea', 'paperless', 'grafana', 'adguard',
    'uptimekuma', 'nginxproxymanager',
    # media and downloads
    'emby', 'sonarr', 'radarr', 'lidarr', 'readarr', 'prowlarr', 'bazarr', 'overseerr',
    'jellyseerr', 'qbittorrent', 'transmission', 'deluge', 'sabnzbd', 'navidrome',
    'audiobookshelf', 'kavita', 'calibreweb',
    # photos, documents, cloud and sync
    'photoprism', 'owncloud', 'seafile', 'syncthing', 'filebrowser', 'stirlingpdf',
    'bookstack', 'wikijs', 'joplin', 'mealie',
    # authentication
    'authentik', 'authelia', 'keycloak',
    # git and CI
    'gitlab', 'jenkins', 'woodpecker',
    # smart home
    'mosquitto', 'zigbee2mqtt', 'nodered', 'esphome', 'homebridge',
    # monitoring
    'prometheus', 'influxdb', 'loki', 'zabbix', 'netdata',
    # databases
    'redis', 'mongodb', 'opensearch',
    # network, DNS, VPN and proxy
    'tailscale', 'zerotier', 'openvpn', 'unbound', 'bind', 'haproxy',
    # containers and dashboards
    'dozzle', 'watchtower', 'homepage', 'homarr', 'dashy',
    # ai
    'ollama', 'openwebui',
})
MAX_SERVICES = 24
# Runtimes, web servers and databases that many hosts run under the
# applications that tell them apart. When more than MAX_SERVICES are found,
# these are the ones left out first.
INFRASTRUCTURE_SERVICES = frozenset({
    'docker', 'podman', 'k3s', 'portainer', 'watchtower', 'dozzle',
    'nginx', 'apache', 'caddy', 'traefik', 'haproxy',
    'mariadb', 'postgresql', 'redis', 'mongodb',
})

# systemd unit name (without .service) -> service. Only units that run the server
# itself: Debian's openvpn package, for example, keeps a plain openvpn.service
# active that only runs /bin/true, so OpenVPN counts through its instances.
SERVICE_UNITS = {
    'nginx': 'nginx', 'apache2': 'apache', 'httpd': 'apache', 'caddy': 'caddy', 'mariadb': 'mariadb',
    'mysql': 'mariadb', 'postgresql': 'postgresql', 'smbd': 'samba', 'k3s': 'k3s',
    'jellyfin': 'jellyfin', 'plexmediaserver': 'plex', 'emby-server': 'emby',
    'sonarr': 'sonarr', 'radarr': 'radarr', 'lidarr': 'lidarr', 'readarr': 'readarr',
    'prowlarr': 'prowlarr', 'bazarr': 'bazarr', 'overseerr': 'overseerr', 'jellyseerr': 'jellyseerr',
    'qbittorrent-nox': 'qbittorrent', 'transmission-daemon': 'transmission', 'deluged': 'deluge',
    'sabnzbdplus': 'sabnzbd', 'navidrome': 'navidrome', 'audiobookshelf': 'audiobookshelf',
    'kavita': 'kavita', 'calibre-web': 'calibreweb', 'photoprism': 'photoprism',
    'seafile': 'seafile', 'syncthing': 'syncthing', 'filebrowser': 'filebrowser',
    'bookstack': 'bookstack', 'wikijs': 'wikijs', 'mealie': 'mealie',
    'authentik': 'authentik', 'authelia': 'authelia', 'keycloak': 'keycloak',
    'gitea': 'gitea', 'forgejo': 'gitea', 'gitlab-runsvdir': 'gitlab', 'jenkins': 'jenkins',
    'woodpecker-server': 'woodpecker', 'mosquitto': 'mosquitto', 'zigbee2mqtt': 'zigbee2mqtt',
    'nodered': 'nodered', 'esphome': 'esphome', 'homebridge': 'homebridge',
    'vaultwarden': 'vaultwarden', 'grafana-server': 'grafana', 'prometheus': 'prometheus',
    'influxdb': 'influxdb', 'loki': 'loki', 'zabbix-server': 'zabbix', 'netdata': 'netdata',
    'redis-server': 'redis', 'redis': 'redis', 'mongod': 'mongodb', 'opensearch': 'opensearch',
    'tailscaled': 'tailscale', 'zerotier-one': 'zerotier',
    'unbound': 'unbound', 'named': 'bind', 'bind9': 'bind', 'haproxy': 'haproxy',
    'traefik': 'traefik', 'pihole-FTL': 'pihole', 'AdGuardHome': 'adguard',
    'uptime-kuma': 'uptimekuma', 'ollama': 'ollama', 'open-webui': 'openwebui',
    'paperless-webserver': 'paperless', 'immich-server': 'immich',
    'homeassistant': 'homeassistant', 'home-assistant': 'homeassistant',
}

# Templated systemd unit (name before '@') -> service
SERVICE_UNIT_TEMPLATES = {
    'syncthing': 'syncthing', 'openvpn': 'openvpn', 'openvpn-server': 'openvpn', 'openvpn-client': 'openvpn',
}

# Absolute path -> service. Only fixed paths whose existence alone identifies the service:
# directories that agent, client or tool packages also create (/etc/zabbix,
# /etc/mosquitto, /etc/redis, /etc/prometheus) are left to units and images.
SERVICE_PATHS = (
    ('/var/www/nextcloud/occ', 'nextcloud'),
    ('/var/www/html/nextcloud/occ', 'nextcloud'),
    ('/var/www/owncloud/occ', 'owncloud'),
    ('/etc/pihole', 'pihole'),
    ('/var/lib/sonarr', 'sonarr'),
    ('/var/lib/radarr', 'radarr'),
    ('/var/lib/lidarr', 'lidarr'),
    ('/var/lib/readarr', 'readarr'),
    ('/var/lib/prowlarr', 'prowlarr'),
    ('/var/lib/jellyfin', 'jellyfin'),
    ('/var/lib/plexmediaserver', 'plex'),
    ('/var/lib/emby', 'emby'),
    ('/opt/gitlab', 'gitlab'),
    ('/etc/gitlab', 'gitlab'),
    ('/var/lib/jenkins', 'jenkins'),
    ('/opt/zigbee2mqtt', 'zigbee2mqtt'),
    ('/var/lib/homebridge', 'homebridge'),
    ('/var/lib/influxdb', 'influxdb'),
    ('/etc/netdata', 'netdata'),
    ('/var/lib/mongodb', 'mongodb'),
    ('/etc/haproxy', 'haproxy'),
    ('/etc/authelia', 'authelia'),
    ('/opt/AdGuardHome', 'adguard'),
)

# snap name -> service
SERVICE_SNAPS = {
    'nextcloud': 'nextcloud', 'jellyfin': 'jellyfin', 'plexmediaserver': 'plex',
    'docker': 'docker', 'homeassistant': 'homeassistant', 'adguard-home': 'adguard',
    'syncthing': 'syncthing', 'mosquitto': 'mosquitto', 'node-red': 'nodered',
    'prometheus': 'prometheus', 'grafana': 'grafana', 'influxdb': 'influxdb',
    'redis': 'redis', 'mongodb': 'mongodb', 'ollama': 'ollama', 'tailscale': 'tailscale',
    'zerotier': 'zerotier', 'bind9': 'bind', 'haproxy': 'haproxy', 'gitea': 'gitea',
    'gitlab': 'gitlab', 'netdata': 'netdata',
}


# Start of an image name segment. The first segment does not count when it is a
# registry host ("gitea:3000/me/app", "postgres.internal/x"), i.e. contains ':'
# or '.' and more segments follow.
_SEGMENT = r'(?:^(?![^/]*[.:][^/]*/)|/)'


def _image(service, *names, strict=False):
    # Anchored at a path segment so e.g. "postgres-exporter" is not a database.
    # The strict form needs the whole segment; the loose form also allows the
    # edition suffixes of official images, but not exporters or bundles.
    tail = '' if strict else '(?:-server|-ce|-ee|-nox|-oss)?'
    return (service, re.compile(_SEGMENT + '(?:' + '|'.join(names) + ')' + tail + r'(:|@|$)'))


# Matched against lower-cased image references; first match wins, so specific
# names come before generic ones.
SERVICE_IMAGES = (
    _image('nginxproxymanager', 'nginx-proxy-manager'),
    _image('nextcloud', 'nextcloud', 'aio-nextcloud', 'nextcloud/all-in-one', 'nextcloud-releases/all-in-one'),
    ('homeassistant', re.compile(_SEGMENT + r'(?:home-?assistant/[a-z0-9-]+-)?home-?assistant(:|@|$)')),
    _image('jellyfin', 'jellyfin'),
    _image('plex', 'plex', 'pms-docker'),
    _image('portainer', 'portainer', 'portainer/agent'),
    _image('traefik', 'traefik'),
    _image('vaultwarden', 'vaultwarden', 'vaultwarden/server', 'bitwardenrs/server', strict=True),
    _image('immich', 'immich', 'immich-machine-learning'),
    _image('gitea', 'gitea', 'forgejo'),
    _image('paperless', 'paperless', 'paperless-ngx', 'paperless-ng'),
    ('grafana', re.compile(_SEGMENT + r'grafana(-oss|-enterprise)?(:|@|$)')),
    _image('pihole', 'pihole', 'pi-hole'),
    _image('adguard', 'adguardhome', 'adguard-home'),
    _image('uptimekuma', 'uptime-kuma'),
    _image('jellyseerr', 'jellyseerr'),
    _image('overseerr', 'overseerr'),
    _image('emby', 'embyserver', 'emby'),
    _image('sonarr', 'sonarr'),
    _image('radarr', 'radarr'),
    _image('lidarr', 'lidarr'),
    _image('readarr', 'readarr'),
    _image('prowlarr', 'prowlarr'),
    _image('bazarr', 'bazarr'),
    _image('qbittorrent', 'qbittorrent'),
    _image('transmission', 'transmission'),
    _image('deluge', 'deluge'),
    _image('sabnzbd', 'sabnzbd'),
    _image('navidrome', 'navidrome'),
    _image('audiobookshelf', 'audiobookshelf'),
    _image('kavita', 'kavita'),
    _image('calibreweb', 'calibre-web'),
    _image('photoprism', 'photoprism'),
    _image('owncloud', 'owncloud'),
    _image('owncloud', 'owncloud/server', strict=True),
    _image('seafile', 'seafile', 'seafile-mc'),
    _image('syncthing', 'syncthing'),
    _image('filebrowser', 'filebrowser'),
    _image('stirlingpdf', 'stirling-pdf'),
    _image('bookstack', 'bookstack'),
    _image('wikijs', 'wikijs'),
    _image('wikijs', 'requarks/wiki', strict=True),
    _image('joplin', 'joplin-server', 'joplin'),
    _image('joplin', 'joplin/server', strict=True),
    _image('mealie', 'mealie'),
    _image('authentik', 'authentik'),
    _image('authentik', 'goauthentik/server', strict=True),
    _image('authelia', 'authelia'),
    _image('keycloak', 'keycloak'),
    _image('gitlab', 'gitlab-ce', 'gitlab-ee', 'gitlab'),
    _image('jenkins', 'jenkins'),
    _image('woodpecker', 'woodpecker'),
    _image('mosquitto', 'eclipse-mosquitto', 'mosquitto'),
    _image('zigbee2mqtt', 'zigbee2mqtt'),
    _image('nodered', 'node-red'),
    _image('esphome', 'esphome'),
    _image('homebridge', 'homebridge'),
    _image('prometheus', 'prometheus'),
    _image('influxdb', 'influxdb'),
    _image('loki', 'loki'),
    _image('zabbix', 'zabbix', 'zabbix-server-(?:mysql|pgsql)'),
    _image('netdata', 'netdata'),
    _image('opensearch', 'opensearch'),
    _image('tailscale', 'tailscale'),
    _image('zerotier', 'zerotier'),
    _image('openvpn', 'openvpn'),
    _image('wireguard', 'wireguard', 'wg-easy'),
    _image('unbound', 'unbound'),
    _image('bind', 'bind9'),
    _image('haproxy', 'haproxy', 'haproxy-alpine', 'haproxy-debian', 'haproxy-ubuntu', strict=True),
    _image('dozzle', 'dozzle'),
    _image('watchtower', 'watchtower'),
    _image('homepage', 'gethomepage/homepage', 'benphelps/homepage', strict=True),
    _image('homarr', 'homarr'),
    _image('dashy', 'dashy'),
    _image('ollama', 'ollama'),
    _image('openwebui', 'open-webui'),
    ('mariadb', re.compile(_SEGMENT + r'(mariadb|mysql)(:|@|$)')),
    ('postgresql', re.compile(_SEGMENT + r'postgres(ql)?(:|@|$)')),
    _image('redis', 'redis', 'valkey', strict=True),
    _image('mongodb', 'mongo', strict=True),
    ('nginx', re.compile(_SEGMENT + r'nginx(:|@|$)')),
    ('caddy', re.compile(_SEGMENT + r'caddy(:|@|$)')),
    _image('apache', 'httpd', strict=True),
)
