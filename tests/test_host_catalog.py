from app import host_catalog as c, host_platform

def test_catalogs_are_consistent():
    assert set(c.OS_ID_PLATFORMS.values()) <= c.PLATFORMS
    assert set(c.FAMILIES.values()) <= c.PLATFORMS
    assert set(c.MARKER_PLATFORMS.values()) <= c.PLATFORMS
    assert set(c.KERNEL_PLATFORMS.values()) <= c.PLATFORMS
    assert c.NON_POSIX_PLATFORMS <= c.PLATFORMS
    assert set(c.VIRT_MAP.values()) <= c.VIRT_KINDS
    mapped = set(c.SERVICE_UNITS.values()) | {i for _, i in c.SERVICE_PATHS} | set(c.SERVICE_SNAPS.values()) | {i for i, _ in c.SERVICE_IMAGES}
    assert mapped <= c.SERVICES and c.SERVICES <= mapped | {'docker', 'podman'}
    assert len(c.SERVICES) >= 70 and 'server' in c.ROLES

def test_old_ids_stay_valid_and_are_re_exported():
    old = {'server', 'proxmox', 'raspberrypi', 'homeassistant', 'truenas', 'opnsense', 'ubuntu', 'debian',
           'fedora', 'archlinux', 'alpinelinux', 'linux', 'apple', 'freebsd', 'docker'}
    assert old <= c.PLATFORMS and host_platform.PLATFORMS is c.PLATFORMS
    assert {'paperless', 'immich', 'nextcloud', 'nginxproxymanager'} <= c.SERVICES and host_platform.SERVICES is c.SERVICES

def test_image_patterns_prefer_specific_names():
    first = lambda image: next(i for i, p in c.SERVICE_IMAGES if p.search(image))
    assert first('jc21/nginx-proxy-manager:latest') == 'nginxproxymanager'
    assert first('ghcr.io/immich-app/immich-server:release') == 'immich'
    assert first('ghcr.io/paperless-ngx/paperless-ngx:2') == 'paperless'
    assert first('docker.io/library/postgres:16') == 'postgresql'


def _image_id(image):
    return next((i for i, p in c.SERVICE_IMAGES if p.search(image)), None)


def test_image_rules_positive():
    cases = {
        'grafana/grafana:latest': 'grafana', 'grafana/grafana-oss:10': 'grafana',
        'grafana/loki:2.9': 'loki', 'grafana/promtail:2': None, 'grafana/tempo:2': None,
        'lscr.io/linuxserver/sonarr:latest': 'sonarr', 'ghcr.io/hotio/radarr': 'radarr',
        'prom/prometheus:v2': 'prometheus', 'influxdb:2.7': 'influxdb',
        'gitlab/gitlab-ce:latest': 'gitlab', 'qbittorrentofficial/qbittorrent-nox': 'qbittorrent',
        'lscr.io/linuxserver/qbittorrent:4': 'qbittorrent', 'requarks/wiki:2': 'wikijs',
        'mongo:7': 'mongodb', 'redis:7': 'redis', 'valkey/valkey:8': 'redis',
        'eclipse-mosquitto:2': 'mosquitto', 'ollama/ollama': 'ollama',
        'ghcr.io/open-webui/open-webui:main': 'openwebui', 'linuxserver/wireguard': 'wireguard',
        'docker.io/library/haproxy:2': 'haproxy', 'kylemanna/openvpn': 'openvpn',
    }
    for image, expected in cases.items():
        assert _image_id(image) == expected, image


def test_image_rules_negative():
    for image in ('grafana/promtail', 'prometheus-postgres-exporter:1', 'bitnami/postgres-exporter',
                  'mongo-express:1', 'prom/postgres-exporter', 'haugene/transmission-openvpn',
                  'dperson/openvpn-client', 'prometheuscommunity/influxdb-exporter',
                  'wikipedia/mirror', 'redis-commander/redis-commander', 'oliver006/redis_exporter'):
        assert _image_id(image) is None, image
    assert _image_id('grafana/loki:2') == 'loki'


def test_every_posix_platform_is_detectable():
    reachable = (set(c.OS_ID_PLATFORMS.values()) | set(c.FAMILIES.values()) | set(c.MARKER_PLATFORMS.values())
                 | set(c.KERNEL_PLATFORMS.values()) | {'raspberrypi'})
    assert c.PLATFORMS - c.NON_POSIX_PLATFORMS - {'server', 'docker'} <= reachable
    assert not reachable & c.NON_POSIX_PLATFORMS


def test_ubiquiti_is_a_marker_platform():
    assert 'ubiquiti' in c.PLATFORMS and 'ubiquiti' in c.MARKER_PLATFORMS.values()


def test_service_paths_are_fixed_absolute():
    assert all(p.startswith('/') and '..' not in p and ' ' not in p for p, _ in c.SERVICE_PATHS)
