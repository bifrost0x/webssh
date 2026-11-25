import json
import os
import re
from pathlib import Path

from app import host_catalog as c, host_platform

def test_catalogs_are_consistent():
    assert set(c.OS_ID_PLATFORMS.values()) <= c.PLATFORMS
    assert set(c.FAMILIES.values()) <= c.PLATFORMS
    assert set(c.MARKER_PLATFORMS.values()) <= c.PLATFORMS
    assert set(c.KERNEL_PLATFORMS.values()) <= c.PLATFORMS
    assert c.NON_POSIX_PLATFORMS <= c.BANNER_ONLY_PLATFORMS <= c.PLATFORMS
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
    assert c.PLATFORMS - c.BANNER_ONLY_PLATFORMS - {'server', 'docker'} <= reachable
    assert not reachable & c.BANNER_ONLY_PLATFORMS


def test_ubiquiti_is_a_marker_platform():
    assert 'ubiquiti' in c.PLATFORMS and 'ubiquiti' in c.MARKER_PLATFORMS.values()


def test_service_paths_are_fixed_absolute():
    assert all(p.startswith('/') and '..' not in p and ' ' not in p for p, _ in c.SERVICE_PATHS)


def test_service_paths_skip_directories_that_agent_and_client_packages_create():
    # zabbix-agent, mosquitto-clients (a single package on Fedora and Alpine), redis tools and
    # prometheus-alertmanager create these without the server running; units and images decide.
    paths = {path for path, _ in c.SERVICE_PATHS}
    assert not paths & {'/etc/zabbix', '/etc/mosquitto', '/etc/redis', '/etc/prometheus'}
    assert {'/etc/pihole', '/var/lib/mongodb', '/var/lib/influxdb', '/etc/haproxy'} <= paths


def test_image_rules_for_generic_names_need_their_publisher():
    cases = {
        'ghcr.io/gethomepage/homepage:latest': 'homepage', 'gethomepage/homepage:v0.9': 'homepage',
        'requarks/wiki:2': 'wikijs', 'ghcr.io/requarks/wiki:2.5': 'wikijs', 'lscr.io/linuxserver/wikijs': 'wikijs',
        'ghcr.io/goauthentik/server:2024.10': 'authentik', 'goauthentik/server': 'authentik',
        'joplin/server:latest': 'joplin', 'ghcr.io/goauthentik/proxy': None,
        'me/homepage:1': None, 'acme/wiki:2': None, 'homepage:1': None, 'wiki:2': None,
        'acme/server:1': None, 'someone/server': None,
    }
    for image, expected in cases.items():
        assert _image_id(image) == expected, image


def test_app_image_rules_match_the_image_name_only():
    cases = {
        'lscr.io/linuxserver/nextcloud:latest': 'nextcloud', 'nextcloud:30-apache': 'nextcloud',
        'nextcloud/all-in-one:latest': 'nextcloud', 'ghcr.io/nextcloud-releases/aio-nextcloud:latest': 'nextcloud',
        'ghcr.io/nextcloud-releases/all-in-one:latest': 'nextcloud',
        'jellyfin/jellyfin:10.10': 'jellyfin', 'ghcr.io/hotio/jellyfin': 'jellyfin',
        'plexinc/pms-docker:latest': 'plex', 'lscr.io/linuxserver/plex': 'plex',
        'portainer/portainer-ce:2.21': 'portainer', 'portainer/portainer-ee': 'portainer', 'portainer/agent:2': 'portainer',
        'traefik:v3.2': 'traefik', 'docker.io/library/traefik': 'traefik',
        'gitea/gitea:1.22': 'gitea', 'codeberg.org/forgejo/forgejo:9': 'gitea',
        'ghcr.io/paperless-ngx/paperless-ngx:2': 'paperless', 'jonaswinkler/paperless-ng': 'paperless',
        'ghcr.io/immich-app/immich-server:release': 'immich', 'ghcr.io/immich-app/immich-machine-learning:release': 'immich',
        'ghcr.io/imagegenius/immich:latest': 'immich',
        'pihole/pihole:2024.07.0': 'pihole',
        'homeassistant/home-assistant:stable': 'homeassistant', 'ghcr.io/home-assistant/home-assistant:2024.11': 'homeassistant',
        'lscr.io/linuxserver/homeassistant': 'homeassistant',
        'ghcr.io/home-assistant/qemux86-64-homeassistant:2024.11.3': 'homeassistant',
        'vaultwarden/server:1.32.5': 'vaultwarden', 'bitwardenrs/server': 'vaultwarden',
        'adguard/adguardhome:v0.107': 'adguard', 'louislam/uptime-kuma:1': 'uptimekuma',
        'jc21/nginx-proxy-manager:latest': 'nginxproxymanager',
    }
    for image, expected in cases.items():
        assert _image_id(image) == expected, image


def test_app_image_rules_skip_exporters_sidecars_and_tools():
    for image in ('thomseddon/traefik-forward-auth:2', 'traefik/whoami', 'ghcr.io/jmbannon/jellyfin-exporter',
                  'jellyfin/jellyfin-vue', 'meisnate12/plex-meta-manager', 'kometateam/plex-meta-manager',
                  'plexinc/plex-exporter', 'ghcr.io/nextcloud/nextcloud-exporter', 'xperimental/nextcloud-exporter',
                  'portainer/helper-reset-password', 'gitea/act_runner:0.2', 'ekofr/pihole-exporter',
                  'clusterio/paperless-ai', 'icereed/paperless-gpt', 'damongolding/immich-kiosk',
                  'ghcr.io/linuxserver/nextcloud-backup', 'ghcr.io/bfren/vaultwarden-backup',
                  'ghcr.io/bakito/adguardhome-sync', 'tcpipuk/uptime-kuma-exporter',
                  'ghcr.io/home-assistant/amd64-hassio-supervisor', 'homeassistant-exporter',
                  'gitea:3000/me/app:latest', 'traefik:5000/whoami', 'nginx:8080/team/site',
                  'postgres.internal/tools/backup:1', 'redis:6000/cache-warmer'):
        assert _image_id(image) is None, image


def test_image_rules_skip_the_registry_host_only():
    cases = {
        'localhost:5000/gitea:latest': 'gitea', 'registry.example.com:5000/library/traefik:v3': 'traefik',
        'ghcr.io/hotio/jellyfin': 'jellyfin', 'lscr.io/linuxserver/nextcloud': 'nextcloud',
        'docker.io/library/postgres:16': 'postgresql', 'traefik:v3.2': 'traefik', 'nginx:1.27': 'nginx',
        'nextcloud/all-in-one:latest': 'nextcloud', 'redis@sha256:abc': 'redis',
    }
    for image, expected in cases.items():
        assert _image_id(image) == expected, image


def test_cloud_and_other_hypervisors_are_vms():
    for value in ('amazon', 'google', 'vm-other', 'apple', 'powervm', 'zvm', 'acrn', 'qnx', 'sre'):
        assert c.VIRT_MAP[value] == 'vm', value


JS_CATALOG_FIXTURE = Path(__file__).parent / 'js' / 'fixtures' / 'host-catalog.json'


def _js_catalog():
    return json.dumps({'platforms': sorted(c.PLATFORMS), 'services': sorted(c.SERVICES)}, indent=2) + '\n'


def test_js_catalog_fixture_is_current():
    """The browser tests check labels against this copy of the catalog."""
    if os.environ.get('WEBSSH_WRITE_JS_CATALOG') == '1':
        JS_CATALOG_FIXTURE.write_text(_js_catalog(), encoding='utf-8')
    current = JS_CATALOG_FIXTURE.read_text(encoding='utf-8') if JS_CATALOG_FIXTURE.exists() else None
    assert current == _js_catalog(), (
        'tests/js/fixtures/host-catalog.json is stale; regenerate with: '
        'WEBSSH_WRITE_JS_CATALOG=1 python -m pytest tests/test_host_catalog.py -k js_catalog_fixture')


def test_profile_editor_offers_every_platform():
    template = (Path(__file__).parents[1] / 'templates' / 'index.html').read_text(encoding='utf-8')
    select = re.search(r'<select id="profileEditorPlatformIcon".*?</select>', template, re.S).group(0)
    assert set(re.findall(r'<option value="([^"]+)"', select)) == c.PLATFORMS | {'auto'}


def test_platform_icons_are_plain_simple_icons_with_provenance():
    directory = Path(__file__).parents[1] / 'static' / 'icons' / 'platforms'
    provenance = json.loads((directory / 'provenance.json').read_text(encoding='utf-8'))
    icons = {path.stem: path for path in directory.glob('*.svg')}
    assert set(icons) == set(provenance['icons']) and set(icons) <= c.PLATFORMS
    for name, path in icons.items():
        svg = path.read_text(encoding='utf-8')
        title = provenance['icons'][name]['title'].replace('&', '&amp;')
        assert svg.startswith(f'<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>{title}</title><path d="'), name
        assert svg.endswith('"/></svg>') and svg.count('<') == 5, name
