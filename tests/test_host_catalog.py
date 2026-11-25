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
