(function(root, factory) {
    const platform = typeof module !== 'undefined' && module.exports
        ? require('./host-platform.js')
        : root.HostPlatform;
    const api = factory(platform);
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.HostIdentity = api;
})(typeof window !== 'undefined' ? window : globalThis, function(loadedPlatform) {
    'use strict';
    // Without the platform catalog nothing about a host can be checked, so every
    // host reads as a Server with no platform or services.
    const NO_PLATFORM = Object.freeze({resolve: () => ({id: 'server', source: 'pending'}), services: () => [], labels: {}});
    const platformCatalog = () => loadedPlatform || globalThis.HostPlatform || NO_PLATFORM;
    const ROLES = Object.freeze(['hypervisor', 'backup', 'storage', 'container', 'docs', 'photos', 'media', 'cloud',
        'smarthome', 'network', 'monitoring', 'dev', 'passwords', 'database', 'web', 'workstation', 'server']);
    const ROLE_GLYPHS = Object.freeze({
        hypervisor: 'layers', backup: 'backup', storage: 'storage', container: 'view_in_ar', docs: 'description',
        photos: 'photo_library', media: 'movie', cloud: 'cloud', smarthome: 'home', network: 'router',
        monitoring: 'insights', dev: 'code', passwords: 'vpn_key', database: 'table_chart', web: 'language',
        workstation: 'computer', server: 'dns',
    });
    const DATABASE = ['mariadb', 'postgresql', 'redis', 'mongodb', 'influxdb'];
    const WEB = ['nginx', 'apache', 'caddy', 'traefik', 'nginxproxymanager', 'haproxy'];
    // Runtimes first, then the tools that manage or watch their containers.
    const CONTAINER = ['docker', 'podman', 'portainer', 'k3s', 'watchtower', 'dozzle'];
    // VPN and overlay networks say how a host is reached, not what it is: rules
    // ignore them, and a host that runs nothing else is a Network host.
    const VPN = Object.freeze(['wireguard', 'tailscale', 'zerotier', 'openvpn']);
    const rule = (role, platforms, services, only = null) => Object.freeze({
        role, platforms: Object.freeze(platforms), services: Object.freeze(services), only: only && Object.freeze(only),
    });
    // The platform comes first: the first rule that matches it names the role. A
    // container runtime or its tooling is next and wins over every application
    // it runs. Then the first service rule names the role. `only` rules describe
    // hosts that run nothing but infrastructure: one more application and the
    // host is more than that.
    // NetBird, Headscale and Forgejo are not in the catalog; Forgejo reports as gitea.
    const RULES = Object.freeze([
        rule('hypervisor', ['proxmox'], []),
        rule('backup', ['proxmoxbackup'], []),
        rule('storage', ['truenas', 'unraid', 'synology', 'qnap'], []),
        rule('photos', [], ['immich', 'photoprism']),
        rule('docs', [], ['paperless']),
        rule('cloud', [], ['nextcloud', 'owncloud', 'seafile']),
        rule('media', [], ['jellyfin', 'plex', 'emby']),
        rule('smarthome', ['homeassistant'], ['homeassistant']),
        rule('network', ['opnsense', 'pfsense', 'openwrt', 'mikrotik', 'cisco', 'ubiquiti'], ['pihole', 'adguard']),
        rule('monitoring', [], ['grafana', 'prometheus', 'uptimekuma', 'zabbix', 'netdata']),
        rule('dev', [], ['gitea', 'gitlab']),
        rule('passwords', [], ['vaultwarden']),
        rule('database', [], DATABASE, [...DATABASE, ...WEB]),
        rule('web', [], WEB, WEB),
        rule('container', ['docker'], CONTAINER),
    ]);
    const RUNTIME = RULES.find(item => item.role === 'container');
    // Services that name a role, in rule order; shown before everything else.
    // The container runtime does not lead the applications it runs.
    const PRIORITY = Object.freeze(RULES.filter(item => !item.only && item !== RUNTIME).flatMap(item => item.services)
        .filter((id, index, list) => list.indexOf(id) === index));
    // Only a verified or chosen platform names a role; a greeting or name hint does not.
    const TRUSTED_PLATFORM = new Set(['manual', 'detected', 'family']);
    const VIRT = new Set(['bare-metal', 'vm', 'lxc', 'container', 'wsl']);
    const VERSION = /^[0-9][0-9A-Za-z._-]{0,15}$/;
    const STALE_SECONDS = 7 * 86400;

    function trustedPlatform(profile) {
        const resolved = platformCatalog().resolve(profile);
        return TRUSTED_PLATFORM.has(resolved.source) && resolved.id !== 'server' ? resolved.id : null;
    }
    function derive(profile, services) {
        const platform = trustedPlatform(profile);
        const apps = services.filter(id => !VPN.includes(id));
        const named = platform && RULES.find(item => item.platforms.includes(platform));
        if (named) return {id: named.role, basis: platform};
        const runtime = RUNTIME.services.find(id => apps.includes(id));
        if (runtime) return {id: RUNTIME.role, basis: runtime};
        for (const item of RULES) {
            const basis = item.services.find(id => apps.includes(id));
            if (!basis) continue;
            if (item.only && !apps.every(id => item.only.includes(id))) continue;
            return {id: item.role, basis};
        }
        if (profile.detected_graphical === true) return {id: 'workstation', basis: null};
        if (services.length && !apps.length) return {id: 'network', basis: VPN.find(id => services.includes(id))};
        return null;
    }
    /** The host's role: a manual choice, else the first matching rule, else 'server'. */
    function role(profile) {
        const source = profile && typeof profile === 'object' ? profile : {};
        if (ROLES.includes(source.role_override)) return {id: source.role_override, source: 'manual', basis: null};
        const derived = derive(source, platformCatalog().services(source));
        return derived ? {...derived, source: 'derived'} : {id: 'server', source: 'default', basis: null};
    }
    function stamp(value) {
        return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
    }
    function ordered(services, lead) {
        const rank = id => (id === lead ? -1 : PRIORITY.includes(id) ? PRIORITY.indexOf(id)
            : RUNTIME.services.includes(id) ? PRIORITY.length + 1 : VPN.includes(id) ? PRIORITY.length + 2 : PRIORITY.length);
        return [...services].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
    }
    /** Display facts of a host, each validated against the catalog or dropped. */
    function facts(profile, now = Date.now() / 1000) {
        const source = profile && typeof profile === 'object' ? profile : {};
        const resolved = platformCatalog().resolve(source);
        const translate = (key, fallback) => globalThis.i18n?.t(key) || fallback;
        const label = resolved.id === 'server' ? translate('platform.server', 'Server') : platformCatalog().labels[resolved.id];
        const services = platformCatalog().services(source);
        const current = role(source);
        const lead = current.id === RUNTIME.role ? null : current.source === 'manual'
            ? RULES.find(item => item.role === current.id)?.services.find(id => services.includes(id))
            : current.basis;
        const guests = source.detected_guests;
        const stamps = [stamp(source.platform_checked_at), stamp(source.services_checked_at)].filter(v => v !== null);
        const checkedAt = stamps.length ? Math.max(...stamps) : null;
        const version = source.detected_os_version;
        return {
            platform: {id: resolved.id, source: resolved.source, label},
            version: typeof version === 'string' && VERSION.test(version) ? version : null,
            virt: VIRT.has(source.detected_virt) ? source.detected_virt : null,
            guests: Number.isInteger(guests) && guests >= 0 && guests <= 9999 ? guests : null,
            containerAccess: source.detected_container_access === 'ok' || source.detected_container_access === 'denied'
                ? source.detected_container_access : null,
            services: ordered(services, lead),
            checkedAt,
            stale: checkedAt !== null && now - checkedAt > STALE_SECONDS,
            state: source.detection_state === 'detected' || source.detection_state === 'unavailable'
                ? source.detection_state : 'pending',
        };
    }
    const VIRT_LABELS = Object.freeze({'bare-metal': ['virtBareMetal', 'Bare Metal'], vm: ['virtVm', 'VM'],
        lxc: ['virtLxc', 'LXC'], container: ['virtContainer', 'Container'], wsl: ['virtWsl', 'WSL']});
    // Matches the os-release ID the server accepts; such a name is shown only next to its family.
    const OS_ID = /^[a-z0-9._-]{1,32}$/;
    /** Fills `{name}` placeholders; a function replacement keeps `$&` and the like in values literal. */
    function format(text, values = {}) {
        return Object.entries(values).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, () => String(replacement)),
            text);
    }
    const sentence = text => (text ? `${text.charAt(0).toLocaleUpperCase()}${text.slice(1)}` : text);
    /** Role, facts and the system and machine texts a host is shown with. */
    function describe(profile) {
        const source = profile && typeof profile === 'object' ? profile : {};
        const translate = (key, fallback, values = {}) => {
            const text = globalThis.i18n?.t(key);
            return format(text && text !== key ? text : fallback, values);
        };
        const current = role(source);
        const details = facts(source);
        const {platform, version} = details;
        let system = '';
        if (platform.source === 'family') {
            const name = typeof source.detected_os_id === 'string' && OS_ID.test(source.detected_os_id)
                ? sentence(source.detected_os_id) : '';
            const family = translate('overviewWorkspace.osFamily', '{family}-based', {family: platform.label});
            system = [[name, version].filter(Boolean).join(' '), family].filter(Boolean).join(' · ');
        } else if (platform.source === 'detected') {
            system = [platform.label, version].filter(Boolean).join(' ');
        } else if (platform.source === 'manual') {
            system = `${platform.label} (${translate('platform.manual', 'manual choice')})`;
        }
        const virt = details.virt ? translate(`overviewWorkspace.${VIRT_LABELS[details.virt][0]}`, VIRT_LABELS[details.virt][1]) : '';
        return {role: current, facts: details, system, virt};
    }
    return {ROLES, ROLE_GLYPHS, RULES, PRIORITY, VPN, role, facts, describe, format};
});
