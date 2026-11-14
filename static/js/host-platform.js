(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.HostPlatform = api;
})(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';
    const labels = Object.freeze({
        server: 'Server', docker: 'Docker', proxmox: 'Proxmox', raspberrypi: 'Raspberry Pi',
        homeassistant: 'Home Assistant', truenas: 'TrueNAS', opnsense: 'OPNsense',
        ubuntu: 'Ubuntu', debian: 'Debian', fedora: 'Fedora', archlinux: 'Arch Linux',
        alpinelinux: 'Alpine Linux', linux: 'Linux', apple: 'macOS', freebsd: 'FreeBSD',
    });
    const known = value => typeof value === 'string' && Object.hasOwn(labels, value);
    const hints = [
        ['docker', /\bdocker\b/i],
        ['proxmox', /\bproxmox\b/i], ['raspberrypi', /\braspberry[ -]?pi\b/i],
        ['homeassistant', /\bhome[ -]?assistant\b/i], ['truenas', /\btruenas\b/i],
        ['opnsense', /\bopnsense\b/i], ['ubuntu', /\bubuntu\b/i], ['debian', /\bdebian\b/i],
        ['fedora', /\bfedora\b/i], ['archlinux', /\barch[ -]?linux\b/i],
        ['alpinelinux', /\balpine[ -]?linux\b/i], ['freebsd', /\bfreebsd\b/i], ['apple', /\bmacos\b/i],
    ];
    const serviceLabels = {
        docker: 'Docker', podman: 'Podman', nginx: 'nginx', apache: 'Apache', caddy: 'Caddy', mariadb: 'MariaDB',
        postgresql: 'PostgreSQL', samba: 'Samba', k3s: 'k3s', wireguard: 'WireGuard', nextcloud: 'Nextcloud',
        pihole: 'Pi-hole', homeassistant: 'Home Assistant', jellyfin: 'Jellyfin', plex: 'Plex', portainer: 'Portainer',
        traefik: 'Traefik', vaultwarden: 'Vaultwarden', immich: 'Immich', gitea: 'Gitea', paperless: 'Paperless',
        grafana: 'Grafana', adguard: 'AdGuard Home', uptimekuma: 'Uptime Kuma', nginxproxymanager: 'Nginx Proxy Manager',
    };
    /** Services detected on the host, as known ids in a stable order. */
    function services(profile = {}) {
        const list = Array.isArray(profile?.detected_services) ? profile.detected_services : [];
        return [...new Set(list.filter(id => Object.hasOwn(serviceLabels, id)))];
    }
    function resolve(profile = {}) {
        if (known(profile.platform_icon)) return {id: profile.platform_icon, source: 'manual'};
        if (known(profile.detected_platform)) return {id: profile.detected_platform, source: 'detected'};
        // Named by the SSH greeting during discovery; a connection later confirms or replaces it.
        if (known(profile.greeting_platform)) return {id: profile.greeting_platform, source: 'greeting'};
        const name = typeof profile.name === 'string' ? profile.name.slice(0, 128) : '';
        const matches = hints.filter(([, pattern]) => pattern.test(name));
        return matches.length === 1 ? {id: matches[0][0], source: 'hint'} : {id: 'server', source: 'fallback'};
    }
    function render(profile, doc = document) {
        const identity = profile?.id && known(profile.id) && ['manual', 'detected', 'greeting', 'hint', 'fallback'].includes(profile.source)
            ? profile : resolve(profile);
        const element = doc.createElement('span');
        element.className = 'host-platform-icon';
        element.setAttribute('data-platform', identity.id);
        const sources = {manual: 'manual choice', detected: 'detected after SSH connection', greeting: 'SSH greeting; unverified',
            hint: 'name hint; unverified', fallback: 'platform unknown'};
        const translate = (key, fallback) => globalThis.i18n?.t(key) || fallback;
        const label = identity.id === 'server' ? translate('platform.server', 'Server') : labels[identity.id];
        element.title = `${label} — ${translate(`platform.${identity.source}`, sources[identity.source])}`;
        element.setAttribute('role', 'img');
        element.setAttribute('aria-label', element.title);
        if (identity.id === 'server') {
            element.className += ' material-icons';
            element.textContent = 'dns';
        } else {
            let assets = {};
            try {
                assets = JSON.parse(doc.getElementById?.('hostPlatformAssets')?.textContent || '{}');
            } catch {
                // Older embedded documents may not provide an asset manifest.
            }
            const base = doc.querySelector?.('meta[name="host-platform-icons"]')?.content || '/static/icons/platforms/';
            const asset = assets[identity.id] || `${base}${identity.id}.svg`;
            element.style.maskImage = `url("${asset}")`;
        }
        return element;
    }
    function canonicalHost(host) {
        let value = String(host || '').trim().replace(/\.+$/, '');
        if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
        try { return new URL(value.includes(':') ? `http://[${value}]/` : `http://${value}/`).hostname; }
        catch { return value.toLowerCase(); }
    }
    function renderSession(session = {}, profile, doc = document) {
        const sameEndpoint = profile && canonicalHost(profile.host) === canonicalHost(session.host) && profile.username === session.username
            && Number(profile.port || 22) === Number(session.port || 22)
            && (profile.socks_proxy_id || null) === (session.socksProxyId || null)
            && (profile.jump_host_id || null) === (session.jumpHostId || null);
        return render({name: profile?.name || '', platform_icon: profile?.platform_icon,
            detected_platform: session.detectedPlatform || (sameEndpoint ? profile?.detected_platform : undefined),
            greeting_platform: sameEndpoint ? profile?.greeting_platform : undefined}, doc);
    }
    function refreshSessionIcons(manager, profiles = []) {
        if (!manager?.sessions || typeof document === 'undefined') return;
        for (const [id, session] of Object.entries(manager.sessions)) {
            const holder = document.getElementById(`tab-${id}`)?.querySelector('.session-platform-icon');
            if (!holder) continue;
            const profile = profiles.find(item => item.id === session.profileId);
            holder.replaceChildren(renderSession(session, profile));
        }
    }
    return {labels, resolve, services, serviceLabels, render, renderSession, refreshSessionIcons};
});
