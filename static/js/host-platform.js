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
        proxmoxbackup: 'Proxmox Backup Server', rockylinux: 'Rocky Linux', almalinux: 'AlmaLinux',
        redhat: 'Red Hat Enterprise Linux', centos: 'CentOS', opensuse: 'openSUSE', nixos: 'NixOS',
        manjaro: 'Manjaro', endeavouros: 'EndeavourOS', linuxmint: 'Linux Mint', popos: 'Pop!_OS',
        kalilinux: 'Kali Linux', gentoo: 'Gentoo', voidlinux: 'Void Linux', unraid: 'Unraid',
        synology: 'Synology DSM', qnap: 'QNAP QTS', openwrt: 'OpenWrt', pfsense: 'pfSense',
        windows: 'Windows', mikrotik: 'MikroTik RouterOS', cisco: 'Cisco IOS', ubiquiti: 'Ubiquiti',
        embedded: 'Embedded / BusyBox',
    });
    // Platforms without a logo of their own in the bundled set show a related logo.
    // Rocky Linux and Gentoo have none there, and another vendor's mark would
    // misname them, so both use the Linux one.
    const logoOf = Object.freeze({proxmoxbackup: 'proxmox', rockylinux: 'linux', gentoo: 'linux'});
    // Simple Icons carries no Windows logo, and embedded systems have no common mark.
    const glyphs = Object.freeze({server: 'dns', windows: 'desktop_windows', embedded: 'memory'});
    const known = value => typeof value === 'string' && Object.hasOwn(labels, value);
    const hints = [
        ['docker', /\bdocker\b/i],
        ['proxmox', /\bproxmox\b(?![ -]?backup)/i], ['proxmoxbackup', /\bproxmox[ -]?backup\b/i],
        ['raspberrypi', /\braspberry[ -]?pi\b/i],
        ['homeassistant', /\bhome[ -]?assistant\b/i], ['truenas', /\btruenas\b/i],
        ['opnsense', /\bopnsense\b/i], ['ubuntu', /\bubuntu\b/i], ['debian', /\bdebian\b/i],
        ['fedora', /\bfedora\b/i], ['archlinux', /\barch[ -]?linux\b/i],
        ['alpinelinux', /\balpine[ -]?linux\b/i], ['freebsd', /\bfreebsd\b/i], ['apple', /\bmacos\b/i],
        ['rockylinux', /\brocky[ -]?linux\b/i], ['almalinux', /\balma[ -]?linux\b/i],
        ['redhat', /\b(?:red[ -]?hat|rhel)\b/i], ['centos', /\bcentos\b/i], ['opensuse', /\bopen[ -]?suse\b/i],
        ['nixos', /\bnixos\b/i], ['manjaro', /\bmanjaro\b/i], ['endeavouros', /\bendeavour[ -]?os\b/i],
        ['linuxmint', /\blinux[ -]?mint\b/i], ['popos', /\bpop!?[_ -]?os\b/i], ['kalilinux', /\bkali\b/i],
        ['gentoo', /\bgentoo\b/i], ['voidlinux', /\bvoid[ -]?linux\b/i], ['unraid', /\bunraid\b/i],
        ['synology', /\bsynology\b/i], ['qnap', /\bqnap\b/i], ['openwrt', /\bopenwrt\b/i],
        ['pfsense', /\bpfsense\b/i], ['windows', /\bwindows\b/i], ['mikrotik', /\bmikrotik\b/i],
        ['cisco', /\bcisco\b/i], ['ubiquiti', /\b(?:ubiquiti|unifi)\b/i],
    ];
    const serviceLabels = {
        docker: 'Docker', podman: 'Podman', nginx: 'nginx', apache: 'Apache', caddy: 'Caddy', mariadb: 'MariaDB',
        postgresql: 'PostgreSQL', samba: 'Samba', k3s: 'k3s', wireguard: 'WireGuard', nextcloud: 'Nextcloud',
        pihole: 'Pi-hole', homeassistant: 'Home Assistant', jellyfin: 'Jellyfin', plex: 'Plex', portainer: 'Portainer',
        traefik: 'Traefik', vaultwarden: 'Vaultwarden', immich: 'Immich', gitea: 'Gitea', paperless: 'Paperless',
        grafana: 'Grafana', adguard: 'AdGuard Home', uptimekuma: 'Uptime Kuma', nginxproxymanager: 'Nginx Proxy Manager',
        emby: 'Emby', sonarr: 'Sonarr', radarr: 'Radarr', lidarr: 'Lidarr', readarr: 'Readarr', prowlarr: 'Prowlarr',
        bazarr: 'Bazarr', overseerr: 'Overseerr', jellyseerr: 'Jellyseerr', qbittorrent: 'qBittorrent',
        transmission: 'Transmission', deluge: 'Deluge', sabnzbd: 'SABnzbd', navidrome: 'Navidrome',
        audiobookshelf: 'Audiobookshelf', kavita: 'Kavita', calibreweb: 'Calibre-Web',
        photoprism: 'PhotoPrism', owncloud: 'ownCloud', seafile: 'Seafile', syncthing: 'Syncthing',
        filebrowser: 'File Browser', stirlingpdf: 'Stirling-PDF', bookstack: 'BookStack', wikijs: 'Wiki.js',
        joplin: 'Joplin Server', mealie: 'Mealie',
        authentik: 'authentik', authelia: 'Authelia', keycloak: 'Keycloak',
        gitlab: 'GitLab', jenkins: 'Jenkins', woodpecker: 'Woodpecker CI',
        mosquitto: 'Mosquitto', zigbee2mqtt: 'Zigbee2MQTT', nodered: 'Node-RED', esphome: 'ESPHome', homebridge: 'Homebridge',
        prometheus: 'Prometheus', influxdb: 'InfluxDB', loki: 'Loki', zabbix: 'Zabbix', netdata: 'Netdata',
        redis: 'Redis', mongodb: 'MongoDB', opensearch: 'OpenSearch',
        tailscale: 'Tailscale', zerotier: 'ZeroTier', openvpn: 'OpenVPN', unbound: 'Unbound', bind: 'BIND', haproxy: 'HAProxy',
        dozzle: 'Dozzle', watchtower: 'Watchtower', homepage: 'Homepage', homarr: 'Homarr', dashy: 'Dashy',
        ollama: 'Ollama', openwebui: 'Open WebUI',
    };
    /** Services detected on the host, as known ids in a stable order. */
    function services(profile = {}) {
        const list = Array.isArray(profile?.detected_services) ? profile.detected_services : [];
        return [...new Set(list.filter(id => Object.hasOwn(serviceLabels, id)))];
    }
    const sourceIds = ['manual', 'detected', 'family', 'greeting', 'hint', 'pending', 'unavailable', 'unlisted'];
    function resolve(profile = {}) {
        if (known(profile.platform_icon)) return {id: profile.platform_icon, source: 'manual'};
        // 'server' is what the old probe stored when it learned nothing; it is not a detection.
        const detected = profile.detected_platform;
        if (known(detected) && detected !== 'server') {
            // An unlisted derivative (Omarchy on Arch, for example) is shown as its family.
            const derived = typeof profile.detected_os_id === 'string' && profile.detected_os_id !== ''
                && profile.detected_family === detected;
            return {id: detected, source: derived ? 'family' : 'detected'};
        }
        // Named by the SSH greeting during discovery; a connection later confirms or replaces it.
        if (known(profile.greeting_platform)) return {id: profile.greeting_platform, source: 'greeting'};
        const name = typeof profile.name === 'string' ? profile.name.slice(0, 128) : '';
        const matches = hints.filter(([, pattern]) => pattern.test(name));
        if (matches.length === 1) return {id: matches[0][0], source: 'hint'};
        // A probe that ran but named no platform in the catalog (OpenBSD, an unknown kernel).
        if (profile.detection_state === 'detected') return {id: 'server', source: 'unlisted'};
        return {id: 'server', source: profile.detection_state === 'unavailable' ? 'unavailable' : 'pending'};
    }
    function render(profile, doc = document) {
        const identity = profile?.id && known(profile.id) && sourceIds.includes(profile.source)
            ? profile : resolve(profile);
        const element = doc.createElement('span');
        element.className = 'host-platform-icon';
        element.setAttribute('data-platform', identity.id);
        const sources = {manual: 'manual choice', detected: 'detected after SSH connection',
            family: 'detected; derived from its family', greeting: 'SSH greeting; unverified', hint: 'name hint; unverified',
            pending: 'not detected yet', unavailable: 'detection not possible on this host',
            unlisted: 'detected; platform not recognised'};
        const translate = (key, fallback) => globalThis.i18n?.t(key) || fallback;
        const label = identity.id === 'server' ? translate('platform.server', 'Server') : labels[identity.id];
        element.title = `${label} — ${translate(`platform.${identity.source}`, sources[identity.source])}`;
        element.setAttribute('role', 'img');
        element.setAttribute('aria-label', element.title);
        if (Object.hasOwn(glyphs, identity.id)) {
            element.className += ' material-icons';
            element.textContent = glyphs[identity.id];
        } else {
            const logo = logoOf[identity.id] || identity.id;
            let assets = {};
            try {
                assets = JSON.parse(doc.getElementById?.('hostPlatformAssets')?.textContent || '{}');
            } catch {
                // Older embedded documents may not provide an asset manifest.
            }
            const base = doc.querySelector?.('meta[name="host-platform-icons"]')?.content || '/static/icons/platforms/';
            const asset = assets[logo] || `${base}${logo}.svg`;
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
        const stored = sameEndpoint ? profile : {};
        return render({name: profile?.name || '', platform_icon: profile?.platform_icon,
            detected_platform: session.detectedPlatform || stored.detected_platform,
            detected_family: stored.detected_family, detected_os_id: stored.detected_os_id,
            detection_state: stored.detection_state, greeting_platform: stored.greeting_platform}, doc);
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
