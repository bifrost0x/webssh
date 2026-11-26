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
    let serviceManifest = {text: null, assets: {}};
    /** Versioned URL of a bundled service logo, or null when none is bundled. */
    function serviceAsset(id, doc = document) {
        if (typeof id !== 'string' || !Object.hasOwn(serviceLabels, id)) return null;
        // Without the manifest nothing says which logos exist, so no file is guessed.
        const text = doc.getElementById?.('hostServiceAssets')?.textContent || '{}';
        if (text !== serviceManifest.text) {
            let assets = {};
            try {
                assets = JSON.parse(text);
            } catch {
                // Older embedded documents may not provide a valid asset manifest.
            }
            serviceManifest = {text, assets: assets && typeof assets === 'object' ? assets : {}};
        }
        const asset = Object.hasOwn(serviceManifest.assets, id) ? serviceManifest.assets[id] : null;
        return typeof asset === 'string' && asset !== '' ? asset : null;
    }
    // Two capitals from the label: the first letters of two words, else the first
    // letter and the next capital (NetBird -> NB), else the first letter and the
    // next consonant, which keeps names like Samba and SABnzbd or Jenkins and
    // Jellyseerr apart (SM, SA, JN, JL).
    function monogram(label) {
        const words = String(label).match(/[\p{L}\p{N}]+/gu) || [];
        if (words.length > 1) return `${[...words[0]][0]}${[...words[1]][0]}`.toUpperCase();
        const letters = [...(words[0] || '')];
        const rest = letters.slice(1);
        const second = rest.find(letter => /\p{Lu}/u.test(letter))
            || rest.find(letter => !/[aeiouy]/i.test(letter)) || rest[0] || '';
        return `${letters[0] || ''}${second}`.toUpperCase();
    }
    /** A service logo (or monogram) for a known service id; null for any other value. */
    function renderService(id, doc = document) {
        if (typeof id !== 'string' || !Object.hasOwn(serviceLabels, id)) return null;
        const label = serviceLabels[id];
        const element = doc.createElement('span');
        element.className = 'host-service-icon';
        element.setAttribute('data-service', id);
        element.setAttribute('role', 'img');
        element.setAttribute('aria-label', label);
        element.title = label;
        const asset = serviceAsset(id, doc);
        if (asset) {
            element.style.maskImage = `url("${asset}")`;
        } else {
            const letters = doc.createElement('span');
            letters.className = 'host-service-monogram';
            letters.setAttribute('aria-hidden', 'true');
            letters.textContent = monogram(label);
            element.append(letters);
        }
        return element;
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
    /** Whether a saved host still describes the endpoint and route of a session. */
    function sameEndpoint(session, profile) {
        if (!profile || !session) return false;
        return canonicalHost(profile.host) === canonicalHost(session.host) && profile.username === session.username
            && Number(profile.port || 22) === Number(session.port || 22)
            && (profile.socks_proxy_id || null) === (session.socksProxyId || null)
            && (profile.jump_host_id || null) === (session.jumpHostId || null);
    }
    function renderSession(session = {}, profile, doc = document) {
        const stored = sameEndpoint(session, profile) ? profile : {};
        return render({name: profile?.name || '', platform_icon: profile?.platform_icon,
            detected_platform: session.detectedPlatform || stored.detected_platform,
            detected_family: stored.detected_family, detected_os_id: stored.detected_os_id,
            detection_state: stored.detection_state, greeting_platform: stored.greeting_platform}, doc);
    }
    const TAB_SERVICES = 2;
    const BAR_SERVICES = 4;
    /**
     * Hides whole tiles of a logo strip, last first, while `cut()` reports that
     * the text next to it is cut. A tile whose removal gives the text no room
     * stays: the text is longer than its own limit. Hidden tiles leave the
     * accessibility tree.
     */
    function dropTiles(holder, cut, width) {
        const tiles = [...holder.children];
        holder.hidden = false;
        tiles.forEach(tile => { tile.hidden = false; });
        for (let index = tiles.length - 1; index >= 0 && cut(); index -= 1) {
            const before = width();
            tiles[index].hidden = true;
            if (width() <= before) {
                tiles[index].hidden = false;
                break;
            }
        }
        holder.hidden = tiles.every(tile => tile.hidden);
    }
    // scrollWidth and clientWidth are rounded, so text a fraction of a pixel too
    // wide still draws its ellipsis; the fractional checks below catch that.
    function contentBox(element) {
        const box = element.getBoundingClientRect();
        const style = globalThis.getComputedStyle(element);
        const left = parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth);
        const right = parseFloat(style.paddingRight) + parseFloat(style.borderRightWidth);
        return {left: box.left + left, right: box.right - right, width: box.width - left - right};
    }
    const measurable = element => typeof element.getBoundingClientRect === 'function'
        && typeof globalThis.getComputedStyle === 'function';
    /** Whether the text of `element` is cut, measured by its text nodes. */
    function textCut(element) {
        if (element.scrollWidth > element.clientWidth) return true;
        const range = measurable(element) ? element.ownerDocument?.createRange?.() : null;
        if (!range) return false;
        range.selectNodeContents(element);
        return range.getBoundingClientRect().width > contentBox(element).width + 0.01;
    }
    /**
     * Whether a line of inline parts is cut. Its last part ends past the content
     * edge; a Range would miss generated separators between the parts.
     */
    function lineCut(element) {
        if (element.scrollWidth > element.clientWidth) return true;
        const last = element.lastElementChild;
        if (!last || !measurable(element)) return false;
        return last.getBoundingClientRect().right > contentBox(element).right + 0.01;
    }
    // A text is an element, or {lead, within}: a leading part that must end inside
    // the content box of the element it runs in, whatever follows it there.
    function isCut(text) {
        if (text.lead) {
            return measurable(text.within)
                && text.lead.getBoundingClientRect().right > contentBox(text.within).right + 0.01;
        }
        return text.children?.length ? lineCut(text) : textCut(text);
    }
    function widthOf(text) {
        const element = text.within || text;
        return typeof element.getBoundingClientRect === 'function' ? element.getBoundingClientRect().width : element.clientWidth;
    }
    /** Shows as many service tiles as fit without cutting the tab name. */
    function fitSessionTab(tab) {
        const label = tab?.querySelector('.tab-label');
        const holder = tab?.querySelector('.tab-services');
        if (!label || !holder) return;
        if (label.querySelector('.tab-rename-input')) return;
        const parts = [...label.children];
        dropTiles(holder, () => label.scrollWidth > label.clientWidth || parts.some(textCut), () => widthOf(label));
    }
    /** Shows as many tiles of `holder` as fit without cutting any of `texts`. */
    function fitTiles(holder, texts) {
        if (!holder?.isConnected || !texts.length) return;
        dropTiles(holder, () => texts.some(isCut), () => texts.reduce((sum, text) => sum + widthOf(text), 0));
    }
    // Text widths follow renames, theme fonts, panes and the viewport, so the text is what is watched.
    const fitters = new WeakMap();
    let fitObserver = null;
    let pendingFits = new Set();
    function observeFit(target, fit) {
        fitters.set(target, fit);
        if (!fitObserver && typeof globalThis.ResizeObserver === 'function') {
            fitObserver = new globalThis.ResizeObserver(entries => {
                const schedule = !pendingFits.size;
                entries.forEach(({target: element}) => pendingFits.add(element));
                if (!schedule) return;
                // Refitting inside the callback would resize observed text again in the
                // same frame and trip the browser's resize loop guard.
                const run = () => {
                    const targets = pendingFits;
                    pendingFits = new Set();
                    targets.forEach(element => {
                        if (!element.isConnected) fitObserver.unobserve(element);
                        else fitters.get(element)?.();
                    });
                };
                if (typeof globalThis.requestAnimationFrame === 'function') globalThis.requestAnimationFrame(run);
                else run();
            });
        }
        fitObserver?.observe(target);
    }
    /** Keeps the tiles of `holder` fitted next to the given texts while they change size. */
    function keepTilesFitting(holder, ...candidates) {
        const texts = candidates.filter(Boolean);
        if (!holder || !texts.length) return;
        fitTiles(holder, texts);
        texts.forEach(text => observeFit(text.within || text, () => fitTiles(holder, texts)));
    }
    function serviceTile(id, className, doc) {
        const logo = renderService(id, doc);
        if (!logo) return null;
        // The tile carries the name; the logo inside is decoration.
        ['title', 'role', 'aria-label'].forEach(attribute => logo.removeAttribute(attribute));
        logo.setAttribute('aria-hidden', 'true');
        const tile = doc.createElement('span');
        tile.className = className;
        tile.setAttribute('data-service', id);
        tile.setAttribute('role', 'img');
        tile.setAttribute('aria-label', serviceLabels[id]);
        tile.title = serviceLabels[id];
        tile.append(logo);
        return tile;
    }
    /** Service tiles for known ids, each with the given class; unknown ids are skipped. */
    function serviceTiles(ids, className, doc = document) {
        return (Array.isArray(ids) ? ids : []).map(id => serviceTile(id, className, doc)).filter(Boolean);
    }
    // A platform detected in this session counts until the saved host is reloaded
    // with it, exactly as for the platform icon.
    function sessionProfile(session, profile) {
        const detected = session?.detectedPlatform;
        if (!detected || detected === profile.detected_platform) return profile;
        // The saved version and family describe the platform that was replaced.
        return {...profile, detected_platform: detected, detected_os_version: null, detected_family: null, detected_os_id: null};
    }
    /**
     * What the saved host says about the machine behind a session, or null while
     * the session does not match its endpoint. Every text is from a catalog or
     * the host's own name; none of it is markup.
     */
    function sessionIdentity(session, profile) {
        const Identity = globalThis.HostIdentity;
        if (!Identity?.describe || !sameEndpoint(session, profile)) return null;
        const {role, facts, system, virt} = Identity.describe(sessionProfile(session, profile));
        const label = globalThis.i18n?.t(`role.${role.id}`);
        const name = typeof profile.name === 'string' && profile.name.trim() ? profile.name.trim() : String(session.host || '');
        return {role: role.id, glyph: Identity.ROLE_GLYPHS[role.id] || 'dns',
            label: label && label !== `role.${role.id}` ? label : role.id,
            name, system, virt, services: facts.services.slice(0, BAR_SERVICES)};
    }
    /**
     * The identity line above a terminal pane: role, host name, system, machine
     * and up to four service logos. Removed when the session does not match its
     * saved host; rebuilt only when what it shows changes.
     */
    function markIdentityBar(pane, session, profile, doc = document) {
        if (!pane) return null;
        const current = [...(pane.children || [])].find(child => child.classList?.contains('session-identity-bar')) || null;
        const identity = sessionIdentity(session, profile);
        if (!identity) {
            current?.remove();
            return null;
        }
        const parts = [identity.label, identity.name, identity.system, identity.virt].filter(Boolean);
        const names = identity.services.map(id => serviceLabels[id]);
        const summary = [...parts, names.join(', ')].filter(Boolean).join(' · ');
        const key = JSON.stringify([identity.role, parts, identity.services]);
        if (current?.dataset.identity === key) {
            if (pane.firstElementChild !== current) pane.insertBefore(current, pane.firstElementChild);
            return current;
        }
        const bar = doc.createElement('div');
        bar.className = 'session-identity-bar';
        bar.dataset.role = identity.role;
        bar.dataset.identity = key;
        bar.setAttribute('role', 'note');
        bar.setAttribute('aria-label', summary);
        bar.title = summary;
        const glyph = doc.createElement('span');
        glyph.className = 'session-identity-glyph material-icons';
        glyph.setAttribute('aria-hidden', 'true');
        glyph.textContent = identity.glyph;
        const text = doc.createElement('span');
        text.className = 'session-identity-text';
        text.setAttribute('aria-hidden', 'true');
        [['role', identity.label], ['name', identity.name], ['system', identity.system], ['virt', identity.virt]]
            .filter(([, value]) => value).forEach(([part, value]) => {
                const item = doc.createElement('span');
                item.className = `session-identity-${part}`;
                item.textContent = value;
                text.append(item);
            });
        bar.append(glyph, text);
        const tiles = serviceTiles(identity.services, 'session-identity-service', doc);
        let holder = null;
        if (tiles.length) {
            holder = doc.createElement('span');
            holder.className = 'session-identity-services';
            holder.setAttribute('aria-hidden', 'true');
            holder.append(...tiles);
            bar.append(holder);
        }
        if (current) current.replaceWith(bar);
        else pane.insertBefore(bar, pane.firstElementChild);
        if (holder) keepTilesFitting(holder, text);
        return bar;
    }
    /** Role and main services of a session tab, from the saved host only while it matches the endpoint. */
    function markSessionTab(tab, session, profile, doc = document) {
        const Identity = globalThis.HostIdentity;
        const label = tab?.querySelector('.tab-label');
        if (!label) return;
        if (!Identity || !sameEndpoint(session, profile)) {
            tab.querySelector('.tab-role')?.remove();
            tab.querySelector('.tab-services')?.remove();
            delete tab.dataset.role;
            return;
        }
        const stored = sessionProfile(session, profile);
        const role = Identity.role(stored).id;
        const ids = Identity.facts(stored).services.slice(0, TAB_SERVICES);
        const shown = [...(tab.querySelector('.tab-services')?.children || [])].map(tile => tile.getAttribute('data-service'));
        if (tab.dataset.role === role && tab.querySelector('.tab-role') && shown.join() === ids.join()) return;
        tab.querySelector('.tab-role')?.remove();
        tab.querySelector('.tab-services')?.remove();
        tab.dataset.role = role;
        const name = doc.createElement('span');
        name.className = 'tab-role sr-only';
        name.setAttribute('data-i18n', `role.${role}`);
        name.textContent = globalThis.i18n?.t(`role.${role}`) || role;
        tab.insertBefore(name, label);
        if (!ids.length) return;
        const holder = doc.createElement('span');
        holder.className = 'tab-services';
        holder.append(...serviceTiles(ids, 'tab-service', doc));
        tab.insertBefore(holder, label.nextElementSibling);
        if (tab.isConnected) fitSessionTab(tab);
        observeFit(label, () => fitSessionTab(tab));
    }
    function refreshSessionIcons(manager, profiles = [], doc = globalThis.document) {
        if (!manager?.sessions || !doc) return;
        for (const [id, session] of Object.entries(manager.sessions)) {
            const tab = doc.getElementById(`tab-${id}`);
            const holder = tab?.querySelector('.session-platform-icon');
            if (!holder) continue;
            const profile = profiles.find(item => item.id === session.profileId);
            holder.replaceChildren(renderSession(session, profile, doc));
            markSessionTab(tab, session, profile, doc);
        }
        manager.refreshSessionIdentity?.();
    }
    return {labels, resolve, services, serviceLabels, serviceAsset, render, renderService, renderSession,
        sameEndpoint, markSessionTab, fitSessionTab, refreshSessionIcons, sessionIdentity, markIdentityBar, serviceTiles,
        keepTilesFitting};
});
