const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {localeTable} = require('./i18n-locales.js');
const id = require('../../static/js/host-identity');

const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/host-catalog.json'), 'utf8'));
const DAY = 86400;

test('manual role wins, rules derive, default is server', () => {
    assert.deepEqual(id.role({role_override: 'backup', detected_services: ['immich']}), {id: 'backup', source: 'manual', basis: null});
    assert.deepEqual(id.role({detected_platform: 'proxmox'}), {id: 'hypervisor', source: 'derived', basis: 'proxmox'});
    assert.deepEqual(id.role({detected_services: ['docker', 'paperless', 'postgresql']}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(id.role({detected_services: ['paperless']}), {id: 'docs', source: 'derived', basis: 'paperless'});
    assert.deepEqual(id.role({detected_services: ['docker', 'portainer']}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(id.role({detected_services: ['postgresql', 'docker']}).id, 'container');
    assert.deepEqual(id.role({detected_services: ['postgresql']}).id, 'database');
    assert.deepEqual(id.role({}), {id: 'server', source: 'default', basis: null});
    assert.deepEqual(id.role({role_override: 'bogus', detected_platform: 'future-os', detected_services: ['future']}), {id: 'server', source: 'default', basis: null});
});

test('rules apply in their documented order', () => {
    const derived = profile => id.role(profile);
    assert.deepEqual(derived({role_override: 'auto', detected_platform: 'proxmox'}), {id: 'hypervisor', source: 'derived', basis: 'proxmox'});
    assert.deepEqual(derived({detected_platform: 'proxmoxbackup', detected_services: ['immich']}), {id: 'backup', source: 'derived', basis: 'proxmoxbackup'});
    for (const platform of ['truenas', 'unraid', 'synology', 'qnap']) {
        assert.deepEqual(derived({detected_platform: platform, detected_services: ['jellyfin']}), {id: 'storage', source: 'derived', basis: platform});
    }
    assert.deepEqual(derived({detected_services: ['paperless', 'photoprism']}), {id: 'photos', source: 'derived', basis: 'photoprism'});
    assert.deepEqual(derived({detected_services: ['plex', 'owncloud']}), {id: 'cloud', source: 'derived', basis: 'owncloud'});
    assert.deepEqual(derived({detected_services: ['homeassistant', 'emby']}), {id: 'media', source: 'derived', basis: 'emby'});
    assert.deepEqual(derived({detected_platform: 'homeassistant'}), {id: 'smarthome', source: 'derived', basis: 'homeassistant'});
    assert.deepEqual(derived({detected_services: ['homeassistant', 'tailscale']}), {id: 'smarthome', source: 'derived', basis: 'homeassistant'});
    assert.deepEqual(derived({detected_platform: 'opnsense'}), {id: 'network', source: 'derived', basis: 'opnsense'});
    assert.deepEqual(derived({detected_services: ['grafana', 'pihole']}), {id: 'network', source: 'derived', basis: 'pihole'});
    assert.deepEqual(derived({detected_services: ['gitea', 'uptimekuma']}), {id: 'monitoring', source: 'derived', basis: 'uptimekuma'});
    assert.deepEqual(derived({detected_services: ['vaultwarden', 'gitlab']}), {id: 'dev', source: 'derived', basis: 'gitlab'});
    assert.deepEqual(derived({detected_services: ['vaultwarden', 'caddy']}), {id: 'passwords', source: 'derived', basis: 'vaultwarden'});
    assert.deepEqual(derived({detected_services: ['nginx', 'redis', 'influxdb']}), {id: 'database', source: 'derived', basis: 'redis'});
    assert.deepEqual(derived({detected_services: ['traefik', 'nginxproxymanager']}), {id: 'web', source: 'derived', basis: 'traefik'});
    assert.deepEqual(derived({detected_services: ['k3s']}), {id: 'container', source: 'derived', basis: 'k3s'});
    assert.deepEqual(derived({detected_services: ['watchtower', 'docker']}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({detected_services: ['dozzle']}), {id: 'container', source: 'derived', basis: 'dozzle'});
    assert.deepEqual(derived({detected_platform: 'docker'}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({platform_icon: 'docker'}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({detected_services: ['docker', 'watchtower', 'paperless']}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({detected_platform: 'docker', detected_services: ['paperless']}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({detected_services: ['postgresql', 'watchtower']}), {id: 'container', source: 'derived', basis: 'watchtower'});
    assert.deepEqual(derived({detected_services: ['postgresql', 'nginx']}), {id: 'database', source: 'derived', basis: 'postgresql'});
    assert.deepEqual(derived({detected_services: ['docker'], detected_graphical: true}), {id: 'container', source: 'derived', basis: 'docker'});
    assert.deepEqual(derived({detected_graphical: true}), {id: 'workstation', source: 'derived', basis: null});
    assert.deepEqual(derived({detected_graphical: 'true'}), {id: 'server', source: 'default', basis: null});
});

test('a container runtime names the role unless the platform does', () => {
    const derived = profile => id.role(profile);
    const container = {id: 'container', source: 'derived', basis: 'docker'};
    assert.deepEqual(derived({detected_services: ['paperless', 'docker', 'postgresql', 'redis']}), container);
    assert.deepEqual(derived({detected_services: ['immich', 'docker']}), container);
    assert.deepEqual(derived({detected_services: ['podman', 'jellyfin']}), {id: 'container', source: 'derived', basis: 'podman'});
    assert.deepEqual(derived({detected_services: ['paperless']}), {id: 'docs', source: 'derived', basis: 'paperless'});
    assert.deepEqual(derived({detected_platform: 'truenas', detected_services: ['docker']}), {id: 'storage', source: 'derived', basis: 'truenas'});
    assert.deepEqual(derived({detected_platform: 'proxmox', detected_services: ['docker', 'immich']}), {id: 'hypervisor', source: 'derived', basis: 'proxmox'});
    assert.deepEqual(derived({detected_platform: 'proxmoxbackup', detected_services: ['docker']}), {id: 'backup', source: 'derived', basis: 'proxmoxbackup'});
    assert.deepEqual(derived({detected_platform: 'opnsense', detected_services: ['docker']}), {id: 'network', source: 'derived', basis: 'opnsense'});
    assert.deepEqual(derived({detected_platform: 'opnsense', detected_services: ['jellyfin']}), {id: 'network', source: 'derived', basis: 'opnsense'});
    assert.deepEqual(derived({detected_platform: 'homeassistant', detected_services: ['docker']}), {id: 'smarthome', source: 'derived', basis: 'homeassistant'});
    assert.deepEqual(derived({detected_services: ['homeassistant', 'docker']}), container);
    assert.deepEqual(derived({detected_services: ['docker'], detected_graphical: true}), container);
    assert.equal(derived({role_override: 'docs', detected_services: ['docker']}).id, 'docs');
    assert.equal(derived({role_override: 'docs', detected_services: ['docker']}).source, 'manual');
});

test('apps lead the service logos on a container host, the runtime follows them', () => {
    const lead = profile => id.facts(profile).services;
    assert.deepEqual(lead({detected_services: ['docker', 'paperless', 'postgresql', 'redis']}), ['paperless', 'postgresql', 'redis', 'docker']);
    assert.deepEqual(lead({detected_services: ['docker', 'immich']}), ['immich', 'docker']);
    assert.deepEqual(lead({role_override: 'container', detected_services: ['docker', 'grafana']}), ['grafana', 'docker']);
    assert.deepEqual(lead({detected_services: ['docker', 'zerotier', 'bazarr']}), ['bazarr', 'docker', 'zerotier']);
    assert.deepEqual(lead({detected_services: ['docker']}), ['docker']);
});

test('infrastructure roles need infrastructure only', () => {
    // Any other application means the host is more than its database, proxy or runtime.
    assert.equal(id.role({detected_services: ['postgresql', 'sonarr']}).id, 'server');
    assert.equal(id.role({detected_services: ['nginx', 'samba']}).id, 'server');
    assert.equal(id.role({detected_services: ['docker', 'syncthing']}).id, 'container');
    assert.equal(id.role({detected_services: ['nginx', 'postgresql', 'syncthing']}).id, 'server');
    // Unknown ids are ignored, not counted as applications.
    assert.equal(id.role({detected_services: ['docker', 'future-app']}).id, 'container');
});

test('only verified platforms derive a role', () => {
    assert.equal(id.role({platform_icon: 'proxmox'}).id, 'hypervisor');
    assert.equal(id.role({name: 'Proxmox node'}).id, 'server');
    assert.equal(id.role({greeting_platform: 'opnsense'}).id, 'server');
    assert.equal(id.role({detected_platform: 'server', detected_services: 'docker'}).id, 'server');
    assert.equal(id.role(null).id, 'server');
});

test('facts are safe for empty, legacy and unknown data', () => {
    const f = id.facts({});
    assert.equal(f.state, 'pending'); assert.equal(f.version, null); assert.deepEqual(f.services, []);
    assert.equal(id.facts({detection_state: 'unavailable'}).state, 'unavailable');
    assert.equal(id.facts({detected_virt: 'hypervisor-x', detected_guests: -1}).virt, null);
    assert.equal(id.facts({detected_guests: 7, detected_virt: 'lxc'}).guests, 7);
    assert.equal(id.facts({platform_checked_at: Date.now() / 1000 - 8 * DAY}).stale, true);
});

test('facts validate every field and keep only catalog values', () => {
    const now = Date.now() / 1000;
    const f = id.facts({
        detected_platform: 'debian', detection_state: 'detected', detected_os_version: '12.5', detected_virt: 'vm',
        detected_guests: 0, detected_container_access: 'denied', platform_checked_at: now - DAY,
        detected_services: ['sonarr', 'docker', 'immich', '<img>', 'immich', 'apache'],
    });
    assert.deepEqual(f.platform, {id: 'debian', source: 'detected', label: 'Debian'});
    assert.equal(f.version, '12.5');
    assert.equal(f.virt, 'vm');
    assert.equal(f.guests, 0);
    assert.equal(f.containerAccess, 'denied');
    assert.deepEqual(f.services, ['immich', 'apache', 'sonarr', 'docker']);
    assert.equal(f.checkedAt, now - DAY);
    assert.equal(f.stale, false);
    assert.equal(f.state, 'detected');
    assert.deepEqual(id.facts({}).platform, {id: 'server', source: 'pending', label: 'Server'});
    for (const version of ['<b>1</b>', 'v1', '1'.repeat(17), 12, '']) assert.equal(id.facts({detected_os_version: version}).version, null);
    for (const guests of [1.5, '3', 10000, NaN, true]) assert.equal(id.facts({detected_guests: guests}).guests, null);
    for (const access of ['none', 'OK', 1]) assert.equal(id.facts({detected_container_access: access}).containerAccess, null);
    assert.equal(id.facts({detected_virt: 'wsl'}).virt, 'wsl');
    assert.equal(id.facts({detection_state: 'other'}).state, 'pending');
    for (const stamp of [true, '1700000000', -1, Infinity]) assert.equal(id.facts({platform_checked_at: stamp}).checkedAt, null);
    assert.equal(id.facts({}).stale, false);
    // The newer of the two probe stamps counts.
    assert.equal(id.facts({platform_checked_at: now - 9 * DAY, services_checked_at: now - DAY}).stale, false);
});

test('services list the role basis first, then the other role services, then the rest alphabetically', () => {
    assert.deepEqual(id.facts({detected_services: ['redis', 'caddy', 'postgresql']}).services, ['postgresql', 'caddy', 'redis']);
    assert.deepEqual(id.facts({detected_services: ['vaultwarden', 'grafana', 'bazarr']}).services, ['grafana', 'vaultwarden', 'bazarr']);
    // A manual role leads with the service that role is named after.
    assert.deepEqual(id.facts({role_override: 'passwords', detected_services: ['grafana', 'vaultwarden']}).services, ['vaultwarden', 'grafana']);
    assert.deepEqual(id.facts({role_override: 'workstation', detected_services: ['grafana', 'vaultwarden']}).services, ['grafana', 'vaultwarden']);
});

test('role ids and rule ids exist in the catalog fixture', () => {
    assert.deepEqual([...id.ROLES].sort(), [...catalog.roles].sort());
    assert.deepEqual(id.ROLES, ['hypervisor', 'backup', 'storage', 'container', 'docs', 'photos', 'media', 'cloud',
        'smarthome', 'network', 'monitoring', 'dev', 'passwords', 'database', 'web', 'workstation', 'server']);
    assert.ok(Object.isFrozen(id.ROLES));
    for (const rule of id.RULES) {
        assert.ok(id.ROLES.includes(rule.role), rule.role);
        for (const platform of rule.platforms) assert.ok(catalog.platforms.includes(platform), platform);
        for (const service of rule.services) assert.ok(catalog.services.includes(service), service);
    }
    for (const service of id.PRIORITY) assert.ok(catalog.services.includes(service), service);
    assert.deepEqual(new Set(id.RULES.map(rule => rule.role)).size, id.RULES.length);
});

test('every role has its own glyph and a label in every locale', () => {
    assert.deepEqual(Object.keys(id.ROLE_GLYPHS).sort(), [...id.ROLES].sort());
    const glyphs = Object.values(id.ROLE_GLYPHS);
    assert.equal(new Set(glyphs).size, glyphs.length);
    for (const glyph of glyphs) assert.match(glyph, /^[a-z_]+$/);
    const locales = localeTable();
    for (const lang of ['en', 'de', 'es', 'fr', 'vi', 'zh']) {
        for (const role of id.ROLES) assert.ok(locales[lang][`role.${role}`]?.trim(), `${lang} role.${role}`);
    }
});

test('the stylesheet colours every role and has a paper and forced-colors variant', () => {
    const css = fs.readFileSync(path.join(__dirname, '../../static/css/host-identity.css'), 'utf8');
    for (const role of id.ROLES) assert.match(css, new RegExp(`\\[data-role="${role}"\\]\\s*\\{[^}]*--role:[^}]*--role-ink:`), role);
    assert.match(css, /body\[data-theme="paper"\]/);
    assert.match(css, /@media \(forced-colors: active\)/);
    const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
    assert.ok(template.indexOf("js/host-identity.js") > template.indexOf("js/host-platform.js"));
    assert.ok(template.indexOf("css/host-identity.css") > template.indexOf("css/host-platform.css"));
});

test('describe gives the system and machine texts shared by cards and terminals', () => {
    const vm = id.describe({detected_platform: 'ubuntu', detection_state: 'detected', detected_os_version: '24.04',
        detected_virt: 'vm', detected_services: ['paperless']});
    assert.equal(vm.role.id, 'docs');
    assert.equal(vm.system, 'Ubuntu 24.04');
    assert.equal(vm.virt, 'VM');
    const derived = id.describe({detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy',
        detected_os_version: '3.1', detection_state: 'detected'});
    assert.equal(derived.system, 'Omarchy 3.1 · Arch Linux-based');
    assert.equal(id.describe({platform_icon: 'debian'}).system, 'Debian (manual choice)');
    // Unverified or missing platforms name no system; an invalid os id names no derivative.
    assert.equal(id.describe({greeting_platform: 'ubuntu'}).system, '');
    assert.equal(id.describe({name: 'ubuntu box'}).system, '');
    assert.equal(id.describe({detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: '<b>x</b>'}).system,
        'Arch Linux-based');
    assert.deepEqual({system: id.describe(null).system, virt: id.describe(null).virt, role: id.describe(null).role.id},
        {system: '', virt: '', role: 'server'});
    assert.equal(id.describe({detected_virt: 'bogus'}).virt, '');
});

test('VPN overlays say how a host is reached, not what it is', () => {
    const derived = services => id.role({detected_services: services});
    assert.equal(derived(['grafana', 'tailscale']).id, 'monitoring');
    assert.equal(derived(['gitea', 'tailscale']).id, 'dev');
    assert.equal(derived(['vaultwarden', 'wireguard']).id, 'passwords');
    assert.deepEqual(derived(['tailscale', 'docker']), {id: 'container', source: 'derived', basis: 'docker'});
    assert.equal(derived(['postgresql', 'tailscale']).id, 'database');
    assert.equal(derived(['docker', 'zerotier']).id, 'container');
    assert.equal(derived(['nginx', 'zerotier']).id, 'web');
    assert.equal(derived(['openvpn', 'nginx', 'caddy']).id, 'web');
    assert.equal(derived(['openvpn', 'nginx', 'docker']).id, 'container');
    // Only overlays: the host exists to route traffic.
    assert.deepEqual(derived(['wireguard']), {id: 'network', source: 'derived', basis: 'wireguard'});
    assert.deepEqual(derived(['zerotier', 'tailscale']), {id: 'network', source: 'derived', basis: 'tailscale'});
    assert.deepEqual(id.role({detected_platform: 'opnsense', detected_services: ['tailscale']}),
        {id: 'network', source: 'derived', basis: 'opnsense'});
    assert.deepEqual(derived(['pihole', 'tailscale']), {id: 'network', source: 'derived', basis: 'pihole'});
    // An overlay counts as nothing next to another application.
    assert.equal(derived(['tailscale', 'syncthing']).id, 'server');
    // A desktop that reaches the tailnet is still a workstation.
    assert.deepEqual(id.role({detected_services: ['tailscale'], detected_graphical: true}),
        {id: 'workstation', source: 'derived', basis: null});
});

test('VPN overlays are listed after every other service', () => {
    assert.deepEqual(id.facts({detected_services: ['tailscale', 'bazarr', 'grafana', 'wireguard']}).services,
        ['grafana', 'bazarr', 'tailscale', 'wireguard']);
    assert.deepEqual(id.facts({detected_services: ['zerotier', 'docker']}).services, ['docker', 'zerotier']);
    assert.deepEqual(id.facts({role_override: 'network', detected_services: ['openvpn', 'samba']}).services, ['samba', 'openvpn']);
    assert.deepEqual(id.facts({detected_services: ['wireguard']}).services, ['wireguard']);
    for (const service of id.VPN) assert.ok(catalog.services.includes(service), service);
});

test('placeholders take names verbatim, replacement patterns included', () => {
    assert.equal(id.format('Host profile: {name}', {name: 'db $& box'}), 'Host profile: db $& box');
    assert.equal(id.format('{a} and {a}', {a: "$' $$ $`"}), "$' $$ $` and $' $$ $`");
    assert.equal(id.format('{family}-based', {family: 'Debian'}), 'Debian-based');
    assert.equal(id.format('no {values}'), 'no {values}');
});

test('without HostPlatform every host is a plain Server with no facts', () => {
    const context = {};
    context.window = context;
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/host-identity.js'), 'utf8'), context);
    const alone = context.HostIdentity;
    const profile = {detected_platform: 'proxmox', detected_services: ['immich'], detected_virt: 'vm', detection_state: 'detected'};
    assert.equal(alone.role(profile).id, 'server');
    assert.equal(alone.role({role_override: 'backup'}).id, 'backup');
    const facts = alone.facts(profile);
    assert.deepEqual([...facts.services], []);
    assert.equal(facts.platform.id, 'server');
    assert.equal(facts.virt, 'vm');
    const described = alone.describe(profile);
    assert.equal(described.system, '');
    assert.equal(described.role.id, 'server');
});
