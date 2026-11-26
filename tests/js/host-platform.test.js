const test = require('node:test');
const assert = require('node:assert/strict');
const icons = require('../../static/js/host-platform');

test('manual choice beats detection, detection beats bounded name hints', () => {
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'ubuntu', platform_icon: 'debian'}), {id: 'debian', source: 'manual'});
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'ubuntu'}), {id: 'ubuntu', source: 'detected'});
    // The old probe stored 'server' when it learned nothing; that is not a detection.
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'server'}), {id: 'proxmox', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'Proxmox node'}), {id: 'proxmox', source: 'hint'});
    // The SSH greeting from discovery ranks below a real detection and a manual choice, above the name.
    assert.deepEqual(icons.resolve({name: 'Proxmox node', greeting_platform: 'debian'}), {id: 'debian', source: 'greeting'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'debian', detected_platform: 'proxmox'}), {id: 'proxmox', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'debian', platform_icon: 'docker'}), {id: 'docker', source: 'manual'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'windows'}), {id: 'windows', source: 'greeting'});
    for (const name of ['notproxmox', 'Ubuntu Proxmox', '<img src=x>', 'x'.repeat(5000)]) {
        assert.equal(icons.resolve({name}).id, 'server');
    }
    assert.deepEqual(icons.resolve({name: 'Docker host'}), {id: 'docker', source: 'hint'});
    assert.equal(icons.resolve({name: 'Docker', detected_platform: 'linux'}).id, 'linux');
    assert.equal(icons.resolve({name: 'Ubuntu', platform_icon: '../bad', detected_platform: '<svg>'}).id, 'ubuntu');
});

test('renderer uses only fixed local assets and accessible provenance', () => {
    const doc = {createElement(tag) { return {tag, style: {}, setAttribute(key, value) {this[key] = value;}}; }};
    const icon = icons.render({name: 'Ubuntu'}, doc);
    assert.match(icon.style.maskImage, /^url\("\/static\/icons\/platforms\/ubuntu.svg"\)$/);
    assert.match(icon.title, /name hint/i);
    assert.equal(icon.role, 'img');
    assert.equal(icon['aria-label'], icon.title);
    assert.equal(icons.render({platform_icon: '../../bad'}, doc).textContent, 'dns');
});
const fakeDocument = () => ({createElement() {return {style: {}, setAttribute(key, value) {this[key] = value;}};}});
test('session cache follows canonical endpoint and exact route/user', () => {
    const profile = {name: 'Ubuntu', host: 'NAS.Example.test', username: 'root', detected_platform: 'debian'};
    const session = {host: 'nas.example.test', username: 'root', port: 22};
    assert.match(icons.renderSession(session, profile, fakeDocument()).title, /Debian.*detected/);
    assert.match(icons.renderSession({...session, jumpHostId: 'other'}, profile, fakeDocument()).title, /Ubuntu.*name hint/);
    assert.match(icons.renderSession({...session, username: 'other'}, profile, fakeDocument()).title, /Ubuntu.*name hint/);
    assert.match(icons.renderSession({...session, host: '2001:db8::1'}, {...profile, host: '2001:0db8:0000:0000:0000:0000:0000:0001'}, fakeDocument()).title, /Debian.*detected/);
});
test('icons honor the configured reverse-proxy prefix', () => {
    const doc = fakeDocument();
    doc.querySelector = () => ({content: '/tools/webssh/static/icons/platforms/'});
    assert.equal(icons.render({name: 'Ubuntu'}, doc).style.maskImage, 'url("/tools/webssh/static/icons/platforms/ubuntu.svg")');
});

test('icons retain per-file content versions and reverse-proxy prefixes', () => {
    const doc = fakeDocument();
    doc.getElementById = id => id === 'hostPlatformAssets' ? {
        textContent: JSON.stringify({ubuntu: '/tools/webssh/static/icons/platforms/ubuntu.svg?v=1234567890abcdef'}),
    } : null;
    assert.equal(icons.render({name: 'Ubuntu'}, doc).style.maskImage,
        'url("/tools/webssh/static/icons/platforms/ubuntu.svg?v=1234567890abcdef")');
    doc.getElementById = () => ({textContent: 'invalid json'});
    assert.equal(icons.render({name: 'Ubuntu'}, doc).style.maskImage,
        'url("/static/icons/platforms/ubuntu.svg")');
});

test('detected services are limited to known names and deduplicated', () => {
    assert.deepEqual(icons.services({detected_services: ['docker', 'nextcloud', 'docker', '<img src=x>', 'plex']}), ['docker', 'nextcloud', 'plex']);
    assert.deepEqual(icons.services({detected_services: 'docker'}), []);
    assert.deepEqual(icons.services({}), []);
    assert.equal(icons.serviceLabels.homeassistant, 'Home Assistant');
});

const catalog = require('./fixtures/host-catalog.json');

test('every catalog platform and service has a label', () => {
    assert.deepEqual(Object.keys(icons.labels).sort(), catalog.platforms);
    for (const id of catalog.platforms) assert.ok(icons.labels[id], id);
    assert.deepEqual(Object.keys(icons.serviceLabels).sort(), catalog.services);
    for (const id of catalog.services) assert.ok(icons.serviceLabels[id], id);
});

test('resolution ladder never treats server as detected and names pending and unavailable hosts', () => {
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'server'}), {id: 'server', source: 'pending'});
    assert.deepEqual(icons.resolve({name: 'x', detection_state: 'unavailable'}), {id: 'server', source: 'unavailable'});
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy'}), {id: 'archlinux', source: 'family'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'windows'}), {id: 'windows', source: 'greeting'});
    for (const id of ['mikrotik', 'cisco', 'embedded']) {
        assert.deepEqual(icons.resolve({name: 'x', greeting_platform: id}), {id, source: 'greeting'});
    }
    // A failed later probe keeps facts an earlier one found.
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'debian', detection_state: 'unavailable'}), {id: 'debian', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy', detection_state: 'unavailable'}),
        {id: 'archlinux', source: 'family'});
    // Better sources than nothing still win over an unavailable probe.
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'debian', detection_state: 'unavailable'}), {id: 'debian', source: 'greeting'});
    assert.deepEqual(icons.resolve({name: 'Proxmox', detection_state: 'unavailable'}), {id: 'proxmox', source: 'hint'});
    // The probe ran but the platform is not in the catalog (OpenBSD, an unknown kernel).
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'server', detection_state: 'detected'}), {id: 'server', source: 'unlisted'});
    assert.deepEqual(icons.resolve({name: 'x', detection_state: 'detected'}), {id: 'server', source: 'unlisted'});
    assert.deepEqual(icons.resolve({name: 'Proxmox', detection_state: 'detected'}), {id: 'proxmox', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'embedded', detection_state: 'detected'}), {id: 'embedded', source: 'greeting'});
    // A marker platform on a derivative is the platform itself, not its family.
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'proxmoxbackup', detected_family: 'debian', detected_os_id: 'pbs'}), {id: 'proxmoxbackup', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'x', detected_platform: 'debian', detected_family: 'debian'}), {id: 'debian', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'x', platform_icon: 'server', detected_platform: 'debian'}), {id: 'server', source: 'manual'});
});

test('name hints cover the new platforms without overlapping', () => {
    assert.deepEqual(icons.resolve({name: 'Proxmox Backup'}), {id: 'proxmoxbackup', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'proxmox-01'}), {id: 'proxmox', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'Linux Mint laptop'}), {id: 'linuxmint', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'core switch cisco'}), {id: 'cisco', source: 'hint'});
    assert.deepEqual(icons.resolve({name: 'Windows build box'}), {id: 'windows', source: 'hint'});
    assert.equal(icons.resolve({name: 'rocky'}).id, 'server');
});

test('every platform renders a local icon, a family logo or a glyph', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const directory = path.join(__dirname, '../../static/icons/platforms');
    const files = new Set(fs.readdirSync(directory).filter(name => name.endsWith('.svg')).map(name => name.slice(0, -4)));
    for (const id of catalog.platforms) {
        const icon = icons.render({platform_icon: id}, fakeDocument());
        assert.equal(icon['data-platform'], id);
        assert.ok(icon.title.startsWith(`${icons.labels[id]} — `), id);
        if (icon.textContent) {
            assert.match(icon.className, /material-icons/, id);
            assert.ok(['server', 'windows', 'embedded'].includes(id), id);
            continue;
        }
        const [, file] = icon.style.maskImage.match(/^url\("\/static\/icons\/platforms\/([a-z]+)\.svg"\)$/) || [];
        assert.ok(files.has(file), `${id} -> ${file}`);
    }
    assert.match(icons.render({platform_icon: 'proxmoxbackup'}, fakeDocument()).style.maskImage, /proxmox\.svg/);
    // Rocky Linux is not Red Hat; like Gentoo it falls back to the neutral Linux mark.
    assert.match(icons.render({platform_icon: 'rockylinux'}, fakeDocument()).style.maskImage, /\/linux\.svg"/);
    assert.match(icons.render({platform_icon: 'gentoo'}, fakeDocument()).style.maskImage, /\/linux\.svg"/);
    const doc = fakeDocument();
    doc.getElementById = id => id === 'hostPlatformAssets' ? {textContent: JSON.stringify({proxmox: '/static/icons/platforms/proxmox.svg?v=0123456789abcdef'})} : null;
    assert.equal(icons.render({platform_icon: 'proxmoxbackup'}, doc).style.maskImage, 'url("/static/icons/platforms/proxmox.svg?v=0123456789abcdef")');
});

test('source texts name pending, unavailable and family identities', () => {
    assert.match(icons.render({name: 'x'}, fakeDocument()).title, /^Server — not detected yet$/);
    assert.match(icons.render({name: 'x', detection_state: 'unavailable'}, fakeDocument()).title, /^Server — detection not possible/);
    assert.match(icons.render({name: 'x', detection_state: 'detected'}, fakeDocument()).title, /^Server — detected; platform not recognised$/);
    assert.match(icons.render({id: 'server', source: 'unlisted'}, fakeDocument()).title, /not recognised/);
    assert.match(icons.render({name: 'x', detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy'}, fakeDocument()).title,
        /^Arch Linux — detected; derived from its family$/);
    const session = {host: 'h', username: 'u', port: 22};
    const profile = {name: 'x', host: 'h', username: 'u', detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy'};
    assert.match(icons.renderSession(session, profile, fakeDocument()).title, /family/);
    assert.match(icons.renderSession(session, {name: 'x', host: 'h', username: 'u', detection_state: 'unavailable'}, fakeDocument()).title, /not possible/);
});

const serviceDocument = (manifest) => {
    const doc = {
        createElement(tag) {
            const element = {tag, style: {}, children: [], className: '', setAttribute(key, value) {this[key] = value;},
                append(...nodes) {this.children.push(...nodes);}};
            Object.defineProperty(element, 'innerHTML', {set() {throw new Error('innerHTML must not be used');}});
            return element;
        },
    };
    if (manifest !== undefined) {
        doc.getElementById = id => id === 'hostServiceAssets' ? {textContent: manifest} : null;
    }
    return doc;
};

test('service logos come from the versioned manifest and carry the label', () => {
    const doc = serviceDocument(JSON.stringify({immich: '/tools/webssh/static/icons/services/immich.svg?v=0123456789abcdef'}));
    const icon = icons.renderService('immich', doc);
    assert.equal(icon.tag, 'span');
    assert.equal(icon.className, 'host-service-icon');
    assert.equal(icon['data-service'], 'immich');
    assert.equal(icon.role, 'img');
    assert.equal(icon['aria-label'], 'Immich');
    assert.equal(icon.title, 'Immich');
    assert.equal(icon.style.maskImage, 'url("/tools/webssh/static/icons/services/immich.svg?v=0123456789abcdef")');
    assert.deepEqual(icon.children, []);
    assert.equal(icons.serviceAsset('immich', doc), '/tools/webssh/static/icons/services/immich.svg?v=0123456789abcdef');
});

test('services without a bundled logo show a two-letter monogram', () => {
    const doc = serviceDocument(JSON.stringify({immich: '/static/icons/services/immich.svg?v=1'}));
    const cases = {filebrowser: 'FB', haproxy: 'HA', stirlingpdf: 'SP', openwebui: 'OW', samba: 'SA', k3s: 'K3'};
    for (const [id, letters] of Object.entries(cases)) {
        const icon = icons.renderService(id, doc);
        assert.equal(icon.className, 'host-service-icon', id);
        assert.equal(icon.style.maskImage, undefined, id);
        assert.equal(icon['aria-label'], icons.serviceLabels[id], id);
        const [monogram] = icon.children;
        assert.equal(monogram.className, 'host-service-monogram', id);
        assert.equal(monogram.textContent, letters, id);
        assert.equal(monogram['aria-hidden'], 'true', id);
    }
    assert.equal(icons.serviceAsset('filebrowser', doc), null);
    // Without a manifest nothing is known to exist, so no request for a missing file is made.
    assert.equal(icons.serviceAsset('immich', serviceDocument()), null);
    assert.equal(icons.serviceAsset('immich', serviceDocument('invalid json')), null);
    assert.equal(icons.renderService('immich', serviceDocument()).children[0].textContent, 'IM');
});

test('monograms follow word and capital boundaries of the label', () => {
    const doc = serviceDocument('{}');
    const labels = {netbird: 'NetBird', uptime: 'Uptime Kuma', single: 'Grafana', camel: 'qBittorrent', short: 'X'};
    try {
        Object.assign(icons.serviceLabels, labels);
        const letters = id => icons.renderService(id, doc).children[0].textContent;
        assert.equal(letters('netbird'), 'NB');
        assert.equal(letters('uptime'), 'UK');
        assert.equal(letters('single'), 'GR');
        assert.equal(letters('camel'), 'QB');
        assert.equal(letters('short'), 'X');
    } finally {
        for (const id of Object.keys(labels)) delete icons.serviceLabels[id];
    }
});

test('unknown services render nothing and labels never become markup', () => {
    const doc = serviceDocument(JSON.stringify({future: '/static/icons/services/future.svg', '<img>': '/x.svg'}));
    assert.equal(icons.renderService('future', doc), null);
    assert.equal(icons.renderService('<img src=x>', doc), null);
    assert.equal(icons.renderService('__proto__', doc), null);
    assert.equal(icons.renderService(undefined, doc), null);
    assert.equal(icons.serviceAsset('future', doc), null);
    try {
        icons.serviceLabels.markup = '<img src=x onerror=alert(1)> Probe';
        const icon = icons.renderService('markup', doc);
        assert.equal(icon.title, '<img src=x onerror=alert(1)> Probe');
        assert.equal(icon['aria-label'], icon.title);
        assert.equal(icon.children[0].textContent, 'IS');
    } finally {
        delete icons.serviceLabels.markup;
    }
});
