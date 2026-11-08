const test = require('node:test');
const assert = require('node:assert/strict');
const icons = require('../../static/js/host-platform');

test('manual choice beats detection, detection beats bounded name hints', () => {
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'ubuntu', platform_icon: 'debian'}), {id: 'debian', source: 'manual'});
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'ubuntu'}), {id: 'ubuntu', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'Proxmox', detected_platform: 'server'}), {id: 'server', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'Proxmox node'}), {id: 'proxmox', source: 'hint'});
    // The SSH greeting from discovery ranks below a real detection and a manual choice, above the name.
    assert.deepEqual(icons.resolve({name: 'Proxmox node', greeting_platform: 'debian'}), {id: 'debian', source: 'greeting'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'debian', detected_platform: 'proxmox'}), {id: 'proxmox', source: 'detected'});
    assert.deepEqual(icons.resolve({name: 'x', greeting_platform: 'debian', platform_icon: 'docker'}), {id: 'docker', source: 'manual'});
    assert.equal(icons.resolve({name: 'x', greeting_platform: 'windows'}).source, 'fallback');
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
