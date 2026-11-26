const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const HostPlatform = require('../../static/js/host-platform.js');
const HostIdentity = require('../../static/js/host-identity.js');

function createElement(tagName = 'div') {
    const element = {
        tagName: tagName.toUpperCase(),
        children: [],
        parentNode: null,
        dataset: {},
        attributes: {},
        style: {},
        textContent: '',
        className: '',
        id: '',
        title: '',
        classList: {add() {}, remove() {}, contains: name => String(element.className).split(/\s+/).includes(name),
            toggle() { return false; }},
        appendChild(child) { return this.insertBefore(child, null); },
        append(...nodes) { nodes.forEach(node => this.appendChild(node)); },
        replaceChildren(...nodes) {
            this.children.forEach(child => { child.parentNode = null; });
            this.children = [];
            this.append(...nodes);
        },
        insertBefore(child, reference) {
            child.parentNode?.removeChild(child);
            child.parentNode = this;
            const index = reference ? this.children.indexOf(reference) : -1;
            this.children.splice(index < 0 ? this.children.length : index, 0, child);
            return child;
        },
        removeChild(child) {
            this.children = this.children.filter(candidate => candidate !== child);
            child.parentNode = null;
        },
        remove() { this.parentNode?.removeChild(this); },
        get firstElementChild() { return this.children[0] || null; },
        get nextElementSibling() {
            const siblings = this.parentNode?.children || [];
            return siblings[siblings.indexOf(this) + 1] || null;
        },
        addEventListener() {},
        setAttribute(name, value) { this.attributes[name] = String(value); },
        getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; },
        removeAttribute(name) { delete this.attributes[name]; },
        scrollIntoView() {},
        closest() { return null; },
        querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
        querySelectorAll(selector) {
            const matches = [];
            const visit = node => {
                if (String(node.className || '').split(/\s+/).includes(selector.slice(1))) matches.push(node);
                node.children.forEach(visit);
            };
            this.children.forEach(visit);
            return matches;
        },
    };
    return element;
}

function setup(profiles, extras = {}) {
    const tabs = createElement('div');
    tabs.id = 'sessionTabs';
    const document = {
        body: createElement('body'),
        createElement,
        createTextNode: value => ({textContent: String(value), children: []}),
        getElementById(id) {
            if (id === 'sessionTabs') return tabs;
            return tabs.children.find(child => child.id === id) || null;
        },
        querySelectorAll: () => [],
    };
    const window = {ProfileManager: {profiles}, HostPlatform, HostIdentity, addEventListener() {}, dispatchEvent() {}};
    window.window = window;
    const context = {console, document, window, setTimeout: () => 0, ...extras};
    vm.createContext(context);
    vm.runInContext(`${fs.readFileSync(path.join(__dirname, '../../static/js/session-manager.js'), 'utf8')}
;globalThis.__manager = SessionManager;`, context);
    const manager = context.__manager;
    manager.scrollTabIntoView = () => {};
    return {manager, tabs, document, window};
}

const PAPERLESS = {
    id: 'paper', name: 'Paper', host: 'paper.example.test', username: 'ops', port: 22,
    detected_platform: 'ubuntu', detection_state: 'detected',
    detected_services: ['docker', 'postgresql', 'redis', 'paperless', 'not-a-service'],
};
const session = (overrides = {}) => ({host: 'paper.example.test', username: 'ops', port: 22, profileId: 'paper', ...overrides});
const tabOf = (tabs, id) => tabs.children.find(child => child.id === `tab-${id}`);
const services = tab => (tab.querySelector('.tab-services')?.children || []).map(child => child.attributes['data-service']);

test('a tab of a Paperless host carries the docs role and its two main services after the label', () => {
    const {manager, tabs} = setup([PAPERLESS]);
    manager.sessions.s1 = session();
    manager.createSessionTab('s1');
    const tab = tabOf(tabs, 's1');
    assert.equal(tab.dataset.role, 'docs');
    assert.deepEqual(services(tab), ['paperless', 'docker']);
    const holder = tab.querySelector('.tab-services');
    assert.equal(tab.querySelector('.tab-label').nextElementSibling, holder);
    // The role is named for assistive technology, never as markup.
    const role = tab.querySelector('.tab-role');
    assert.equal(role.textContent, 'docs');
    assert.equal(role.attributes['data-i18n'], 'role.docs');
    assert.match(role.className, /\bsr-only\b/);
    // Each tile carries the service name; the logo inside is decoration.
    assert.deepEqual(holder.children.map(tile => [tile.className, tile.attributes.role, tile.attributes['aria-label'], tile.title]),
        [['tab-service', 'img', 'Paperless', 'Paperless'], ['tab-service', 'img', 'Docker', 'Docker']]);
    for (const tile of holder.children) {
        assert.equal(tile.children[0].className, 'host-service-icon');
        assert.equal(tile.children[0].attributes['aria-hidden'], 'true');
        assert.equal(tile.children[0].attributes.role, undefined);
    }
});

test('a tab whose endpoint differs from the saved host shows neither role nor services', () => {
    for (const overrides of [{username: 'root'}, {host: 'other.example.test'}, {port: 2222}, {jumpHostId: 'jump-1'},
        {socksProxyId: 'socks-1'}, {profileId: null}, {profileId: 'missing'}]) {
        const {manager, tabs} = setup([PAPERLESS]);
        manager.sessions.s1 = session(overrides);
        manager.createSessionTab('s1');
        const tab = tabOf(tabs, 's1');
        assert.equal(Object.hasOwn(tab.dataset, 'role'), false, JSON.stringify(overrides));
        assert.equal(tab.querySelector('.tab-services'), null, JSON.stringify(overrides));
        assert.equal(tab.querySelector('.tab-role'), null, JSON.stringify(overrides));
    }
});

test('a profile update changes role and services in place without rebuilding the tab', () => {
    const {manager, tabs, document} = setup([PAPERLESS]);
    manager.sessions.s1 = session();
    manager.createSessionTab('s1');
    const tab = tabOf(tabs, 's1');
    const label = tab.querySelector('.tab-label');
    const icon = tab.querySelector('.session-platform-icon');

    HostPlatform.refreshSessionIcons(manager, [{...PAPERLESS, detected_services: ['jellyfin', 'docker', 'nginx']}], document);
    assert.equal(tabOf(tabs, 's1'), tab);
    assert.equal(tab.querySelector('.tab-label'), label);
    assert.equal(tab.querySelector('.session-platform-icon'), icon);
    assert.equal(tab.dataset.role, 'media');
    assert.deepEqual(services(tab), ['jellyfin', 'docker']);
    assert.equal(tab.querySelectorAll('.tab-services').length, 1);
    assert.equal(tab.querySelectorAll('.tab-role').length, 1);

    HostPlatform.refreshSessionIcons(manager, [{...PAPERLESS, role_override: 'backup', detected_services: []}], document);
    assert.equal(tab.dataset.role, 'backup');
    assert.equal(tab.querySelector('.tab-services'), null);

    HostPlatform.refreshSessionIcons(manager, [{...PAPERLESS, host: 'moved.example.test'}], document);
    assert.equal(Object.hasOwn(tab.dataset, 'role'), false);
    assert.equal(tab.querySelector('.tab-role'), null);
    assert.equal(tab.querySelector('.tab-services'), null);
});

test('a platform detected in the session counts toward the role like it does for the icon', () => {
    const {manager, tabs} = setup([{...PAPERLESS, detected_platform: undefined, detected_services: []}]);
    manager.sessions.s1 = session({detectedPlatform: 'proxmox'});
    manager.createSessionTab('s1');
    assert.equal(tabOf(tabs, 's1').dataset.role, 'hypervisor');
});

test('pending connection tabs carry no role', () => {
    const {manager, tabs} = setup([PAPERLESS]);
    manager.createPendingConnection('r1', 'paper.example.test', 'ops', 22);
    const pending = tabs.children.find(child => child.id === 'pending-r1');
    assert.ok(pending);
    assert.equal(Object.hasOwn(pending.dataset, 'role'), false);
    assert.equal(pending.querySelector('.tab-services'), null);
});

test('the endpoint rule is shared by the icon and the identity', () => {
    const profile = {host: 'NAS.Example.test.', username: 'root'};
    assert.equal(HostPlatform.sameEndpoint({host: 'nas.example.test', username: 'root', port: 22}, profile), true);
    assert.equal(HostPlatform.sameEndpoint({host: 'nas.example.test', username: 'root', port: 22, jumpHostId: 'j'}, profile), false);
    assert.equal(HostPlatform.sameEndpoint({host: 'nas.example.test', username: 'root'}, null), false);
});

test('unchanged role and services keep their nodes on refresh', () => {
    const {manager, tabs, document} = setup([PAPERLESS]);
    manager.sessions.s1 = session();
    manager.createSessionTab('s1');
    const tab = tabOf(tabs, 's1');
    const role = tab.querySelector('.tab-role');
    const holder = tab.querySelector('.tab-services');
    HostPlatform.refreshSessionIcons(manager, [{...PAPERLESS, name: 'Renamed', detected_services: ['paperless', 'docker', 'redis']}], document);
    assert.equal(tab.querySelector('.tab-role'), role);
    assert.equal(tab.querySelector('.tab-services'), holder);
});

// A label that needs `need` pixels and gets what the visible tiles leave of `room`.
function laidOut(tab, {need, room, cap = Infinity}) {
    const label = tab.querySelector('.tab-label');
    const tiles = () => tab.querySelector('.tab-services').children.filter(tile => !tile.hidden).length;
    const width = () => Math.min(need, cap, room - tiles() * 21);
    Object.defineProperty(label, 'clientWidth', {configurable: true, get: width});
    Object.defineProperty(label, 'scrollWidth', {configurable: true, get: width});
    const name = label.children[0];
    Object.defineProperty(name, 'clientWidth', {configurable: true, get: width});
    Object.defineProperty(name, 'scrollWidth', {configurable: true, get: () => need});
    return tiles;
}

test('tiles give way whole, last first, while the tab name is cut', () => {
    const cases = [
        [{need: 50, room: 100}, 2],
        [{need: 70, room: 100}, 1],
        [{need: 90, room: 100}, 0],
        [{need: 200, room: 100}, 0],
        // A name cut by its own limit gains nothing from hiding tiles.
        [{need: 200, room: 100, cap: 40}, 2],
    ];
    for (const [layout, visible] of cases) {
        const {manager, tabs} = setup([PAPERLESS]);
        manager.sessions.s1 = session();
        manager.createSessionTab('s1');
        const tab = tabOf(tabs, 's1');
        const tiles = laidOut(tab, layout);
        HostPlatform.fitSessionTab(tab);
        assert.equal(tiles(), visible, JSON.stringify(layout));
        assert.equal(tab.querySelector('.tab-services').hidden, visible === 0, JSON.stringify(layout));
        // Freed space brings the tiles back.
        laidOut(tab, {need: 10, room: 100});
        HostPlatform.fitSessionTab(tab);
        assert.equal(tiles(), 2);
    }
});

test('the identity line appears only when the saved host says more than its name', () => {
    const bare = {id: 'plain', name: 'plainhost', host: 'paper.example.test', username: 'ops', port: 22};
    const cases = [
        [bare, false],
        [{...bare, detection_state: 'detected'}, false],
        [{...bare, detection_state: 'unavailable', detected_platform: 'server'}, false],
        [{...bare, role_override: 'server'}, false],
        [{...bare, greeting_platform: 'debian', name: 'ubuntu box'}, false],
        [{...bare, role_override: 'backup'}, true],
        [{...bare, detected_platform: 'debian', detection_state: 'detected'}, true],
        [{...bare, platform_icon: 'debian'}, true],
        [{...bare, detected_virt: 'vm'}, true],
        [{...bare, detected_services: ['samba']}, true],
        [{...bare, detected_graphical: true}, true],
    ];
    for (const [profile, shown] of cases) {
        const pane = createElement('div');
        const terminal = createElement('div');
        pane.append(terminal);
        const bar = HostPlatform.markIdentityBar(pane, session({profileId: 'plain'}), profile, {createElement});
        assert.equal(Boolean(bar), shown, JSON.stringify(profile));
        assert.equal(pane.children.length, shown ? 2 : 1, JSON.stringify(profile));
        assert.equal(pane.children.at(-1), terminal);
    }
    // Facts that go away take the line with them.
    const pane = createElement('div');
    HostPlatform.markIdentityBar(pane, session({profileId: 'plain'}), {...bare, detected_virt: 'vm'}, {createElement});
    assert.equal(pane.children.length, 1);
    HostPlatform.markIdentityBar(pane, session({profileId: 'plain'}), bare, {createElement});
    assert.equal(pane.children.length, 0);
});

test('closing a session stops watching the names in its tab', () => {
    const {manager, tabs, window} = setup([PAPERLESS], {
        TerminalManager: {destroyTerminal() {}},
        CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
    });
    manager.sessions.s1 = session();
    manager.createSessionTab('s1');
    const tab = tabOf(tabs, 's1');
    const released = [];
    window.HostPlatform = {...HostPlatform, releaseFits: root => released.push(root)};
    manager.updateSessionMeta = () => {};
    manager.notifyWorkspaceChange = () => {};
    manager.removeSessionUI('s1');
    assert.equal(tabOf(tabs, 's1'), undefined);
    assert.deepEqual(released, [tab]);
});
