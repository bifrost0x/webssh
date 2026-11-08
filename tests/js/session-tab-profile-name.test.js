const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(profiles) {
    const context = {document: {body: {dataset: {}}, createElement: () => ({className: '', textContent: ''})},
        window: {ProfileManager: {profiles}}};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/session-manager.js'), 'utf8')
        + '\n globalThis.manager = SessionManager;', context);
    const manager = context.manager;
    manager.sessions.s = {host: '10.10.1.253', port: 22, username: 'root', profileId: 'baldur'};
    return manager;
}

function element() {
    return {children: [], innerHTML: '', title: '', appendChild(child) { this.children.push(child); }};
}

test('a saved host names the tab instead of its address', () => {
    const manager = setup([{id: 'baldur', name: 'Baldur', host: '10.10.1.253', username: 'root'}]);
    assert.equal(manager.getDisplayLabel('s', 'root', '10.10.1.253'), 'Baldur');
});

test('a profile that no longer describes the endpoint does not rename the tab', () => {
    const manager = setup([{id: 'baldur', name: 'Baldur', host: '10.10.1.99', username: 'root'}]);
    assert.equal(manager.getDisplayLabel('s', 'root', '10.10.1.253'), 'root@10.10.1.253');
});

test('a custom tab name still wins over the saved host name', () => {
    const manager = setup([{id: 'baldur', name: 'Baldur', host: '10.10.1.253', username: 'root'}]);
    manager.sessions.s.displayName = 'Hypervisor';
    assert.equal(manager.getDisplayLabel('s', 'root', '10.10.1.253'), 'Hypervisor');
});

test('ad-hoc connections keep the address and user', () => {
    const manager = setup([]);
    manager.sessions.s.profileId = null;
    assert.equal(manager.getDisplayLabel('s', 'root', '10.10.1.253'), 'root@10.10.1.253');
});

test('the tab shows the saved name with the user and keeps the address as a tooltip', () => {
    const manager = setup([{id: 'baldur', name: 'Baldur', host: '10.10.1.253', username: 'root'}]);
    const label = element();
    manager.renderTabLabelContent(label, 's');
    assert.deepEqual(label.children.map(child => child.textContent), ['Baldur', 'root']);
    assert.equal(label.title, 'root@10.10.1.253');
});
