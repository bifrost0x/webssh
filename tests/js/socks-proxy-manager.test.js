const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(response) {
    const notifications = [];
    const sent = [];
    const element = {reportValidity: () => true, dataset: {}, classList: {contains: () => true}, hidden: false};
    const window = {
        addEventListener() {},
        showNotification: (message, type) => notifications.push({message, type}),
        socket: {
            connected: true,
            timeout: () => ({emit: (event, payload, callback) => { sent.push({event, payload}); callback(null, response); }}),
        },
    };
    const context = {window, document: {getElementById: () => element}};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/socks-proxy-manager.js'), 'utf8'), context);
    const manager = window.SocksProxyManager;
    manager.renderEditorState = manager.renderList = () => {};
    manager.draft = () => 'draft';
    return {manager, notifications, sent};
}

test('a rejected save leaves the server error to the global error handler', async () => {
    const {manager, notifications, sent} = setup({success: false, error: 'Invalid host format', code: 'validation_error'});
    await manager.save('Proxy', 'bad host!', '1080', '', 'none', true);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].event, 'save_socks_proxy');
    assert.deepEqual(notifications, []);
    assert.equal(manager.pending, false);
});

test('usage errors name hosts and persistent sessions separately', () => {
    const {manager, notifications} = setup();
    assert.equal(manager.handleUsageError({error: 'SOCKS proxy is used by 2 profiles', usages: ['A', 'B']}), true);
    assert.equal(manager.handleUsageError({error: 'SOCKS proxy is used by 1 persistent session', usages: ['Build box']}), true);
    assert.equal(manager.handleUsageError({error: 'Invalid host format'}), false);
    assert.deepEqual(notifications.map(item => item.message), [
        'This SOCKS5 proxy is used by 2 host(s): A, B',
        'This SOCKS5 proxy is still used by 1 persistent session(s). Close them before deleting the proxy: Build box',
    ]);
});
