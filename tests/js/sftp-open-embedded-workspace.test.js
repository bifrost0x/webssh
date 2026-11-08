const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {};
global.document = {};
require('../../static/js/file-directory-requests.js');
require('../../static/js/sftp-file-manager.js');
const Manager = window.SFTPFileManager;

function fixture(tabs = []) {
    const manager = Object.create(Manager.prototype);
    const calls = [];
    const source = {sourceId: 'sftp-session:one', kind: 'sftp'};
    Object.assign(manager, {
        displayMode: 'embedded',
        panes: {left: {source, path: '/srv/project'}},
        workspace: {activePane: 'right', getTabs: () => tabs},
        open() { calls.push('open'); this.panes = {left: {}, right: {}}; },
        openWorkspaceSource: async (...args) => calls.push(['source', ...args]),
        activateSourceTab: (...args) => calls.push(['activate', ...args]),
    });
    return {manager, calls, source};
}

test('opening the full manager from session files carries the source and folder into the active pane', async () => {
    const {manager, calls, source} = fixture([{id: 'existing', source: {sourceId: 'other'}, paneState: {path: '/keep'}}]);
    await manager.openEmbeddedInWorkspace();
    assert.deepEqual(calls, ['open', ['source', 'right', source, {path: '/srv/project'}]]);
});

test('repeated expansion reuses the same source and folder without replacing other tabs', async () => {
    const {manager, calls} = fixture([{id: 'same', source: {sourceId: 'sftp-session:one'}, paneState: {path: '/srv/project'}}]);
    await manager.openEmbeddedInWorkspace();
    assert.deepEqual(calls, ['open', ['activate', 'right', 'same']]);
});

test('a different folder on the same source opens separately', async () => {
    const {manager, calls, source} = fixture([{id: 'same-host', source: {sourceId: 'sftp-session:one'}, paneState: {path: '/keep'}}]);
    await manager.openEmbeddedInWorkspace();
    assert.deepEqual(calls, ['open', ['source', 'right', source, {path: '/srv/project'}]]);
});

test('a delayed directory response preserves a path being edited, but explicit source changes replace it', () => {
    const manager = Object.create(Manager.prototype);
    manager.displayMode = 'modal';
    const input = {value: '/tm', title: '/home/testuser'};
    document.getElementById = () => input;
    document.activeElement = input;
    manager.updatePathInput('left', '/home/testuser', {preserveDraft: true});
    assert.equal(input.value, '/tm');
    manager.updatePathInput('left', '/other-source');
    assert.equal(input.value, '/other-source');
    input.value = input.title = '/tmp/../var';
    manager.updatePathInput('left', '/var', {preserveDraft: true});
    assert.equal(input.value, '/var');
});
