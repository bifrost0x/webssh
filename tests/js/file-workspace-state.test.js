const assert = require('node:assert/strict');
const test = require('node:test');

global.window = {};
require('../../static/js/file-workspace-state.js');

const FileWorkspaceState = global.window.FileWorkspaceState;

test('workspace starts as an empty single left pane', () => {
    const workspace = new FileWorkspaceState(() => ({ path: '/', selected: new Set() }));

    assert.equal(workspace.layout, 'single');
    assert.equal(workspace.activePane, 'left');
    assert.deepEqual(workspace.getTabs('left'), []);
    assert.deepEqual(workspace.getTabs('right'), []);
    assert.equal(workspace.getActiveTab('left'), null);
});

test('opening tabs keeps independent pane state and strips credential fields', () => {
    const workspace = new FileWorkspaceState(() => ({ path: '/', selected: new Set() }));
    const leftState = { path: '/srv/app', selected: new Set([1]) };
    const rightState = { path: '/srv/archive', selected: new Set() };

    const leftTab = workspace.openTab('left', {
        sourceId: 'sftp-session:session-a', kind: 'sftp', label: 'Production',
        protocol: 'SFTP', capabilities: ['list'], ephemeral: false,
        password: 'must-not-survive', keyMaterial: 'private',
    }, leftState);
    const rightTab = workspace.openTab('right', {
        sourceId: 'sftp-session:session-b', kind: 'sftp', label: 'Archive',
        protocol: 'SFTP', capabilities: ['list'], ephemeral: false,
    }, rightState);

    assert.equal(workspace.getActiveTab('left'), leftTab);
    assert.equal(workspace.getActiveTab('right'), rightTab);
    assert.equal(leftTab.paneState, leftState);
    assert.equal(rightTab.paneState, rightState);
    assert.equal(leftTab.source.password, undefined);
    assert.equal(leftTab.source.keyMaterial, undefined);
    assert.deepEqual(Object.keys(leftTab.source).sort(), [
        'capabilities', 'endpoint', 'ephemeral', 'kind', 'label', 'protocol',
        'security', 'sourceId', 'status',
    ]);
});

test('activating a tab changes only the requested pane', () => {
    const workspace = new FileWorkspaceState(() => ({ path: '/' }));
    const first = workspace.openTab('left', { key: 'ssh:a', type: 'ssh', label: 'A' });
    const second = workspace.openTab('left', { key: 'ssh:b', type: 'ssh', label: 'B' });
    const right = workspace.openTab('right', { key: 'ssh:c', type: 'ssh', label: 'C' });

    workspace.activateTab('left', first.id);

    assert.equal(workspace.getActiveTab('left').id, first.id);
    assert.equal(workspace.getActiveTab('right').id, right.id);
    assert.notEqual(first.id, second.id);
});

test('closing the active tab chooses its nearest remaining neighbor', () => {
    const workspace = new FileWorkspaceState(() => ({ path: '/' }));
    const first = workspace.openTab('left', { key: 'ssh:a', type: 'ssh', label: 'A' });
    const second = workspace.openTab('left', { key: 'ssh:b', type: 'ssh', label: 'B' });
    const third = workspace.openTab('left', { key: 'ssh:c', type: 'ssh', label: 'C' });
    workspace.activateTab('left', second.id);

    const result = workspace.closeTab('left', second.id);

    assert.equal(result.closed.id, second.id);
    assert.equal(workspace.getActiveTab('left').id, third.id);
    workspace.closeTab('left', third.id);
    assert.equal(workspace.getActiveTab('left').id, first.id);
    workspace.closeTab('left', first.id);
    assert.equal(workspace.getActiveTab('left'), null);
});

test('layout changes preserve both panes and reject invalid values', () => {
    const workspace = new FileWorkspaceState(() => ({ path: '/' }));
    const right = workspace.openTab('right', { key: 'ssh:b', type: 'ssh', label: 'B' });
    workspace.setActivePane('right');
    workspace.setLayout('split');

    assert.equal(workspace.layout, 'split');
    assert.equal(workspace.activePane, 'right');
    assert.equal(workspace.getActiveTab('right').id, right.id);
    assert.throws(() => workspace.setLayout('quad'), /Unsupported workspace layout/);
    assert.throws(() => workspace.setActivePane('middle'), /Unsupported workspace pane/);
});
