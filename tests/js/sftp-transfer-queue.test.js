const assert = require('node:assert/strict');
const test = require('node:test');

global.window = {};
global.document = { getElementById: () => null };
require('../../static/js/file-workspace-state.js');
require('../../static/js/sftp-file-manager.js');
const SFTPFileManager = global.window.SFTPFileManager;

function classList() {
    const values = new Set();
    return {
        add(...names) { names.forEach(name => values.add(name)); },
        remove(...names) { names.forEach(name => values.delete(name)); },
        toggle(name, force) {
            const next = force === undefined ? !values.has(name) : Boolean(force);
            if (next) values.add(name); else values.delete(name);
            return next;
        },
        contains(name) { return values.has(name); },
    };
}

const ALL_FILE_CAPABILITIES = [
    'list', 'read', 'write', 'mkdir', 'rename', 'delete',
    'preview', 'edit', 'recursive', 'remote-transfer',
];

function fileSource(sourceId, overrides = {}) {
    return {
        sourceId,
        kind: 'sftp',
        label: sourceId,
        endpoint: 'example.test:22',
        protocol: 'SFTP',
        capabilities: [...ALL_FILE_CAPABILITIES],
        ephemeral: sourceId.startsWith('sftp-quick:'),
        security: { hostKeyVerified: true },
        access: {},
        ...overrides,
    };
}

function serverFileSource(sourceId, overrides = {}) {
    const normalized = fileSource(sourceId, overrides);
    return {
        source_id: normalized.sourceId,
        kind: normalized.kind,
        label: normalized.label,
        endpoint: normalized.endpoint,
        protocol: normalized.protocol,
        capabilities: normalized.capabilities,
        ephemeral: normalized.ephemeral,
        security: { host_key_verified: normalized.security.hostKeyVerified },
        access: Object.fromEntries(
            Object.entries(normalized.access || {}).map(([key, value]) => [
                key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`),
                value,
            ]),
        ),
    };
}

function filePane(manager, sourceId, overrides = {}) {
    return {
        ...manager.createEmptyPaneState(),
        source: fileSource(sourceId),
        ...overrides,
    };
}

test('standalone workspace starts in one pane with independent empty states', () => {
    const manager = Object.create(SFTPFileManager.prototype);

    manager.initializeWorkspaceState();

    assert.equal(manager.workspace.layout, 'single');
    assert.equal(manager.workspace.activePane, 'left');
    assert.notEqual(manager.panes.left, manager.panes.right);
    assert.equal(manager.workspace.getActiveTab('left'), null);
    assert.equal(manager.workspace.getActiveTab('right'), null);
});

test('closing the final tab restores an independent empty pane state', () => {
    for (const pane of ['left', 'right']) {
        const manager = Object.create(SFTPFileManager.prototype);
        manager.initializeWorkspaceState();
        const populatedState = filePane(manager, `sftp-session:${pane}`, {
            path: `/srv/${pane}`,
            files: [{ name: 'stale.txt', is_dir: false }],
        });
        const tab = manager.workspace.openTab(
            pane,
            fileSource(`sftp-session:${pane}`),
            populatedState,
        );
        manager.syncPaneFromWorkspace(pane);
        Object.assign(manager, {
            displayMode: 'modal',
            updatePathInput() {},
            updatePaneBadge() {},
            renderPane() {},
            renderWorkspaceChrome() {},
            openSourceLauncher() {},
        });

        manager.closeSourceTab(pane, tab.id);

        assert.equal(manager.workspace.getActiveTab(pane), null);
        assert.notEqual(manager.panes[pane], populatedState);
        assert.equal(manager.panes[pane].source, null);
        assert.equal(manager.panes[pane].path, '/');
        assert.deepEqual(manager.panes[pane].files, []);
    }
});

test('pane state has one canonical source and no legacy identity fields', () => {
    const manager = Object.create(SFTPFileManager.prototype);

    const state = manager.createEmptyPaneState();

    assert.equal(state.source, null);
    assert.equal(Object.hasOwn(state, 'type'), false);
    assert.equal(Object.hasOwn(state, 'sessionId'), false);
    assert.equal(Object.hasOwn(state, 'connectionId'), false);
});

test('source descriptor normalization is the only snake case boundary', () => {
    const manager = Object.create(SFTPFileManager.prototype);

    const source = manager.normalizeSourceDescriptor({
        source_id: 'sftp-quick:quick-a',
        kind: 'sftp',
        label: 'deploy@stage.example',
        endpoint: 'stage.example:22',
        protocol: 'SFTP',
        capabilities: ['list', 'read'],
        ephemeral: true,
        security: { host_key_verified: true },
    });

    assert.deepEqual(source, {
        sourceId: 'sftp-quick:quick-a',
        kind: 'sftp',
        label: 'deploy@stage.example',
        endpoint: 'stage.example:22',
        protocol: 'SFTP',
        capabilities: ['list', 'read'],
        ephemeral: true,
        security: { hostKeyVerified: true },
        access: {},
    });

    const untrustedSecurity = manager.normalizeSourceDescriptor({
        source_id: 'sftp-quick:quick-b',
        kind: 'sftp',
        label: 'deploy@stage.example',
        endpoint: 'stage.example:22',
        protocol: 'SFTP',
        capabilities: ['list'],
        ephemeral: true,
        security: { host_key_verified: 'false' },
    });
    assert.deepEqual(untrustedSecurity.security, {});
    assert.equal(manager.sourceDescriptorForSession({ id: 'legacy-only' }), null);
});

test('SMB access evidence is normalized, labeled, and enforced only at the root', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.t = (_key, fallback) => fallback;
    const source = manager.normalizeSourceDescriptor({
        source_id: 'smb-quick:readonly',
        kind: 'smb',
        label: 'Docs on nas.example',
        endpoint: 'nas.example/Docs',
        protocol: 'SMB 3.1.1',
        capabilities: ['list', 'read', 'write', 'mkdir'],
        ephemeral: true,
        security: { encrypted: true },
        access: {
            list: 'granted',
            create_file: 'denied',
            create_directory: 'denied',
            delete_children: 'unknown',
            unsupported: 'granted',
        },
    });
    const root = { source, path: '/' };
    const nested = { source, path: '/department' };

    assert.deepEqual(source.access, {
        list: 'granted',
        createFile: 'denied',
        createDirectory: 'denied',
        deleteChildren: 'unknown',
    });
    manager.initializeWorkspaceState();
    const tab = manager.workspace.openTab('left', source);
    assert.deepEqual(tab.source.access, source.access);
    assert.notEqual(tab.source.access, source.access);
    assert.equal(manager.sourceAccessLabel(source), 'Read-only at share root');
    assert.equal(manager.sourceCan(root, 'write'), false);
    assert.equal(manager.sourceCan(root, 'mkdir'), false);
    assert.equal(manager.sourceCan(root, 'read'), true);
    assert.equal(manager.sourceCan(nested, 'write'), true);
});

test('SMB access label distinguishes confirmed write access from unknown evidence', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.t = (_key, fallback) => fallback;
    const base = { kind: 'smb' };

    assert.equal(manager.sourceAccessLabel({
        ...base,
        access: { createFile: 'granted', createDirectory: 'granted' },
    }), 'Write access at share root');
    assert.equal(manager.sourceAccessLabel({
        ...base,
        access: { createFile: 'unknown', createDirectory: 'unknown' },
    }), 'Write access at share root unknown');
    assert.equal(manager.sourceAccessLabel({ kind: 'sftp', access: {} }), '');
});

test('apply-to-all reuses the selected conflict action without opening another dialog', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.applyToAll = true;
    manager.conflictAction = 'replace';

    assert.equal(
        await manager.resolveUploadConflict({ filename: 'next.txt' }),
        'replace',
    );
});

test('conflict dialog source keeps an accessible modal and three explicit actions', () => {
    const fs = require('node:fs');
    const source = fs.readFileSync(
        require.resolve('../../static/js/sftp-file-manager.js'),
        'utf8',
    );

    assert.match(source, /role="dialog"/);
    assert.match(source, /aria-modal="true"/);
    assert.match(source, /data-conflict-action="replace"/);
    assert.match(source, /data-conflict-action="skip"/);
    assert.match(source, /data-conflict-action="cancel"/);
});

test('S2S events must match transfer id source ids and request id', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.transferQueue = [{
        id: 'transfer-a',
        type: 's2s',
        sourceIds: ['sftp-session:source', 'sftp-session:destination'],
        requestId: 'workspace:remote-transfer:1',
    }];
    manager.pendingS2SRequests = new Map([[
        'workspace:remote-transfer:2',
        {
            sourceId: 'sftp-session:source',
            destinationSourceId: 'sftp-session:destination',
        },
    ]]);

    const context = {
        source_id: 'sftp-session:source',
        destination_source_id: 'sftp-session:destination',
    };
    assert.equal(manager.matchesS2SResponse({
        ...context,
        transfer_id: 'transfer-a',
        request_id: 'workspace:remote-transfer:1',
    }), true);
    assert.equal(manager.matchesS2SResponse({
        ...context,
        transfer_id: 'transfer-a',
        request_id: 'workspace:remote-transfer:stale',
    }), false);
    assert.equal(manager.matchesS2SResponse({
        ...context,
        transfer_id: 'early-transfer',
        request_id: 'workspace:remote-transfer:2',
    }), true);
    assert.equal(manager.matchesS2SResponse({
        ...context,
        destination_source_id: 'sftp-session:other',
        transfer_id: 'early-transfer',
        request_id: 'workspace:remote-transfer:2',
    }), false);
});

test('actions depend on server supplied capabilities, not source kind', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const state = manager.createEmptyPaneState();
    state.source = {
        sourceId: 'sftp-session:a',
        kind: 'sftp',
        capabilities: ['list', 'read'],
    };

    assert.equal(manager.sourceCan(state, 'read'), true);
    assert.equal(manager.sourceCan(state, 'write'), false);
    assert.equal(manager.getPaneSourceId(state), 'sftp-session:a');
});

test('transfer queue toggle keeps icon and accessibility state in sync', () => {
    const queueClasses = classList();
    queueClasses.add('collapsed');
    const queue = { classList: queueClasses };
    const toggle = { textContent: 'expand_more' };
    const header = {
        attributes: { 'aria-expanded': 'false' },
        setAttribute(name, value) { this.attributes[name] = value; },
    };
    const originalGetElementById = global.document.getElementById;
    global.document.getElementById = id => ({
        fmQueue: queue,
        fmQueueToggle: toggle,
        fmQueueHeader: header,
    }[id] || null);
    const manager = Object.create(SFTPFileManager.prototype);

    manager.toggleQueue();
    assert.equal(queue.classList.contains('collapsed'), false);
    assert.equal(toggle.textContent, 'expand_less');
    assert.equal(header.attributes['aria-expanded'], 'true');

    manager.toggleQueue();
    assert.equal(queue.classList.contains('collapsed'), true);
    assert.equal(toggle.textContent, 'expand_more');
    assert.equal(header.attributes['aria-expanded'], 'false');
    global.document.getElementById = originalGetElementById;
});

test('an open transfer queue follows appended work but preserves manual history scrolling', () => {
    const previousDocument = global.document;
    const queue = { classList: classList() };
    const list = {
        innerHTML: '',
        scrollHeight: 500,
        scrollTop: 0,
        clientHeight: 100,
    };
    const badge = { textContent: '', style: {} };
    global.document = {
        getElementById(id) {
            return { fmQueue: queue, fmQueueList: list, fmQueueBadge: badge }[id] || null;
        },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        transferQueue: [{
            id: 'first', type: 'upload', filename: 'first.bin', status: 'active', progress: 10,
        }],
        t(_key, fallback) { return fallback; },
        escapeHtml(value) { return String(value); },
    });

    try {
        manager.renderTransferQueue();
        assert.equal(list.scrollTop, 500);

        list.scrollTop = 100;
        manager.transferQueue[0].progress = 20;
        manager.renderTransferQueue();
        assert.equal(list.scrollTop, 100);

        list.scrollHeight = 600;
        manager.transferQueue.push({
            id: 'second', type: 'download', filename: 'second.bin', status: 'pending', progress: 0,
        });
        manager.renderTransferQueue();
        assert.equal(list.scrollTop, 600);
    } finally {
        global.document = previousDocument;
    }
});

test('embedded pane state cannot overwrite standalone workspace tabs', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const standaloneState = filePane(
        manager,
        'sftp-session:workspace-session',
        { path: '/srv/workspace' },
    );
    const tab = manager.workspace.openTab(
        'left',
        fileSource('sftp-session:workspace-session', { label: 'Workspace' }),
        standaloneState,
    );
    manager.syncPaneFromWorkspace('left');

    manager.enterEmbeddedPaneState();
    manager.panes.left.source = fileSource('sftp-session:embedded-session');
    manager.panes.left.path = '/srv/embedded';
    manager.restoreStandalonePaneState();

    assert.equal(manager.panes.left, tab.paneState);
    assert.equal(manager.getPaneSourceId('left'), 'sftp-session:workspace-session');
    assert.equal(manager.panes.left.path, '/srv/workspace');
});

test('split layout preserves tabs and leaves an empty pane inline', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const tab = manager.workspace.openTab(
        'left', fileSource('sftp-session:left', { label: 'Left' }),
        manager.createEmptyPaneState(),
    );
    manager.syncPaneFromWorkspace('left');
    const launcherTargets = [];
    Object.assign(manager, {
        displayMode: 'modal',
        renderWorkspaceChrome() {},
        openSourceLauncher(pane) { launcherTargets.push(pane); },
    });

    manager.setWorkspaceLayout('split');

    assert.equal(manager.workspace.layout, 'split');
    assert.equal(manager.workspace.getActiveTab('left').id, tab.id);
    assert.deepEqual(launcherTargets, []);
});

test('split and single layout changes keep the populated side active', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.openTab(
        'left', fileSource('sftp-session:left', { label: 'Left' }),
        manager.createEmptyPaneState(),
    );
    manager.syncPaneFromWorkspace('left');
    const previousDocument = global.document;
    const launcher = {
        classList: classList(),
        setAttribute() {},
    };
    const actionLabel = { textContent: '' };
    const paneLabel = { hidden: true, textContent: '' };
    const search = { value: '', focus() {} };
    global.document = {
        activeElement: null,
        getElementById(id) {
            return {
                fmSourceLauncher: launcher,
                fmSourceLauncherAction: actionLabel,
                fmSourceLauncherPane: paneLabel,
                fmSourceSearch: search,
            }[id] || null;
        },
    };
    Object.assign(manager, {
        displayMode: 'modal',
        loadWorkspaceProfiles() {},
        renderSourceLauncher() {},
        renderWorkspaceChrome() {},
        t(_key, fallback) { return fallback; },
    });

    try {
        manager.setWorkspaceLayout('split');
        assert.equal(manager.sourceLauncherPane, undefined);
        assert.equal(manager.workspace.activePane, 'left');
        manager.closeSourceLauncher();
        manager.setWorkspaceLayout('single');
        assert.equal(manager.workspace.activePane, 'left');
    } finally {
        global.document = previousDocument;
    }
});

test('split layout moves the active second tab into the empty right side', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const first = manager.workspace.openTab(
        'left', fileSource('sftp-session:first', { label: 'First' }),
        filePane(manager, 'sftp-session:first', { path: '/srv/first' }),
    );
    const second = manager.workspace.openTab(
        'left', fileSource('sftp-session:second', { label: 'Second' }),
        filePane(manager, 'sftp-session:second', { path: '/srv/second' }),
    );
    manager.syncPaneFromWorkspace('left');
    const launcherTargets = [];
    Object.assign(manager, {
        displayMode: 'modal',
        renderWorkspaceChrome() {},
        openSourceLauncher(pane) { launcherTargets.push(pane); },
        updatePathInput() {},
        updatePaneBadge() {},
        renderPane() {},
        setActivePane(pane) {
            this.activePane = pane;
            this.workspace.setActivePane(pane);
        },
    });

    manager.setWorkspaceLayout('split');

    assert.deepEqual(manager.workspace.getTabs('left'), [first]);
    assert.deepEqual(manager.workspace.getTabs('right'), [second]);
    assert.equal(manager.panes.left.path, '/srv/first');
    assert.equal(manager.panes.right.path, '/srv/second');
    assert.deepEqual(launcherTargets, []);
});

test('source catalog preserves SFTP sources without an SMB preview', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        availableSessions: [{
            id: 'session-a', username: 'ops', host: 'edge.example', port: 22, connected: true,
            file_source: serverFileSource('sftp-session:session-a', {
                label: 'ops@edge.example', endpoint: 'edge.example:22',
            }),
        }],
        quickConnections: [{
            connectionId: 'quick-a', username: 'deploy', host: 'stage.example', port: 2222,
            file_source: serverFileSource('sftp-quick:quick-a', {
                label: 'deploy@stage.example', endpoint: 'stage.example:2222',
            }),
        }],
        qcProfiles: [{
            id: 7, name: 'Database', username: 'dba', host: 'db.example', port: 22,
            password: 'not-a-launcher-field',
        }],
        t(_key, fallback) { return fallback; },
    });

    const groups = manager.buildSourceCatalog();
    assert.deepEqual(groups.map(group => group.id), ['active', 'saved', 'quick']);

    assert.deepEqual(groups[0].items[0], {
        ...fileSource('sftp-session:session-a', {
            label: 'ops@edge.example', endpoint: 'edge.example:22',
        }),
        key: 'sftp-session:session-a', status: 'Connected',
        securityLabel: 'SSH host key trusted',
    });
    assert.equal(groups[1].items[0].profileId, 7);
    assert.equal(groups[1].items[0].password, undefined);
    assert.equal(groups[2].items[0].sourceId, 'sftp-quick:quick-a');
    assert.equal(groups.flatMap(group => group.items).some(source => source.kind === 'smb'), false);
});

test('source launcher shows a useful empty state when no connection is open', () => {
    const previousDocument = global.document;
    const container = { innerHTML: '' };
    global.document = {
        getElementById(id) { return id === 'fmSourceGroups' ? container : null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        availableSessions: [], quickConnections: [], qcProfiles: [],
        t(_key, fallback) { return fallback; },
        escapeHtml(value) { return String(value); },
    });

    try {
        manager.renderSourceLauncher('');
    } finally {
        global.document = previousDocument;
    }

    assert.match(container.innerHTML, /fm-source-no-sources/);
    assert.match(container.innerHTML, /No sources available/);
    assert.match(container.innerHTML, /create a new SFTP connection below/);
    assert.doesNotMatch(container.innerHTML, /smb:coming-soon|profile:7|browser-local/);
});

test('opening an SFTP source creates a real tab in only the targeted pane', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const sourceChanges = [];
    Object.assign(manager, {
        displayMode: 'modal',
        async onSourceChange(pane, key) { sourceChanges.push([pane, key]); },
        renderWorkspaceChrome() {},
        closeSourceLauncher() {},
        setActivePane(pane) { this.activePane = pane; },
    });

    const tab = await manager.openWorkspaceSource(
        'right',
        fileSource('sftp-session:session-a', {
            label: 'Production', endpoint: 'edge.example:22',
        }),
    );

    assert.equal(manager.workspace.getActiveTab('right'), tab);
    assert.equal(manager.workspace.getActiveTab('left'), null);
    assert.equal(manager.panes.right, tab.paneState);
    assert.deepEqual(sourceChanges, [['right', 'sftp-session:session-a']]);
});

test('closing the final tab for a quick connection disconnects and removes that source', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const source = fileSource('sftp-quick:quick-a', {
        label: 'deploy@stage.example',
    });
    const leftTab = manager.workspace.openTab('left', source, manager.createEmptyPaneState());
    const rightTab = manager.workspace.openTab('right', source, manager.createEmptyPaneState());
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    Object.assign(manager, {
        displayMode: 'modal',
        quickConnections: [{ connectionId: 'quick-a', username: 'deploy', host: 'stage.example' }],
        socket: { emit(event, payload) { emitted.push([event, payload]); } },
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, renderWorkspaceChrome() {},
        openSourceLauncher() {}, updateSessionLists() {},
    });

    manager.closeSourceTab('left', leftTab.id);
    assert.deepEqual(emitted, []);
    assert.equal(manager.quickConnections.length, 1);

    manager.closeSourceTab('right', rightTab.id);
    assert.deepEqual(emitted, [['quick_disconnect', { connection_id: 'quick-a' }]]);
    assert.deepEqual(manager.quickConnections, []);
});

test('closing the final quick source defers disconnect until its transfer is terminal', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const source = fileSource('sftp-quick:quick-a', {
        label: 'deploy@stage.example',
    });
    const tab = manager.workspace.openTab('left', source, manager.createEmptyPaneState());
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal',
        quickConnections: [{ connectionId: 'quick-a', username: 'deploy', host: 'stage.example' }],
        transferQueue: [{
            id: 'upload-a', type: 'upload', status: 'pending',
            sourceId: 'sftp-quick:quick-a',
        }],
        activeTransfers: new Map(),
        socket: { emit(event, payload) { emitted.push([event, payload]); } },
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, renderWorkspaceChrome() {},
        openSourceLauncher() {}, updateSessionLists() {}, renderTransferQueue() {},
        recordUploadTerminal() {},
    });

    manager.closeSourceTab('left', tab.id);
    assert.deepEqual(emitted, []);
    assert.equal(manager.quickConnections.length, 1);

    manager.finalizeTransferById('upload-a', 'complete');
    assert.deepEqual(emitted, [['quick_disconnect', { connection_id: 'quick-a' }]]);
    assert.deepEqual(manager.quickConnections, []);
});

test('server copy retains a quick connection while its acknowledgement is pending', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    let acknowledgeTransfer;
    const source = fileSource('sftp-quick:quick-a', {
        label: 'deploy@stage.example',
    });
    const tab = manager.workspace.openTab('left', source, manager.createEmptyPaneState());
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal',
        quickConnections: [{ connectionId: 'quick-a', username: 'deploy', host: 'stage.example' }],
        transferQueue: [],
        activeTransfers: new Map(),
        socket: { emit(event, payload, acknowledgement) {
            if (event === 'transfer_server_to_server') {
                acknowledgeTransfer = acknowledgement;
                return;
            }
            emitted.push([event, payload]);
        } },
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, renderWorkspaceChrome() {},
        openSourceLauncher() {}, updateSessionLists() {}, renderTransferQueue() {},
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    const transfer = manager.transferSSHtoSSH(
        '/source/file.bin', filePane(manager, 'sftp-quick:quick-a'),
        '/target/file.bin', filePane(manager, 'sftp-session:target-session'),
        { name: 'file.bin', is_dir: false, size: 10 },
    );
    manager.closeSourceTab('left', tab.id);
    assert.deepEqual(emitted, []);

    acknowledgeTransfer({ success: false });
    await transfer;
    assert.deepEqual(emitted, [['quick_disconnect', { connection_id: 'quick-a' }]]);
});

test('closing a regular SSH source tab never disconnects the terminal session', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const tab = manager.workspace.openTab(
        'left', fileSource('sftp-session:session-a', { label: 'Production' }),
        manager.createEmptyPaneState(),
    );
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal', quickConnections: [],
        socket: { emit(event, payload) { emitted.push([event, payload]); } },
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, renderWorkspaceChrome() {},
        openSourceLauncher() {}, updateSessionLists() {},
    });

    manager.closeSourceTab('left', tab.id);

    assert.deepEqual(emitted, []);
});

test('disabled SMB sources never invoke a connection path', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.onSourceChange = () => assert.fail('SMB attempted to connect');

    const result = await manager.openWorkspaceSource('left', {
        key: 'smb:coming-soon', type: 'smb', label: 'SMB share', disabled: true,
    });

    assert.equal(result, null);
    assert.equal(manager.workspace.getActiveTab('left'), null);
});

test('SMB launcher obeys the server feature flag before opening the dialog', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    let opened = 0;
    Object.assign(manager, {
        smbEnabled: false,
        sourceLauncherPane: 'right',
        smbSourceDialog: { open() { opened += 1; return true; } },
        closeSourceLauncher() {},
    });

    assert.equal(manager.openSMBSourceDialog(), false);
    assert.equal(opened, 0);

    manager.smbEnabled = true;
    assert.equal(manager.openSMBSourceDialog(), true);
    assert.equal(opened, 1);
});

test('SMB success opens only the server supplied descriptor in the target pane', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const opened = [];
    Object.assign(manager, {
        smbSources: [],
        normalizeSourceDescriptor: SFTPFileManager.prototype.normalizeSourceDescriptor,
        async openWorkspaceSource(pane, source) { opened.push([pane, source]); },
        t(_key, fallback) { return fallback; },
        sourceSecurityLabel: SFTPFileManager.prototype.sourceSecurityLabel,
        showNotification() {},
    });
    const descriptor = serverFileSource('smb-quick:server-issued', {
        kind: 'smb', label: 'Docs on nas.example', endpoint: 'nas.example/Docs',
        protocol: 'SMB 3.1.1', security: { encrypted: true },
    });

    assert.equal(await manager.handleSMBSourceConnected({
        pane: 'right', descriptor,
    }), true);
    assert.equal(manager.smbSources.length, 1);
    assert.equal(opened[0][0], 'right');
    assert.equal(opened[0][1].sourceId, 'smb-quick:server-issued');
    assert.equal(opened[0][1].endpoint, 'nas.example/Docs');
});

test('closing the final SMB tab uses the generic owned-source disconnect', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const source = fileSource('smb-quick:owned', {
        kind: 'smb', ephemeral: true, protocol: 'SMB 3.1.1',
    });
    const tab = manager.workspace.openTab('left', source, manager.createEmptyPaneState());
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal', quickConnections: [], smbSources: [source],
        socket: { emit(event, payload) { emitted.push([event, payload]); } },
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, renderWorkspaceChrome() {},
        openSourceLauncher() {}, updateSessionLists() {},
    });

    manager.closeSourceTab('left', tab.id);

    assert.deepEqual(emitted, [[
        'file_source_disconnect', { source_id: 'smb-quick:owned' },
    ]]);
    assert.deepEqual(manager.smbSources, []);
});

test('a correlated listing updates an inactive source tab without replacing the visible tab', () => {
    const listeners = {};
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const inactiveState = filePane(manager, 'sftp-session:session-a', {
        loading: true,
        pendingDirectoryRequestId: 'left:directory:1', pendingDirectoryPath: '/srv/a',
    });
    const activeState = filePane(manager, 'sftp-session:session-b', {
        path: '/srv/b',
        files: [{ name: 'visible.txt' }],
    });
    manager.workspace.openTab(
        'left', fileSource('sftp-session:session-a', { label: 'A' }),
        inactiveState,
    );
    const activeTab = manager.workspace.openTab(
        'left', fileSource('sftp-session:session-b', { label: 'B' }),
        activeState,
    );
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        isOpen: true,
        displayMode: 'modal',
        updatePathInput() { assert.fail('inactive tab changed the visible path'); },
        renderPane() { assert.fail('inactive tab re-rendered the visible pane'); },
    });
    manager.setupSocketListeners();

    listeners.directory_listing({
        source_id: 'sftp-session:session-a', request_id: 'left:directory:1', path: '/srv/a',
        files: [{ name: 'late.txt' }],
    });

    assert.equal(manager.workspace.getActiveTab('left'), activeTab);
    assert.equal(manager.panes.left, activeState);
    assert.equal(manager.panes.left.files[0].name, 'visible.txt');
    assert.equal(inactiveState.loading, false);
    assert.equal(inactiveState.files[0].name, 'late.txt');
});

test('single-pane workspace can activate either side even on a narrow viewport', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const elements = { fmLeftPane: { classList: classList() }, fmRightPane: { classList: classList() } };
    const originalGetElementById = global.document.getElementById;
    global.document.getElementById = id => elements[id] || null;
    Object.assign(manager, {
        displayMode: 'modal',
        isMobile: () => true,
        updateMobilePaneTabs() {},
        renderWorkspaceChrome() {},
    });

    manager.setActivePane('right');

    assert.equal(manager.activePane, 'right');
    assert.equal(manager.workspace.activePane, 'right');
    assert.equal(elements.fmRightPane.classList.contains('active'), true);
    global.document.getElementById = originalGetElementById;
});

test('disconnect removes every matching workspace tab instead of leaving a green stale source', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.openTab(
        'left', fileSource('sftp-session:gone', { label: 'Gone' }),
        filePane(manager, 'sftp-session:gone'),
    );
    const survivor = manager.workspace.openTab(
        'left', fileSource('sftp-session:alive', { label: 'Alive' }),
        filePane(manager, 'sftp-session:alive'),
    );
    manager.workspace.openTab(
        'right', fileSource('sftp-session:gone', { label: 'Gone' }),
        filePane(manager, 'sftp-session:gone'),
    );
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    Object.assign(manager, {
        displayMode: 'modal',
        updateSessionLists() {}, renderWorkspaceChrome() {},
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {},
    });

    manager.handleSessionDisconnected('gone');

    assert.deepEqual(manager.workspace.getTabs('left').map(tab => tab.source.sourceId), ['sftp-session:alive']);
    assert.equal(manager.workspace.getActiveTab('left'), survivor);
    assert.equal(manager.workspace.getTabs('right').length, 0);
});

test('disconnect removes matching workspace tabs while the file manager is closed', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.openTab(
        'left', fileSource('sftp-session:gone', { label: 'Gone' }),
        filePane(manager, 'sftp-session:gone'),
    );
    const survivor = manager.workspace.openTab(
        'left', fileSource('sftp-session:alive', { label: 'Alive' }),
        filePane(manager, 'sftp-session:alive'),
    );
    manager.workspace.openTab(
        'right', fileSource('sftp-session:gone', { label: 'Gone' }),
        filePane(manager, 'sftp-session:gone'),
    );
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    Object.assign(manager, {
        displayMode: 'closed',
        isOpen: false,
        updateSessionLists() { throw new Error('closed workspace must not render'); },
        renderWorkspaceChrome() { throw new Error('closed workspace must not render'); },
    });

    manager.handleSessionDisconnected('gone');

    assert.deepEqual(manager.workspace.getTabs('left').map(tab => tab.source.sourceId), ['sftp-session:alive']);
    assert.equal(manager.workspace.getActiveTab('left'), survivor);
    assert.equal(manager.workspace.getTabs('right').length, 0);
});

test('embedded mode mounts the existing manager body as one remote pane', async () => {
    const modalContent = {
        children: [],
        appendChild(node) { this.children.push(node); node.parentElement = this; },
        insertBefore(node) { this.children.push(node); node.parentElement = this; },
    };
    const mount = {
        children: [],
        replaceChildren(node) { this.children = [node]; node.parentElement = this; },
    };
    const body = { classList: classList(), parentElement: modalContent };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        modalBody: body,
        modalContent,
        actionSheet: {},
        displayMode: 'closed',
        isOpen: false,
        panes: { left: { source: null }, right: { source: null } },
        updateSessionLists() {},
        applyTranslations() {},
        setActivePane(pane) { this.activePane = pane; },
        availableSessions: [],
        onSourceChange(pane, source) { this.sourceChange = { pane, source }; },
    });

    await manager.openEmbedded(mount, 'session-a', {
        id: 'session-a', username: 'ops', host: 'edge.example', port: 22, connected: true,
    });

    assert.equal(manager.displayMode, 'embedded');
    assert.equal(manager.isOpen, true);
    assert.equal(manager.activePane, 'left');
    assert.equal(body.classList.contains('fm-embedded-mode'), true);
    assert.deepEqual(mount.children, [body]);
    assert.deepEqual(manager.sourceChange, { pane: 'left', source: 'sftp-session:session-a' });
});

test('embedded Files recomputes shared toolbar actions after leaving the full manager', () => {
    const previousDocument = global.document;
    const buttons = Object.fromEntries([
        'fmNewFolder', 'fmEmbeddedUpload', 'fmDownload',
        'fmPreview', 'fmRename', 'fmDelete',
    ].map(id => [id, { disabled: true }]));
    global.document = {
        getElementById(id) { return buttons[id] || null; },
        querySelectorAll() { return []; },
        querySelector() { return null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.enterEmbeddedPaneState();
    manager.panes.left = filePane(manager, 'sftp-session:workspace', {
        files: [{ name: 'report.txt', is_dir: false }],
        selected: new Set([0]),
    });
    Object.assign(manager, {
        displayMode: 'embedded',
        activePane: 'left',
        t(_key, fallback) { return fallback; },
    });

    try {
        manager.updateWorkspaceActions();
    } finally {
        global.document = previousDocument;
    }

    assert.deepEqual(
        Object.fromEntries(Object.entries(buttons).map(([id, button]) => [id, button.disabled])),
        {
            fmNewFolder: false,
            fmEmbeddedUpload: false,
            fmDownload: false,
            fmPreview: false,
            fmRename: false,
            fmDelete: false,
        },
    );
});

test('closing embedded mode restores the full manager body for modal use', () => {
    let inserted;
    const modalContent = {
        insertBefore(node, before) { inserted = { node, before }; node.parentElement = this; },
    };
    const body = { classList: classList(), parentElement: {} };
    body.classList.add('fm-embedded-mode');
    const actionSheet = {};
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        modalBody: body,
        modalContent,
        actionSheet,
        displayMode: 'embedded',
        isOpen: true,
        closeContextMenu() {},
        resetPane(pane) { this.reset = pane; },
    });

    manager.closeEmbedded();

    assert.deepEqual(inserted, { node: body, before: actionSheet });
    assert.equal(body.classList.contains('fm-embedded-mode'), false);
    assert.equal(manager.displayMode, 'closed');
    assert.equal(manager.isOpen, false);
    assert.equal(manager.reset, 'left');
});

test('embedded context menu keeps single-pane actions and omits transfer', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.displayMode = 'embedded';
    manager.isMobile = () => false;
    manager.t = (_key, fallback) => fallback;

    const actions = manager.getContextMenuItems(
        { name: 'config.yml', is_dir: false },
        { source: fileSource('sftp-session:session-a') },
    ).filter(item => item.action).map(item => item.action);

    assert.deepEqual(actions, [
        'preview', 'download', 'rename', 'newfolder', 'refresh', 'delete',
    ]);
});

test('F5 refreshes the embedded pane without starting a dual-pane transfer', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    let refreshed;
    Object.assign(manager, {
        isOpen: true,
        displayMode: 'embedded',
        activePane: 'left',
        refreshPane(pane) { refreshed = pane; },
        executeTransfer() { assert.fail('dual-pane transfer started'); },
    });
    let prevented = false;

    manager.handleKeyboardShortcut({
        key: 'F5', ctrlKey: false,
        target: { matches: () => false },
        preventDefault() { prevented = true; },
    });

    assert.equal(refreshed, 'left');
    assert.equal(prevented, true);
});

test('Tab never activates the hidden second pane in embedded mode', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        isOpen: true,
        displayMode: 'embedded',
        activePane: 'left',
        setActivePane() { assert.fail('hidden pane activated'); },
    });

    manager.handleKeyboardShortcut({
        key: 'Tab', ctrlKey: false,
        target: { matches: () => false },
        preventDefault() { assert.fail('normal tab navigation was blocked'); },
    });
});

test('resetPane clears the home directory and pending requests from the previous session', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.panes = {
        left: filePane(manager, 'sftp-session:session-a', {
            homePath: '/home/user-a',
            pendingDirectoryRequestId: 'left:4',
            pendingDirectoryPath: '/srv/a',
            pendingHomeRequestId: 'left:3',
        }),
    };
    Object.assign(manager, {
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {}, capitalize(value) { return value; },
    });

    manager.resetPane('left');

    assert.equal(manager.panes.left.homePath, null);
    assert.equal(manager.panes.left.pendingDirectoryRequestId, null);
    assert.equal(manager.panes.left.pendingDirectoryPath, null);
    assert.equal(manager.panes.left.pendingHomeRequestId, null);
});

test('stale directory and home responses cannot overwrite a newer request', () => {
    const listeners = {};
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        isOpen: true,
        panes: {
            left: filePane(manager, 'sftp-session:session-a', {
                path: '/new',
                files: [{ name: 'new.txt' }],
                pendingDirectoryRequestId: 'left:2',
                pendingDirectoryPath: '/new',
                pendingHomeRequestId: 'left:home:2',
            }),
            right: manager.createEmptyPaneState(),
        },
        updatePathInput() {}, renderPane() {}, navigatePaneTo() { assert.fail('stale home path used'); },
    });
    manager.setupSocketListeners();

    listeners.directory_listing({
        source_id: 'sftp-session:session-a', request_id: 'left:1', path: '/old', files: [{ name: 'old.txt' }],
    });
    listeners.home_directory({
        source_id: 'sftp-session:session-a', request_id: 'left:home:1', path: '/home/old-user',
    });

    assert.equal(manager.panes.left.path, '/new');
    assert.equal(manager.panes.left.files[0].name, 'new.txt');
    assert.equal(manager.panes.left.homePath, null);
});

test('a valid late home response cannot replace a newer manual navigation', () => {
    const listeners = {};
    const manager = Object.create(SFTPFileManager.prototype);
    let navigated = null;
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        isOpen: true,
        panes: {
            left: filePane(manager, 'sftp-session:session-a', {
                path: '/',
                pendingHomeRequestId: 'left:home:1',
                pendingDirectoryRequestId: 'left:directory:2',
                pendingDirectoryPath: '/srv/manual',
                autoHomeEligible: false,
            }),
            right: manager.createEmptyPaneState(),
        },
        navigatePaneTo(_pane, path) { navigated = path; },
    });
    manager.setupSocketListeners();

    listeners.home_directory({
        source_id: 'sftp-session:session-a', request_id: 'left:home:1', path: '/home/operator',
    });

    assert.equal(manager.panes.left.homePath, '/home/operator');
    assert.equal(navigated, null);
    assert.equal(manager.panes.left.pendingDirectoryPath, '/srv/manual');
});

test('file manager claims only the exact correlated listing error', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        isOpen: true,
        panes: {
            left: filePane(manager, 'sftp-session:session-a', {
                pendingDirectoryRequestId: 'left:directory:9', pendingDirectoryPath: '/srv/current',
            }),
            right: manager.createEmptyPaneState(),
        },
    });

    assert.equal(manager.handlesSocketError({ error: 'generic' }), false);
    assert.equal(manager.handlesSocketError({
        operation: 'list_directory', source_id: 'sftp-session:session-a',
        request_id: 'left:directory:8', path: '/srv/old',
    }), false);
    assert.equal(manager.handlesSocketError({
        operation: 'list_directory', source_id: 'sftp-session:session-a',
        request_id: 'left:directory:9', path: '/srv/current',
    }), true);
});

test('only the correlated list-directory error changes a loading SFTP pane', () => {
    const listeners = {};
    let renders = 0;
    let notifications = 0;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        isOpen: true,
        panes: {
            left: filePane(manager, 'sftp-session:session-a', {
                loading: true,
                pendingDirectoryRequestId: 'left:7', pendingDirectoryPath: '/srv/current',
            }),
            right: manager.createEmptyPaneState(),
        },
        renderPane() { renders += 1; },
        showNotification() { notifications += 1; },
    });
    manager.setupSocketListeners();

    listeners.error({ error: 'Unrelated profile error' });
    listeners.error({
        error: 'Stale listing failed', operation: 'list_directory', source_id: 'sftp-session:session-a',
        request_id: 'left:6', path: '/srv/old',
    });
    assert.equal(manager.panes.left.loading, true);
    assert.equal(renders, 0);
    assert.equal(notifications, 0);

    listeners.error({
        error: 'Listing failed', operation: 'list_directory', source_id: 'sftp-session:session-a',
        request_id: 'left:7', path: '/srv/current',
    });
    assert.equal(manager.panes.left.loading, false);
    assert.equal(manager.panes.left.error, 'Listing failed');
    assert.equal(renders, 1);
    assert.equal(notifications, 1);
});

test('embedded pane keeps the existing navigation and preview code paths', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const calls = [];
    global.window.FilePreview = {
        open(...args) { calls.push(['preview', ...args]); },
    };
    Object.assign(manager, {
        displayMode: 'embedded',
        panes: {
            left: {
                source: fileSource('sftp-session:session-a'), path: '/srv',
                files: [{ name: 'releases', is_dir: true }, { name: 'README.md', is_dir: false }],
            },
        },
        navigateIntoDir(pane, name) { calls.push(['directory', pane, name]); },
        joinPath(base, name) { return `${base}/${name}`; },
    });

    manager.handleItemDblClick('left', 0);
    manager.handleItemDblClick('left', 1);

    assert.deepEqual(calls, [
        ['directory', 'left', 'releases'],
        ['preview', 'sftp-session:session-a', '/srv/README.md', 'README.md'],
    ]);
    delete global.window.FilePreview;
});

test('embedded pane keeps ctrl and shift selection plus folder download', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const downloads = [];
    Object.assign(manager, {
        displayMode: 'embedded',
        activePane: 'left',
        panes: {
            left: {
                source: fileSource('sftp-session:session-a'), path: '/srv',
                files: [
                    { name: 'one.txt', is_dir: false },
                    { name: 'two.txt', is_dir: false },
                    { name: 'archive', is_dir: true },
                ],
                selected: new Set(), lastSelected: -1,
            },
        },
        setActivePane(pane) { this.activePane = pane; },
        updateSelectionVisual() {},
        showNotification() {},
        t(_key, fallback) { return fallback; },
        joinPath(base, name) { return `${base}/${name}`; },
        downloadFileToBrowser(_session, path) { downloads.push(['file', path]); },
        downloadFolderToBrowser(_session, path) { downloads.push(['folder', path]); },
    });
    const event = overrides => ({ stopPropagation() {}, ctrlKey: false, metaKey: false, shiftKey: false, ...overrides });

    manager.handleItemClick(event({}), 'left', 0);
    manager.handleItemClick(event({ ctrlKey: true }), 'left', 2);
    manager.handleItemClick(event({ shiftKey: true }), 'left', 1);
    manager.downloadSelected();

    assert.deepEqual([...manager.panes.left.selected], [0, 2, 1]);
    assert.deepEqual(downloads, [
        ['file', '/srv/one.txt'],
        ['folder', '/srv/archive'],
        ['file', '/srv/two.txt'],
    ]);
});

test('clicking file checkboxes toggles multiple items without modifier keys', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: {
                files: [{ name: 'one.txt' }, { name: 'two.txt' }],
                selected: new Set(), lastSelected: -1,
            },
        },
        setActivePane(pane) { this.activePane = pane; },
        updateSelectionVisual() {},
    });
    const checkboxEvent = () => ({
        stopPropagation() {}, ctrlKey: false, metaKey: false, shiftKey: false,
        target: { closest(selector) { return selector === '.fm-file-checkbox' ? this : null; } },
    });

    manager.handleItemClick(checkboxEvent(), 'left', 0);
    manager.handleItemClick(checkboxEvent(), 'left', 1);
    assert.deepEqual([...manager.panes.left.selected], [0, 1]);

    manager.handleItemClick(checkboxEvent(), 'left', 0);
    assert.deepEqual([...manager.panes.left.selected], [1]);
});

test('select all applies the captured choice to the requested pane', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: { files: [{ name: 'left.txt' }], selected: new Set([0]) },
            right: { files: [{ name: 'one.txt' }, { name: 'two.txt' }], selected: new Set() },
        },
        setActivePane(pane) {
            this.activePane = pane;
            // Mirrors renderWorkspaceChrome resetting the DOM checkbox from current state.
        },
        updateSelectionVisual() {},
    });

    manager.setPaneSelection('right', true);
    assert.deepEqual([...manager.panes.right.selected], [0, 1]);
    assert.deepEqual([...manager.panes.left.selected], [0]);

    manager.setPaneSelection('right', false);
    assert.deepEqual([...manager.panes.right.selected], []);
});

test('mobile open action previews a selected file through the normal open path', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const opened = [];
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: {
                files: [{ name: 'readme.txt', is_dir: false }],
                selected: new Set([0]),
            },
        },
        hideActionSheet() {},
        handleItemDblClick(pane, index) { opened.push([pane, index]); },
    });

    manager.handleActionSheetAction('open');

    assert.deepEqual(opened, [['left', 0]]);
});

test('context menu offers transfer only when another connected file area exists', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const file = { name: 'release.tar.gz', is_dir: false };
    const leftState = filePane(manager, 'sftp-session:left', { files: [file] });
    const rightState = filePane(manager, 'sftp-session:right');
    manager.workspace.openTab(
        'left', fileSource('sftp-session:left', { label: 'Left' }), leftState,
    );
    Object.assign(manager, {
        displayMode: 'modal',
        isMobile() { return false; },
        t(_key, fallback) { return fallback; },
    });

    let actions = manager.getContextMenuItems(file, leftState, 'left').map(item => item.action);
    assert.equal(actions.includes('transfer'), false);

    manager.workspace.openTab(
        'right', fileSource('sftp-session:right', { label: 'Right' }), rightState,
    );
    manager.workspace.setLayout('split');
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    actions = manager.getContextMenuItems(file, leftState, 'left').map(item => item.action);
    assert.equal(actions.includes('transfer'), true);

    rightState.source = fileSource('sftp-session:left');
    rightState.path = '/archive';
    const moveAction = manager.getContextMenuItems(file, leftState, 'left')
        .find(item => item.action === 'transfer');
    assert.equal(moveAction.text, 'Move to other pane');
    assert.equal(moveAction.icon, 'drive_file_move');
});

test('workspace operation distinguishes same-source move from cross-source copy', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.setLayout('split');
    const leftState = filePane(manager, 'sftp-session:shared', {
        loading: false, error: null, path: '/source', selected: new Set([0]),
    });
    const rightState = filePane(manager, 'sftp-session:shared', {
        loading: false, error: null, path: '/target',
    });
    manager.workspace.openTab('left', fileSource('sftp-session:shared'), leftState);
    manager.workspace.openTab('right', fileSource('sftp-session:shared'), rightState);
    manager.panes = { left: leftState, right: rightState };

    assert.equal(manager.workspaceOperationBetweenPanes('left', 'right'), 'move');
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), true);

    rightState.path = '/source';
    assert.equal(manager.workspaceOperationBetweenPanes('left', 'right'), 'unavailable');
    rightState.path = '/target';

    rightState.source = fileSource('sftp-session:target');
    rightState.loading = true;
    assert.equal(manager.workspaceOperationBetweenPanes('left', 'right'), 'unavailable');
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), false);

    rightState.loading = false;
    assert.equal(manager.workspaceOperationBetweenPanes('left', 'right'), 'copy');
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), true);

    rightState.autoHomeEligible = true;
    rightState.pendingHomeRequestId = 'right:home:1';
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), false);

    rightState.autoHomeEligible = false;
    rightState.pendingHomeRequestId = null;
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), true);
});

test('same-source move hides the directional action and gives a drag hint', () => {
    const previousDocument = global.document;
    const hint = { textContent: '' };
    const icon = { textContent: '' };
    const text = { textContent: '' };
    const button = {
        dataset: {},
        title: '',
        classList: classList(),
        querySelector(selector) {
            return selector === '.material-icons' ? icon : text;
        },
        setAttribute(name, value) { this[name] = value; },
    };
    global.document = {
        getElementById(id) {
            return id === 'fmTransferHint' ? hint : null;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.setLayout('split');
    manager.panes.left = filePane(manager, 'smb-quick:shared', {
        path: '/source',
        files: [{ name: 'report.txt', is_dir: false }],
        selected: new Set([0]),
    });
    manager.panes.right = filePane(manager, 'smb-quick:shared', {
        path: '/target',
    });
    manager.workspace.openTab(
        'left', manager.panes.left.source, manager.panes.left,
    );
    manager.workspace.openTab(
        'right', manager.panes.right.source, manager.panes.right,
    );
    Object.assign(manager, {
        displayMode: 'modal',
        t(_key, fallback) { return fallback; },
    });

    try {
        manager.updateWorkspaceOperationButton(button, 'move', 'LeftToRight');
        manager.updateWorkspaceActions();

        assert.equal(icon.textContent, 'drive_file_move');
        assert.equal(text.textContent, 'Move');
        assert.equal(button.title, 'Move left to right');
        assert.equal(button.hidden, true);
        assert.equal(hint.textContent, 'Drag items onto a folder to move them');

        manager.panes.left.selected.clear();
        manager.updateWorkspaceActions();
        assert.equal(hint.textContent, 'Drag items onto a folder to move them');
    } finally {
        global.document = previousDocument;
    }
});

test('source launcher identifies the existing connection that enables Move', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.sourceLauncherPane = 'right';
    manager.panes.left = filePane(manager, 'smb-quick:shared');
    manager.t = (_key, fallback) => fallback;

    assert.equal(manager.sourceLauncherStatus({
        sourceId: 'smb-quick:shared', status: 'Connected',
    }), 'Same connection · enables Move');
    assert.equal(manager.sourceLauncherStatus({
        sourceId: 'smb-quick:other', status: 'Connected',
    }), 'Connected');
});

test('same-pane folder drop moves the dragged selection and refreshes once', async () => {
    const requests = [];
    const refreshes = [];
    const manager = Object.create(SFTPFileManager.prototype);
    const sourceState = filePane(manager, 'sftp-session:shared', {
        path: '/source',
        files: [
            { name: 'report.txt', is_dir: false },
            { name: 'archive', is_dir: true },
        ],
    });
    Object.assign(manager, {
        requestSequence: 0,
        panes: { left: sourceState },
        socket: { emit(event, payload, acknowledgement) {
            requests.push({ event, payload });
            acknowledgement({
                success: true,
                source_id: payload.source_id,
                old_path: payload.old_path,
                new_path: payload.new_path,
                request_id: payload.request_id,
            });
        } },
        refreshPane(pane) { refreshes.push(pane); },
        showNotification() {},
        resolveUploadConflict() { return Promise.resolve('cancel'); },
        t(_key, fallback) { return fallback; },
    });

    const result = await manager.moveSelectedToDirectory(
        'left',
        1,
        [sourceState.files[0]],
    );

    assert.equal(result, 'complete');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].event, 'rename_file');
    assert.equal(requests[0].payload.old_path, '/source/report.txt');
    assert.equal(requests[0].payload.new_path, '/source/archive/report.txt');
    assert.deepEqual(refreshes, ['left']);
});

test('directory drop accepts only writable same-pane sibling folders', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const file = { name: 'report.txt', is_dir: false };
    const directory = { name: 'archive', is_dir: true };
    Object.assign(manager, {
        dragSource: 'left',
        draggedItems: [file],
        panes: {
            left: filePane(manager, 'sftp-session:shared', {
                path: '/source', files: [file, directory],
            }),
        },
    });

    assert.equal(manager.canDropDraggedItemsOnDirectory('left', 1), true);
    assert.equal(manager.canDropDraggedItemsOnDirectory('left', 0), false);
    assert.equal(manager.canDropDraggedItemsOnDirectory('right', 1), false);

    manager.draggedItems = [directory];
    assert.equal(manager.canDropDraggedItemsOnDirectory('left', 1), false);
});

test('same-source move is sequential, never replaces, and refreshes both panes once', async () => {
    const requests = [];
    const refreshes = [];
    const conflictOptions = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        requestSequence: 0,
        socket: { emit(event, payload, acknowledgement) {
            requests.push({ event, payload });
            acknowledgement({
                success: payload.old_path !== '/source/two.txt',
                code: payload.old_path === '/source/two.txt' ? 'CONFLICT' : undefined,
                error: payload.old_path === '/source/two.txt'
                    ? 'A file or folder already exists at the destination.'
                    : undefined,
                source_id: payload.source_id,
                old_path: payload.old_path,
                new_path: payload.new_path,
                request_id: payload.request_id,
            });
        } },
        panes: {
            left: filePane(manager, 'smb-quick:shared', { path: '/source' }),
            right: filePane(manager, 'smb-quick:shared', { path: '/target' }),
        },
        resolveUploadConflict(_details, options) {
            conflictOptions.push(options);
            return Promise.resolve('skip');
        },
        refreshPane(pane) { refreshes.push(pane); },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    const result = await manager.moveSelectedBetweenPanes(
        'left',
        'right',
        [
            { name: 'one.txt', is_dir: false },
            { name: 'two.txt', is_dir: false },
            { name: 'three', is_dir: true },
        ],
    );

    assert.equal(result, 'complete');
    assert.deepEqual(requests.map(request => request.event), [
        'rename_file', 'rename_file', 'rename_file',
    ]);
    assert.equal(requests.every(request => (
        !Object.hasOwn(request.payload, 'replace')
    )), true);
    assert.deepEqual(conflictOptions, [{ allowReplace: false }]);
    assert.deepEqual(refreshes, ['left', 'right']);
});

test('same-source move stops after a cancelled conflict and refreshes both panes', async () => {
    const requests = [];
    const refreshes = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        requestSequence: 0,
        socket: { emit(event, payload, acknowledgement) {
            requests.push({ event, payload });
            acknowledgement({
                success: false,
                code: 'CONFLICT',
                error: 'A file or folder already exists at the destination.',
                source_id: payload.source_id,
                old_path: payload.old_path,
                new_path: payload.new_path,
                request_id: payload.request_id,
            });
        } },
        panes: {
            left: filePane(manager, 'smb-quick:shared', { path: '/source' }),
            right: filePane(manager, 'smb-quick:shared', { path: '/target' }),
        },
        resolveUploadConflict(_details, options) {
            assert.deepEqual(options, { allowReplace: false });
            return Promise.resolve('cancel');
        },
        refreshPane(pane) { refreshes.push(pane); },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    const result = await manager.moveSelectedBetweenPanes(
        'left',
        'right',
        [
            { name: 'one.txt', is_dir: false },
            { name: 'two.txt', is_dir: false },
        ],
    );

    assert.equal(result, 'cancelled');
    assert.equal(requests.length, 1);
    assert.deepEqual(refreshes, ['left', 'right']);
});

test('same-source move reports an acknowledgement timeout instead of hanging', async () => {
    const notifications = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        requestSequence: 0,
        moveAcknowledgementTimeoutMs: 1,
        socket: { emit() {} },
        panes: {
            left: filePane(manager, 'smb-quick:shared', { path: '/source' }),
            right: filePane(manager, 'smb-quick:shared', { path: '/target' }),
        },
        refreshPane() {},
        showNotification(message, level) {
            notifications.push({ message, level });
        },
        t(_key, fallback) { return fallback; },
    });

    const result = await manager.moveSelectedBetweenPanes(
        'left',
        'right',
        [{ name: 'one.txt', is_dir: false }],
    );

    assert.equal(result, 'error');
    assert.deepEqual(notifications, [{
        message: 'The move timed out before the server confirmed it. Refresh both folders before retrying.',
        level: 'error',
    }]);
});

test('same-source drag advertises a move instead of a copy', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const item = { name: 'report.txt', is_dir: false };
    Object.assign(manager, {
        workspace: {
            layout: 'split',
            getActiveTab() { return {}; },
        },
        panes: {
            left: filePane(manager, 'smb-quick:shared', {
                path: '/source', files: [item], selected: new Set([0]),
            }),
            right: filePane(manager, 'smb-quick:shared', { path: '/target' }),
        },
    });
    const dataTransfer = {
        effectAllowed: '',
        setData() {},
    };

    manager.handleDragStart({ dataTransfer }, 'left', 0);

    assert.equal(dataTransfer.effectAllowed, 'move');
});

test('file checkbox keeps native Tab and Enter keyboard behavior', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        isOpen: true,
        displayMode: 'modal',
        activePane: 'left',
        workspace: { layout: 'split' },
        panes: { left: { selected: new Set([0]) } },
        setActivePane() { assert.fail('Tab switched file areas'); },
        handleItemDblClick() { assert.fail('Enter opened the selected file'); },
    });
    const target = {
        matches(selector) { return selector === '.fm-file-checkbox'; },
        closest(selector) { return selector.includes('button') ? this : null; },
    };

    for (const key of ['Tab', 'Enter']) {
        manager.handleKeyboardShortcut({
            key, ctrlKey: false, target,
            preventDefault() { assert.fail(`${key} native behavior was blocked`); },
        });
    }
});

test('file checkbox markup is keyboard accessible and double click never opens the item', () => {
    const previousDocument = global.document;
    let rendered = '';
    const container = {
        set innerHTML(value) { rendered = value; },
        get innerHTML() { return rendered; },
        querySelectorAll() { return []; },
    };
    global.document = {
        getElementById(id) { return id === 'fmLeftList' ? container : null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    let opened = false;
    Object.assign(manager, {
        panes: {
            left: {
                source: fileSource('sftp-session:session-a'), path: '/', selected: new Set(),
                files: [{ name: 'readme.txt', is_dir: false, size: 1 }],
            },
        },
        workspace: { layout: 'single' },
        displayMode: 'embedded',
        escapeHtml(value) { return String(value); },
        updatePaneStatus() {},
        t(_key, fallback) { return fallback; },
        handleItemDblClick() { opened = true; },
    });

    try {
        manager.renderPane('left');
        manager.handleItemDoubleClickEvent({
            target: { closest(selector) { return selector === '.fm-file-checkbox' ? this : null; } },
            preventDefault() {}, stopPropagation() {},
        }, 'left', 0);
    } finally {
        global.document = previousDocument;
    }

    assert.match(rendered, /<button[^>]+class="fm-file-checkbox material-icons"/);
    assert.match(rendered, /role="checkbox"[^>]+aria-checked="false"/);
    assert.equal(opened, false);
});

test('an empty non-root folder still renders the parent directory action', () => {
    const previousDocument = global.document;
    let rendered = '';
    const container = {
        set innerHTML(value) { rendered = value; },
        get innerHTML() { return rendered; },
        querySelectorAll() { return []; },
    };
    global.document = {
        getElementById(id) { return id === 'fmLeftList' ? container : null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        panes: {
            left: {
                source: fileSource('smb-quick:share'), path: '/empty',
                selected: new Set(), files: [],
            },
        },
        workspace: { layout: 'single' },
        displayMode: 'modal',
        escapeHtml(value) { return String(value); },
        updatePaneStatus() {},
        t(_key, fallback) { return fallback; },
    });

    try {
        manager.renderPane('left');
    } finally {
        global.document = previousDocument;
    }

    assert.match(rendered, /data-type="parent"/);
    assert.match(rendered, /<div class="fm-file-name">\.\.<\/div>/);
    assert.match(rendered, /Empty directory/);
});

test('embedded drag and drop uses the existing directory upload path', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const folder = { isDirectory: true, isFile: false };
    let uploaded;
    Object.assign(manager, {
        displayMode: 'embedded',
        panes: {
            left: { source: fileSource('sftp-session:session-a'), path: '/srv' },
        },
        draggedItems: [], dragSource: null,
        uploadDesktopItemsToSSH(entries, target) { uploaded = { entries, target }; },
    });

    manager.handleDrop({
        dataTransfer: {
            files: [],
            items: [{ kind: 'file', webkitGetAsEntry: () => folder }],
        },
    }, 'left');

    assert.deepEqual(uploaded.entries, [folder]);
    assert.equal(uploaded.target, manager.panes.left);
});

test('the full modal suspends embedded Files and restores it when closed', async () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    let closed = 0;
    let shown = 0;
    let hidden = 0;
    let dispatched = 0;
    let restored = null;
    const embeddedContainer = {};
    const embeddedSession = {
        id: 'session-a', username: 'ops', host: 'edge.example', port: 22, connected: true,
    };
    Object.assign(manager, {
        displayMode: 'embedded', isOpen: true, embeddedContainer,
        availableSessions: [embeddedSession],
        panes: {
            left: { source: fileSource('sftp-session:session-a'), path: '/', selected: new Set() },
            right: { source: null, path: '/', selected: new Set() },
        },
        modal: { style: {}, classList: classList() },
        closeEmbedded() { closed += 1; this.displayMode = 'closed'; this.isOpen = false; },
        suspendEmbedded() {
            this.suspendedEmbeddedTarget = {
                container: this.embeddedContainer,
                sessionId: this.embeddedTarget?.sessionId || 'session-a',
                session: this.availableSessions[0],
            };
            this.displayMode = 'closed';
            this.isOpen = false;
        },
        openEmbedded(container, sessionId, session) {
            restored = { container, sessionId, session };
            this.displayMode = 'embedded';
            this.isOpen = true;
            return Promise.resolve(true);
        },
        updateSessionLists() {}, restoreLastSources() {}, applyTranslations() {},
        loadWorkspaceProfiles() {}, updatePathInput() {}, updatePaneBadge() {}, renderPane() {},
        renderWorkspaceChrome() {}, openSourceLauncher() {}, closeSourceLauncher() {},
        closeContextMenu() {},
        isMobile() { return false; }, setActivePane() {}, updateMobilePaneTabs() {},
    });
    global.window.ModalManager = {
        open() { shown += 1; },
        close() { hidden += 1; },
    };
    global.window.dispatchEvent = () => { dispatched += 1; };
    const originalGetElementById = global.document.getElementById;
    global.document.getElementById = () => ({ style: {}, classList: classList(), value: '' });

    manager.open();

    assert.equal(closed, 0);
    assert.equal(dispatched, 0);
    assert.equal(shown, 1);
    assert.equal(manager.displayMode, 'modal');
    manager.close();
    await Promise.resolve();

    assert.equal(hidden, 1);
    assert.deepEqual(restored, {
        container: embeddedContainer,
        sessionId: 'session-a',
        session: embeddedSession,
    });
    assert.equal(manager.displayMode, 'embedded');
    global.document.getElementById = originalGetElementById;
    delete global.window.ModalManager;
});

test('manual embedded close cancels a pending restore while the modal is open', () => {
    const target = { container: {}, sessionId: 'session-a', session: { id: 'session-a' } };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        displayMode: 'modal',
        embeddedTarget: target,
        suspendedEmbeddedTarget: target,
    });

    manager.closeEmbedded();

    assert.equal(manager.embeddedTarget, null);
    assert.equal(manager.suspendedEmbeddedTarget, null);
    assert.equal(manager.displayMode, 'modal');
});

test('active session changes replace the pending embedded restore target', async () => {
    const container = {};
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        displayMode: 'modal',
        embeddedTarget: null,
        suspendedEmbeddedTarget: {
            container, sessionId: 'session-a', session: { id: 'session-a' },
        },
    });

    const followed = await manager.followEmbedded('session-b', {
        username: 'deploy', host: 'next.example', port: 2222, connected: true,
    });

    assert.equal(followed, true);
    assert.deepEqual(manager.suspendedEmbeddedTarget, {
        container,
        sessionId: 'session-b',
        session: {
            id: 'session-b', username: 'deploy', host: 'next.example', port: 2222, connected: true,
        },
    });
    assert.equal(manager.embeddedTarget, manager.suspendedEmbeddedTarget);
});

test('disconnect cancels only the matching pending embedded restore target', () => {
    const target = { container: {}, sessionId: 'session-a', session: { id: 'session-a' } };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        displayMode: 'modal',
        embeddedTarget: target,
        suspendedEmbeddedTarget: target,
    });

    manager.handleEmbeddedDisconnect('session-b');
    assert.equal(manager.suspendedEmbeddedTarget, target);

    manager.handleEmbeddedDisconnect('session-a');
    assert.equal(manager.embeddedTarget, null);
    assert.equal(manager.suspendedEmbeddedTarget, null);
});

test('generic transfer failures are localized before entering the queue', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    let finalized;
    manager.t = (key, fallback) => (
        key === 'fm.transferUnavailable' ? 'Transfer nicht verfügbar' : fallback
    );
    manager.finalizeTransferById = (...args) => { finalized = args; };

    manager.failTransferById('transfer-1', 'Transfer unavailable');

    assert.deepEqual(finalized, [
        'transfer-1',
        'error',
        'Transfer nicht verfügbar',
    ]);
});

test('mobile uploads use tokenized transfers with joined target paths', () => {
    const files = [
        { name: 'first report.txt', size: 12 },
        { name: 'archive.zip', size: 345 },
    ];
    const joinCalls = [];
    const uploadRequests = [];
    const queued = [];
    let fetchCalls = 0;
    const previousFetch = global.fetch;
    const previousDocument = global.document;
    global.fetch = () => {
        fetchCalls += 1;
        return new Promise(() => {});
    };
    global.document = { querySelector: () => null };

    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: {
                source: fileSource('sftp-session:mobile-session'),
                path: '/incoming/reports',
            },
        },
        getTransferClient: () => ({
            uploadFile(file, remotePath, sourceId) {
                uploadRequests.push({ file, remotePath, sourceId });
                return `mobile-${file.name}`;
            },
        }),
        joinPath(basePath, filename) {
            joinCalls.push({ basePath, filename });
            return `/joined${basePath}/${filename}`;
        },
        queueTransfer(transfer) { queued.push(transfer); },
        showUploadProgress() {},
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });
    const input = { files, value: 'selected' };

    try {
        manager.handleMobileUpload({ target: input });
    } finally {
        global.fetch = previousFetch;
        global.document = previousDocument;
    }

    assert.deepEqual(uploadRequests, [
        { file: files[0], remotePath: '/joined/incoming/reports/first report.txt', sourceId: 'sftp-session:mobile-session' },
        { file: files[1], remotePath: '/joined/incoming/reports/archive.zip', sourceId: 'sftp-session:mobile-session' },
    ]);
    assert.deepEqual(joinCalls, [
        { basePath: '/incoming/reports', filename: 'first report.txt' },
        { basePath: '/incoming/reports', filename: 'archive.zip' },
    ]);
    assert.equal(queued.length, 2);
    assert.equal(queued[0].id, 'mobile-first report.txt');
    assert.equal(queued[0].sourceId, 'sftp-session:mobile-session');
    assert.equal(queued[0].batchId, queued[1].batchId);
    assert.equal(typeof queued[0].batchId, 'string');
    assert.notEqual(queued[0].batchId, '');
    assert.equal(queued[1].id, 'mobile-archive.zip');
    assert.equal(queued[1].sourceId, 'sftp-session:mobile-session');
    assert.equal(fetchCalls, 0);
    assert.equal(input.value, '');
});

test('remote filenames never enter attributes even when they contain quote and event text', () => {
    const previousDocument = global.document;
    let rendered = '';
    const container = {
        set innerHTML(value) { rendered = value; },
        get innerHTML() { return rendered; },
        querySelectorAll() { return []; },
    };
    global.document = {
        getElementById(id) { return id === 'fmLeftList' ? container : null; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        panes: {
            left: {
                source: fileSource('sftp-session:session-a'), path: '/', selected: new Set(),
                files: [{
                    name: 'quote" onmouseover="globalThis.injected=1',
                    is_dir: false, size: 1, permissions: '-rw-------',
                }],
            },
        },
        workspace: { layout: 'single' },
        displayMode: 'embedded',
        escapeHtml(value) {
            return String(value)
                .replaceAll('&', '&amp;')
                .replaceAll('"', '&quot;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;');
        },
        updatePaneStatus() {},
        t(_key, fallback) { return fallback; },
    });

    try {
        manager.renderPane('left');
    } finally {
        global.document = previousDocument;
    }

    assert.equal(rendered.includes('data-name='), false);
    assert.equal(/<div class="fm-file-item[^>]*\sonmouseover=/i.test(rendered), false);
    assert.equal(rendered.includes('quote&quot; onmouseover=&quot;globalThis.injected=1'), true);
});

test('SFTP socket setup leaves upload progress and terminal state to BinaryTransferClient', () => {
    const registered = [];
    const manager = Object.create(SFTPFileManager.prototype);
    manager.socket = { on(event) { registered.push(event); } };

    manager.setupSocketListeners();

    assert.equal(registered.includes('file_progress'), false);
    assert.equal(registered.includes('file_complete'), false);
});

test('directory creation events do not refresh panes in the middle of an upload batch', () => {
    const listeners = {};
    let refreshes = 0;
    let notifications = 0;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        uploadBatches: new Map([['batch', {}]]),
        pendingOperationRequests: new Map([
            ['upload:create:1', {
                sourceId: 'sftp-session:upload', operation: 'create_directory',
            }],
            ['manual:create:2', {
                sourceId: 'sftp-session:manual', operation: 'create_directory',
            }],
        ]),
        refreshSource() { refreshes += 1; },
        showNotification() { notifications += 1; },
        t(_key, fallback) { return fallback; },
    });
    manager.setupSocketListeners();

    listeners.directory_created({
        source_id: 'sftp-session:upload', request_id: 'upload:create:1',
        path: '/incoming/reports',
    });
    assert.equal(refreshes, 0);
    assert.equal(notifications, 0);

    manager.uploadBatches.clear();
    listeners.directory_created({
        source_id: 'sftp-session:manual', request_id: 'manual:create:2',
        path: '/manual-folder',
    });
    assert.equal(refreshes, 1);
    assert.equal(notifications, 1);
});

test('mutation responses must match both source and request before changing UI', () => {
    const listeners = {};
    let refreshes = 0;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        uploadBatches: new Map(),
        pendingOperationRequests: new Map([['workspace:rename:1', {
            sourceId: 'sftp-session:current', operation: 'rename_file',
        }]]),
        refreshSource() { refreshes += 1; },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });
    manager.setupSocketListeners();

    listeners.file_renamed({
        source_id: 'sftp-session:stale', request_id: 'workspace:rename:1',
    });
    listeners.file_renamed({
        source_id: 'sftp-session:current', request_id: 'workspace:rename:stale',
    });
    assert.equal(refreshes, 0);

    listeners.file_renamed({
        source_id: 'sftp-session:current', request_id: 'workspace:rename:1',
    });
    assert.equal(refreshes, 1);
    assert.equal(manager.pendingOperationRequests.size, 0);
});

test('upload batch finishes on complete error and cancel then refreshes its session pane once', async () => {
    const listeners = {};
    const refreshed = [];
    const client = { on(event, callback) { listeners[event] = callback; } };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: {},
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        panes: {
            left: { source: fileSource('sftp-session:batch-session') },
            right: { source: fileSource('sftp-session:other-session') },
        },
        renderTransferQueue() {},
        processTransferQueue() {},
        showUploadProgress() {},
        showUploadComplete() {},
        createTransferClient: () => client,
        refreshPane(pane) { refreshed.push(pane); },
    });
    manager.getTransferClient();
    const batch = manager.startUploadBatch(3, 'sftp-session:batch-session');
    manager.queueTransfer({ id: 'done', type: 'upload', sourceId: 'sftp-session:batch-session', batchId: batch.id });
    manager.queueTransfer({ id: 'failed', type: 'upload', sourceId: 'sftp-session:batch-session', batchId: batch.id });
    manager.queueTransfer({ id: 'cancelled', type: 'upload', sourceId: 'sftp-session:batch-session', batchId: batch.id });

    listeners.complete({ transferId: 'done' });
    listeners.error({ transferId: 'failed', error: 'no space' });
    await Promise.resolve();
    assert.deepEqual(refreshed, []);
    assert.equal(batch.completed, 2);

    listeners.cancel({ transferId: 'cancelled' });
    await Promise.resolve();
    await Promise.resolve();

    assert.equal(batch.completed, 3);
    assert.equal(batch.succeeded, 1);
    assert.equal(batch.failed, 1);
    assert.equal(batch.cancelled, 1);
    assert.equal(manager.currentUploadBatch, null);
    assert.deepEqual(refreshed, ['left']);
});

test('upload completion refreshes its original tab after another tab becomes active', async () => {
    const emitted = [];
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const destinationState = filePane(manager, 'sftp-session:upload-session', {
        path: '/srv/upload',
    });
    manager.workspace.openTab(
        'left', fileSource('sftp-session:upload-session', { label: 'Upload' }),
        destinationState,
    );
    manager.workspace.openTab(
        'left', fileSource('sftp-session:other-session', { label: 'Other' }),
        filePane(manager, 'sftp-session:other-session', { path: '/srv/other' }),
    );
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal',
        isOpen: true,
        requestSequence: 0,
        socket: { emit(event, payload) { emitted.push({ event, payload }); } },
        showUploadProgress() {},
        showUploadComplete() {},
    });

    const batch = manager.startUploadBatch(1, 'sftp-session:upload-session', destinationState);
    manager.recordUploadTerminal({
        type: 'upload',
        sourceId: 'sftp-session:upload-session',
        batchId: batch.id,
    }, 'complete');
    await Promise.resolve();
    await Promise.resolve();

    assert.equal(manager.workspace.getActiveTab('left').paneState.path, '/srv/other');
    assert.deepEqual(emitted, [{
        event: 'list_directory',
        payload: {
            source_id: 'sftp-session:upload-session',
            remote_path: '/srv/upload',
            request_id: 'left:directory:1',
        },
    }]);
    assert.equal(destinationState.loading, true);
});

test('upload completion refreshes and caches its original tab while the workspace is closed', async () => {
    const emitted = [];
    const listeners = {};
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const destinationState = filePane(manager, 'sftp-session:upload-session', {
        path: '/srv/upload',
        files: [{ name: 'old.txt' }],
    });
    manager.workspace.openTab(
        'left', fileSource('sftp-session:upload-session', { label: 'Upload' }),
        destinationState,
    );
    manager.workspace.openTab(
        'left', fileSource('sftp-session:other-session', { label: 'Other' }),
        filePane(manager, 'sftp-session:other-session', { path: '/srv/other' }),
    );
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'closed',
        isOpen: false,
        requestSequence: 0,
        socket: {
            emit(event, payload) { emitted.push({ event, payload }); },
            on(event, callback) { listeners[event] = callback; },
        },
        showUploadProgress() {},
        showUploadComplete() {},
        showNotification() {},
    });
    manager.setupSocketListeners();

    const batch = manager.startUploadBatch(1, 'sftp-session:upload-session', destinationState);
    manager.recordUploadTerminal({
        type: 'upload',
        sourceId: 'sftp-session:upload-session',
        batchId: batch.id,
    }, 'complete');
    await Promise.resolve();
    await Promise.resolve();

    assert.deepEqual(emitted, [{
        event: 'list_directory',
        payload: {
            source_id: 'sftp-session:upload-session',
            remote_path: '/srv/upload',
            request_id: 'left:directory:1',
        },
    }]);

    listeners.directory_listing({
        source_id: 'sftp-session:upload-session',
        request_id: 'left:directory:1',
        path: '/srv/upload',
        files: [{ name: 'new.txt' }],
    });

    assert.deepEqual(destinationState.files, [{ name: 'new.txt' }]);
    assert.equal(destinationState.loading, false);
    assert.equal(destinationState.pendingDirectoryRequestId, null);
});

test('directory upload batches consume every readEntries page before fixing the total', async () => {
    const uploaded = [];
    let batchTotal;
    const fileEntries = [
        { name: 'first.txt', isFile: true, isDirectory: false, file(callback) { callback({ name: this.name }); } },
        { name: 'second.txt', isFile: true, isDirectory: false, file(callback) { callback({ name: this.name }); } },
    ];
    const directory = {
        name: 'reports',
        isFile: false,
        isDirectory: true,
        createReader() {
            let page = 0;
            return {
                readEntries(resolve) {
                    resolve(page < fileEntries.length ? [fileEntries[page++]] : []);
                },
            };
        },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit() {} },
        joinPath(base, name) { return `${base}/${name}`; },
        startUploadBatch(total) {
            batchTotal = total;
            return { id: 'paged-batch' };
        },
        uploadSingleFileToSSH(file, basePath, sourceId, batchId) {
            uploaded.push({ name: file.name, basePath, sourceId, batchId });
        },
    });

    await manager.uploadDesktopItemsToSSH(
        [directory],
        { source: fileSource('sftp-session:paged-session'), path: '/incoming' },
    );

    assert.equal(batchTotal, 2);
    assert.deepEqual(uploaded.map(item => item.name), ['first.txt', 'second.txt']);
    assert.equal(uploaded.every(item => item.batchId === 'paged-batch'), true);
});

test('upload batch presentation never reports a failed batch as complete', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.t = (_key, fallback) => fallback;

    assert.deepEqual(manager.uploadBatchPresentation({
        total: 1, succeeded: 0, failed: 1, cancelled: 0,
    }), {
        state: 'error',
        icon: 'error',
        heading: 'Upload failed',
        details: '0 / 1 files uploaded · 1 Failed',
    });
    assert.deepEqual(manager.uploadBatchPresentation({
        total: 3, succeeded: 2, failed: 1, cancelled: 0,
    }), {
        state: 'error',
        icon: 'error',
        heading: 'Upload finished with issues',
        details: '2 / 3 files uploaded · 1 Failed',
    });
});

test('default transfer client uses the shared per-socket coordinator', () => {
    const previousClient = global.BinaryTransferClient;
    const socket = {};
    const listeners = [];
    const shared = { on(event) { listeners.push(event); } };
    let receivedSocket;
    global.BinaryTransferClient = {
        forSocket(value) {
            receivedSocket = value;
            return shared;
        },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket,
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        renderTransferQueue() {},
    });

    try {
        assert.equal(manager.getTransferClient(), shared);
    } finally {
        global.BinaryTransferClient = previousClient;
    }

    assert.equal(receivedSocket, socket);
    assert.deepEqual(listeners, [
        'progress', 'complete', 'error', 'cancelling', 'cancel', 'skip',
    ]);
});

test('client events advance two queue entries and report byte progress by id', () => {
    const listeners = {};
    const client = {
        on(event, callback) { listeners[event] = callback; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: {},
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        renderTransferQueue() {},
        refreshBothPanes() {},
        createTransferClient: () => client,
    });

    manager.getTransferClient();
    manager.queueTransfer({ id: 'first', type: 'upload', filename: 'one.bin', size: 10 });
    manager.queueTransfer({ id: 'second', type: 'upload', filename: 'two.bin', size: 20 });
    listeners.progress({ transferId: 'first', transferred: 4, total: 10, percent: 40 });
    assert.equal(manager.transferQueue[0].transferred, 4);
    assert.equal(manager.transferQueue[0].progress, 40);

    listeners.complete({ transferId: 'first' });
    manager.processTransferQueue();
    assert.equal(manager.transferQueue[0].status, 'complete');
    assert.equal(manager.transferQueue[1].status, 'active');

    listeners.error({ transferId: 'second', error: 'failed' });
    assert.equal(manager.transferQueue[1].status, 'error');
    assert.equal(manager.isTransferring, false);
    assert.equal(manager.activeTransfers.size, 0);
});

test('failed transfer row renders a localized visible and accessible reason', () => {
    const previousDocument = global.document;
    const queue = { innerHTML: '' };
    const badge = { textContent: '', style: {} };
    global.document = {
        getElementById(id) {
            return { fmQueueList: queue, fmQueueBadge: badge }[id] || null;
        },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        transferQueue: [{
            id: 'failed-upload',
            type: 'upload',
            filename: 'report.txt',
            status: 'error',
            progress: 0,
            error: 'No write permission for the destination.',
            errorCode: 'PERMISSION_DENIED',
            retryable: false,
        }],
        t(key, fallback) {
            if (key === 'transfer.error.PERMISSION_DENIED') {
                return 'No write permission for the destination.';
            }
            return fallback;
        },
        escapeHtml(value) { return String(value); },
    });

    try {
        manager.renderTransferQueue();
    } finally {
        global.document = previousDocument;
    }

    assert.match(queue.innerHTML, />Failed</);
    assert.match(queue.innerHTML, /fm-transfer-error/);
    assert.match(queue.innerHTML, /No write permission for the destination\./);
    assert.match(queue.innerHTML, /title="No write permission for the destination\."/);
});

test('structured client failure reaches the queue without losing its code', () => {
    const listeners = {};
    const client = { on(event, callback) { listeners[event] = callback; } };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: {},
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        renderTransferQueue() {},
        createTransferClient: () => client,
        t(_key, fallback) { return fallback; },
    });

    manager.getTransferClient();
    manager.queueTransfer({
        id: 'failed-upload', type: 'upload', filename: 'report.txt', size: 7,
    });
    listeners.error({
        transferId: 'failed-upload',
        error: 'No write permission for the destination.',
        errorCode: 'PERMISSION_DENIED',
        retryable: false,
    });

    assert.equal(manager.transferQueue[0].status, 'error');
    assert.equal(manager.transferQueue[0].errorCode, 'PERMISSION_DENIED');
    assert.equal(
        manager.transferQueue[0].error,
        'No write permission for the destination.',
    );
    assert.equal(manager.transferQueue[0].retryable, false);
});

test('a terminal event for a pending entry does not release the active queue entry', () => {
    const listeners = {};
    const client = {
        on(event, callback) { listeners[event] = callback; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: {},
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        renderTransferQueue() {},
        refreshBothPanes() {},
        createTransferClient: () => client,
    });

    manager.getTransferClient();
    manager.queueTransfer({ id: 'first', type: 'upload', filename: 'one.bin', size: 10 });
    manager.queueTransfer({ id: 'second', type: 'upload', filename: 'two.bin', size: 20 });

    listeners.complete({ transferId: 'second' });

    assert.equal(manager.transferQueue[0].status, 'active');
    assert.equal(manager.transferQueue[1].status, 'complete');
    assert.equal(manager.isTransferring, true);
    assert.equal(manager.activeTransfers.has('first'), true);
});

test('a cancellation updates its own queue entry without releasing another active transfer', () => {
    const listeners = {};
    const client = {
        on(event, callback) { listeners[event] = callback; },
    };
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: {},
        transferClient: null,
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        renderTransferQueue() {},
        refreshBothPanes() {},
        createTransferClient: () => client,
    });

    manager.getTransferClient();
    manager.queueTransfer({ id: 'first', type: 'upload', filename: 'one.bin', size: 10 });
    manager.queueTransfer({ id: 'second', type: 'upload', filename: 'two.bin', size: 20 });

    listeners.cancel({ transferId: 'second' });

    assert.equal(manager.transferQueue[0].status, 'active');
    assert.equal(manager.transferQueue[1].status, 'cancelled');
    assert.equal(manager.isTransferring, true);
    assert.equal(manager.activeTransfers.has('first'), true);
});

test('folder downloads queue the HTTP transfer id without a binary socket event', () => {
    let requested;
    let queued;
    const socketEvents = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit(event) { socketEvents.push(event); } },
        getTransferClient: () => ({
            downloadFolder(path, sourceId) {
                requested = { path, sourceId };
                return 'folder-local-id';
            },
        }),
        queueTransfer(transfer) { queued = transfer; },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    manager.downloadFolderToBrowser('sftp-session:session', '/remote/reports', 'reports');

    assert.deepEqual(requested, { path: '/remote/reports', sourceId: 'sftp-session:session' });
    assert.equal(queued.id, 'folder-local-id');
    assert.equal(queued.sourceId, 'sftp-session:session');
    assert.equal(socketEvents.includes('download_folder_binary'), false);
});

test('server copies queue the server-owned cancellable transfer id', async () => {
    let request;
    let queued;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit(event, payload, ack) {
            request = { event, payload };
            ack({
                success: true,
                transfer_id: 'server-transfer-id',
                source_id: payload.source_id,
                destination_source_id: payload.destination_source_id,
                request_id: payload.request_id,
            });
        } },
        queueTransfer(transfer) { queued = transfer; },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    const terminal = manager.transferSSHtoSSH(
        '/source/file.bin', filePane(manager, 'sftp-session:source-session'),
        '/target/file.bin', filePane(manager, 'sftp-session:target-session'),
        { name: 'file.bin', is_dir: false, size: 10 },
    );
    await Promise.resolve();

    assert.equal(request.event, 'transfer_server_to_server');
    assert.equal(request.payload.transfer_id, undefined);
    assert.equal(queued.id, 'server-transfer-id');
    assert.deepEqual(queued.sourceIds, [
        'sftp-session:source-session', 'sftp-session:target-session',
    ]);
    manager.resolveS2STerminal('server-transfer-id', 'complete');
    await terminal;
});

test('three selected server copies start only after the previous transfer is terminal', async () => {
    const requests = [];
    const flushAsync = () => new Promise(resolve => setImmediate(resolve));
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: {
                source: fileSource('sftp-session:source-session'), path: '/source',
                files: [
                    { name: 'first.bin', is_dir: false, size: 1 },
                    { name: 'second.bin', is_dir: false, size: 2 },
                    { name: 'third.bin', is_dir: false, size: 3 },
                ],
                selected: new Set([0, 1, 2]),
            },
            right: {
                source: fileSource('sftp-session:target-session'), path: '/target',
                files: [], selected: new Set(),
            },
        },
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        socket: {
            emit(event, payload, acknowledgement) {
                assert.equal(event, 'transfer_server_to_server');
                const id = `server-${requests.length + 1}`;
                requests.push({ id, sourcePath: payload.source_path });
                acknowledgement({
                    success: true,
                    transfer_id: id,
                    source_id: payload.source_id,
                    destination_source_id: payload.destination_source_id,
                    request_id: payload.request_id,
                });
            },
        },
        renderTransferQueue() {},
        processTransferQueue: SFTPFileManager.prototype.processTransferQueue,
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });
    manager.workspace.openTab(
        'left', fileSource('sftp-session:source-session'), manager.panes.left,
    );
    manager.workspace.openTab(
        'right', fileSource('sftp-session:target-session'), manager.panes.right,
    );
    manager.workspace.setLayout('split');

    const execution = manager.executeTransfer();
    await flushAsync();
    assert.deepEqual(requests.map(request => request.sourcePath), ['/source/first.bin']);
    let duplicateSettled = false;
    manager.executeTransfer().then(() => { duplicateSettled = true; });
    await flushAsync();
    assert.equal(duplicateSettled, true);
    assert.deepEqual(requests.map(request => request.sourcePath), ['/source/first.bin']);

    manager.completeS2STransfer({ transfer_id: 'server-1' });
    await flushAsync();
    assert.deepEqual(requests.map(request => request.sourcePath), [
        '/source/first.bin', '/source/second.bin',
    ]);

    manager.failS2STransfer({
        transfer_id: 'server-2',
        error: 'Permission denied for this file operation.',
        error_code: 'PERMISSION_DENIED',
        retryable: false,
    });
    await flushAsync();
    assert.deepEqual(requests.map(request => request.sourcePath), [
        '/source/first.bin', '/source/second.bin', '/source/third.bin',
    ]);

    manager.cancelTransferById('server-3');
    await execution;
    assert.deepEqual(manager.transferQueue.map(transfer => transfer.status), [
        'complete', 'error', 'cancelled',
    ]);
    assert.equal(manager.transferQueue[1].errorCode, 'PERMISSION_DENIED');
    assert.equal(
        manager.transferQueue[1].error,
        'Permission denied for this file operation.',
    );
});

test('server copy retries a conflict only after explicit replace consent', async () => {
    const requests = [];
    const conflicts = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        transferQueue: [],
        activeTransfers: new Map(),
        pendingS2SRequests: new Map(),
        requestSequence: 0,
        socket: {
            emit(event, payload, acknowledgement) {
                assert.equal(event, 'transfer_server_to_server');
                requests.push(payload);
                acknowledgement({
                    success: true,
                    transfer_id: `copy-${requests.length}`,
                    source_id: payload.source_id,
                    destination_source_id: payload.destination_source_id,
                    request_id: payload.request_id,
                });
            },
        },
        getPaneSourceId(state) { return state.source.sourceId; },
        retainTransferSources() {},
        releaseTransferSources() {},
        flushPendingQuickDisconnects() {},
        showNotification() {},
        matchesS2SResponse() { return true; },
        nextRequestId() { return `request-${++this.requestSequence}`; },
        waitForS2STerminal(transferId) {
            return Promise.resolve(transferId === 'copy-1' ? 'error' : 'complete');
        },
        queueTransfer(transfer) {
            transfer.status = transfer.id === 'copy-1' ? 'error' : 'complete';
            if (transfer.id === 'copy-1') {
                transfer.errorCode = 'CONFLICT';
                transfer.error = 'A file or folder already exists at the destination.';
            }
            this.transferQueue.push(transfer);
        },
        renderTransferQueue() {},
        resolveUploadConflict(details) {
            conflicts.push(details);
            return Promise.resolve('replace');
        },
        t(_key, fallback) { return fallback; },
    });
    const source = { source: fileSource('smb-quick:source') };
    const destination = { source: fileSource('smb-quick:destination') };

    const result = await manager.transferSSHtoSSH(
        '/source/report.txt',
        source,
        '/destination/report.txt',
        destination,
        { name: 'report.txt', size: 10, is_dir: false },
    );

    assert.equal(result, 'complete');
    assert.deepEqual(
        requests.map(request => request.conflict_policy),
        ['error', 'replace'],
    );
    assert.deepEqual(conflicts, [{ filename: 'report.txt' }]);
    assert.deepEqual(
        manager.transferQueue.map(transfer => transfer.id),
        ['copy-2'],
    );
});

test('an S2S terminal event received before its acknowledgement cannot strand the selection', async () => {
    let manager;
    manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        socket: {
            emit(_event, payload, acknowledgement) {
                const context = {
                    transfer_id: 'fast-transfer',
                    source_id: payload.source_id,
                    destination_source_id: payload.destination_source_id,
                    request_id: payload.request_id,
                };
                manager.completeS2STransfer(context);
                acknowledgement({ success: true, ...context });
            },
        },
        renderTransferQueue() {},
        processTransferQueue() {},
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    let settled = false;
    const transfer = manager.transferSSHtoSSH(
        '/source/fast.bin', filePane(manager, 'sftp-session:source-session'),
        '/target/fast.bin', filePane(manager, 'sftp-session:target-session'),
        { name: 'fast.bin', is_dir: false, size: 1 },
    ).then(() => { settled = true; });
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(settled, true);
    assert.equal(manager.transferQueue[0].status, 'complete');
    await transfer;
});

test('server copy cancellation waits for the worker terminal event', () => {
    const requests = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit(event, payload, ack) {
            requests.push({ event, payload });
            ack({ success: true, state: 'cancelling' });
        } },
        transferQueue: [{ id: 's2s-id', type: 's2s', status: 'active' }],
        activeTransfers: new Map([['s2s-id', {}]]),
        isTransferring: true,
        renderTransferQueue() {},
        processTransferQueue() {},
    });

    manager.cancelQueuedTransfer('s2s-id');
    manager.cancelQueuedTransfer('s2s-id');

    assert.deepEqual(requests, [{
        event: 'cancel_transfer', payload: { transfer_id: 's2s-id' },
    }]);
    assert.equal(manager.transferQueue[0].status, 'cancelling');
    assert.equal(manager.isTransferring, true);

    manager.failS2STransfer({
        transfer_id: 's2s-id',
        error_code: 'CANCELLED',
        error: 'The transfer was cancelled.',
    });
    assert.equal(manager.transferQueue[0].status, 'cancelled');
    assert.equal(manager.isTransferring, false);
});

test('structured byte limit renders the exact localized size and limit kind', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.t = (key, fallback) => ({
        'transfer.limit.message': '{actual} exceeds the {limit} {kind} limit.',
        'transfer.limit.kind.upload': 'upload',
    }[key] || fallback);

    assert.equal(manager.transferFailureMessage(
        'LIMIT_EXCEEDED',
        'The transfer exceeds the configured limit.',
        {
            limit_kind: 'upload',
            limit_bytes: 100 * 1024 * 1024,
            actual_bytes: 142 * 1024 * 1024,
        },
    ), '142 MiB exceeds the 100 MiB upload limit.');

    assert.equal(manager.transferFailureMessage(
        'LIMIT_EXCEEDED',
        'The transfer exceeds the configured limit.',
        { limit_kind: 'raw', limit_bytes: -1, actual_bytes: true },
    ), 'The transfer exceeds the configured limit.');
});
