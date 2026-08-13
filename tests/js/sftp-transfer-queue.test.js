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

test('standalone workspace starts in one pane with independent empty states', () => {
    const manager = Object.create(SFTPFileManager.prototype);

    manager.initializeWorkspaceState();

    assert.equal(manager.workspace.layout, 'single');
    assert.equal(manager.workspace.activePane, 'left');
    assert.notEqual(manager.panes.left, manager.panes.right);
    assert.equal(manager.workspace.getActiveTab('left'), null);
    assert.equal(manager.workspace.getActiveTab('right'), null);
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

test('embedded pane state cannot overwrite standalone workspace tabs', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const standaloneState = {
        ...manager.createEmptyPaneState(),
        type: 'ssh', sessionId: 'workspace-session', path: '/srv/workspace',
    };
    const tab = manager.workspace.openTab('left', {
        key: 'ssh:workspace-session', type: 'ssh', label: 'Workspace', sessionId: 'workspace-session',
    }, standaloneState);
    manager.syncPaneFromWorkspace('left');

    manager.enterEmbeddedPaneState();
    manager.panes.left.sessionId = 'embedded-session';
    manager.panes.left.path = '/srv/embedded';
    manager.restoreStandalonePaneState();

    assert.equal(manager.panes.left, tab.paneState);
    assert.equal(manager.panes.left.sessionId, 'workspace-session');
    assert.equal(manager.panes.left.path, '/srv/workspace');
});

test('split layout preserves tabs and requests a source only for an empty pane', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const tab = manager.workspace.openTab('left', {
        key: 'ssh:left', type: 'ssh', label: 'Left', sessionId: 'left',
    }, manager.createEmptyPaneState());
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
    assert.deepEqual(launcherTargets, ['right']);
});

test('split layout moves the active second tab into the empty right side', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const first = manager.workspace.openTab('left', {
        key: 'ssh:first', type: 'ssh', label: 'First', sessionId: 'first',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', path: '/srv/first' });
    const second = manager.workspace.openTab('left', {
        key: 'ssh:second', type: 'ssh', label: 'Second', sessionId: 'second',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', path: '/srv/second' });
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
        }],
        quickConnections: [{
            connectionId: 'quick-a', username: 'deploy', host: 'stage.example', port: 2222,
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
        key: 'ssh:session-a', type: 'ssh', label: 'ops@edge.example',
        endpoint: 'edge.example:22', protocol: 'SFTP', status: 'Connected',
        security: 'SSH host key trusted', sessionId: 'session-a',
    });
    assert.equal(groups[1].items[0].profileId, 7);
    assert.equal(groups[1].items[0].password, undefined);
    assert.equal(groups[2].items[0].connectionId, 'quick-a');
    assert.equal(groups.flatMap(group => group.items).some(source => source.type === 'smb'), false);
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

    const tab = await manager.openWorkspaceSource('right', {
        key: 'ssh:session-a', type: 'ssh', label: 'Production', endpoint: 'edge.example:22',
        protocol: 'SFTP', status: 'Connected', security: 'SSH host key trusted',
        sessionId: 'session-a',
    });

    assert.equal(manager.workspace.getActiveTab('right'), tab);
    assert.equal(manager.workspace.getActiveTab('left'), null);
    assert.equal(manager.panes.right, tab.paneState);
    assert.deepEqual(sourceChanges, [['right', 'ssh:session-a']]);
});

test('closing the final tab for a quick connection disconnects and removes that source', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const source = {
        key: 'quick:quick-a', type: 'ssh', label: 'deploy@stage.example',
        connectionId: 'quick-a',
    };
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

test('closing a regular SSH source tab never disconnects the terminal session', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const emitted = [];
    const tab = manager.workspace.openTab('left', {
        key: 'ssh:session-a', type: 'ssh', label: 'Production', sessionId: 'session-a',
    }, manager.createEmptyPaneState());
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

test('a correlated listing updates an inactive source tab without replacing the visible tab', () => {
    const listeners = {};
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    const inactiveState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'session-a', loading: true,
        pendingDirectoryRequestId: 'left:directory:1', pendingDirectoryPath: '/srv/a',
    };
    const activeState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'session-b', path: '/srv/b',
        files: [{ name: 'visible.txt' }],
    };
    manager.workspace.openTab('left', {
        key: 'ssh:session-a', type: 'ssh', label: 'A', sessionId: 'session-a',
    }, inactiveState);
    const activeTab = manager.workspace.openTab('left', {
        key: 'ssh:session-b', type: 'ssh', label: 'B', sessionId: 'session-b',
    }, activeState);
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
        session_id: 'session-a', request_id: 'left:directory:1', path: '/srv/a',
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
    manager.workspace.openTab('left', {
        key: 'ssh:gone', type: 'ssh', label: 'Gone', sessionId: 'gone',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'gone' });
    const survivor = manager.workspace.openTab('left', {
        key: 'ssh:alive', type: 'ssh', label: 'Alive', sessionId: 'alive',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'alive' });
    manager.workspace.openTab('right', {
        key: 'ssh:gone', type: 'ssh', label: 'Gone', sessionId: 'gone',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'gone' });
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    Object.assign(manager, {
        displayMode: 'modal',
        updateSessionLists() {}, renderWorkspaceChrome() {},
        updatePathInput() {}, updatePaneBadge() {}, renderPane() {},
    });

    manager.handleSessionDisconnected('gone');

    assert.deepEqual(manager.workspace.getTabs('left').map(tab => tab.source.sessionId), ['alive']);
    assert.equal(manager.workspace.getActiveTab('left'), survivor);
    assert.equal(manager.workspace.getTabs('right').length, 0);
});

test('disconnect removes matching workspace tabs while the file manager is closed', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.openTab('left', {
        key: 'ssh:gone', type: 'ssh', label: 'Gone', sessionId: 'gone',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'gone' });
    const survivor = manager.workspace.openTab('left', {
        key: 'ssh:alive', type: 'ssh', label: 'Alive', sessionId: 'alive',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'alive' });
    manager.workspace.openTab('right', {
        key: 'ssh:gone', type: 'ssh', label: 'Gone', sessionId: 'gone',
    }, { ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'gone' });
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    Object.assign(manager, {
        displayMode: 'closed',
        isOpen: false,
        updateSessionLists() { throw new Error('closed workspace must not render'); },
        renderWorkspaceChrome() { throw new Error('closed workspace must not render'); },
    });

    manager.handleSessionDisconnected('gone');

    assert.deepEqual(manager.workspace.getTabs('left').map(tab => tab.source.sessionId), ['alive']);
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
        panes: { left: { sessionId: null }, right: { sessionId: null } },
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
    assert.deepEqual(manager.sourceChange, { pane: 'left', source: 'ssh:session-a' });
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
        { type: 'ssh' },
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
        left: {
            ...manager.createEmptyPaneState(),
            type: 'ssh',
            sessionId: 'session-a',
            homePath: '/home/user-a',
            pendingDirectoryRequestId: 'left:4',
            pendingDirectoryPath: '/srv/a',
            pendingHomeRequestId: 'left:3',
        },
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
            left: {
                ...manager.createEmptyPaneState(),
                type: 'ssh',
                sessionId: 'session-a',
                path: '/new',
                files: [{ name: 'new.txt' }],
                pendingDirectoryRequestId: 'left:2',
                pendingDirectoryPath: '/new',
                pendingHomeRequestId: 'left:home:2',
            },
            right: manager.createEmptyPaneState(),
        },
        updatePathInput() {}, renderPane() {}, navigatePaneTo() { assert.fail('stale home path used'); },
    });
    manager.setupSocketListeners();

    listeners.directory_listing({
        session_id: 'session-a', request_id: 'left:1', path: '/old', files: [{ name: 'old.txt' }],
    });
    listeners.home_directory({
        session_id: 'session-a', request_id: 'left:home:1', path: '/home/old-user',
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
            left: {
                ...manager.createEmptyPaneState(),
                type: 'ssh', sessionId: 'session-a', path: '/',
                pendingHomeRequestId: 'left:home:1',
                pendingDirectoryRequestId: 'left:directory:2',
                pendingDirectoryPath: '/srv/manual',
                autoHomeEligible: false,
            },
            right: manager.createEmptyPaneState(),
        },
        navigatePaneTo(_pane, path) { navigated = path; },
    });
    manager.setupSocketListeners();

    listeners.home_directory({
        session_id: 'session-a', request_id: 'left:home:1', path: '/home/operator',
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
            left: {
                ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'session-a',
                pendingDirectoryRequestId: 'left:directory:9', pendingDirectoryPath: '/srv/current',
            },
            right: manager.createEmptyPaneState(),
        },
    });

    assert.equal(manager.handlesSocketError({ error: 'generic' }), false);
    assert.equal(manager.handlesSocketError({
        operation: 'list_directory', session_id: 'session-a',
        request_id: 'left:directory:8', path: '/srv/old',
    }), false);
    assert.equal(manager.handlesSocketError({
        operation: 'list_directory', session_id: 'session-a',
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
            left: {
                ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'session-a', loading: true,
                pendingDirectoryRequestId: 'left:7', pendingDirectoryPath: '/srv/current',
            },
            right: manager.createEmptyPaneState(),
        },
        renderPane() { renders += 1; },
        showNotification() { notifications += 1; },
    });
    manager.setupSocketListeners();

    listeners.error({ error: 'Unrelated profile error' });
    listeners.error({
        error: 'Stale listing failed', operation: 'list_directory', session_id: 'session-a',
        request_id: 'left:6', path: '/srv/old',
    });
    assert.equal(manager.panes.left.loading, true);
    assert.equal(renders, 0);
    assert.equal(notifications, 0);

    listeners.error({
        error: 'Listing failed', operation: 'list_directory', session_id: 'session-a',
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
                type: 'ssh', sessionId: 'session-a', connectionId: null, path: '/srv',
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
        ['preview', 'session-a', '/srv/README.md', 'README.md'],
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
                type: 'ssh', sessionId: 'session-a', connectionId: null, path: '/srv',
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
    const leftState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'left', files: [file],
    };
    const rightState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'right',
    };
    manager.workspace.openTab('left', {
        key: 'ssh:left', type: 'ssh', label: 'Left', sessionId: 'left',
    }, leftState);
    Object.assign(manager, {
        displayMode: 'modal',
        isMobile() { return false; },
        t(_key, fallback) { return fallback; },
    });

    let actions = manager.getContextMenuItems(file, leftState, 'left').map(item => item.action);
    assert.equal(actions.includes('transfer'), false);

    manager.workspace.openTab('right', {
        key: 'ssh:right', type: 'ssh', label: 'Right', sessionId: 'right',
    }, rightState);
    manager.workspace.setLayout('split');
    manager.syncPaneFromWorkspace('left');
    manager.syncPaneFromWorkspace('right');
    actions = manager.getContextMenuItems(file, leftState, 'left').map(item => item.action);
    assert.equal(actions.includes('transfer'), true);
});

test('transfer availability rejects identical connections and unfinished targets', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    manager.workspace.setLayout('split');
    const leftState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'shared',
        loading: false, error: null, path: '/source', selected: new Set([0]),
    };
    const rightState = {
        ...manager.createEmptyPaneState(), type: 'ssh', sessionId: 'shared',
        loading: false, error: null, path: '/target',
    };
    manager.workspace.openTab('left', { type: 'ssh', sessionId: 'shared' }, leftState);
    manager.workspace.openTab('right', { type: 'ssh', sessionId: 'shared' }, rightState);
    manager.panes = { left: leftState, right: rightState };

    assert.equal(manager.canTransferBetweenPanes('left', 'right'), false);

    rightState.sessionId = 'target';
    rightState.loading = true;
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), false);

    rightState.loading = false;
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), true);

    rightState.autoHomeEligible = true;
    rightState.pendingHomeRequestId = 'right:home:1';
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), false);

    rightState.autoHomeEligible = false;
    rightState.pendingHomeRequestId = null;
    assert.equal(manager.canTransferBetweenPanes('left', 'right'), true);
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
                type: 'ssh', path: '/', selected: new Set(),
                files: [{ name: 'readme.txt', is_dir: false, size: 1 }],
            },
        },
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

test('embedded drag and drop uses the existing directory upload path', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    const folder = { isDirectory: true, isFile: false };
    let uploaded;
    Object.assign(manager, {
        displayMode: 'embedded',
        panes: {
            left: { type: 'ssh', sessionId: 'session-a', connectionId: null, path: '/srv' },
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

test('opening the full modal closes embedded mode before restoring dual-pane UI', () => {
    const manager = Object.create(SFTPFileManager.prototype);
    manager.initializeWorkspaceState();
    let closed = 0;
    let shown = 0;
    Object.assign(manager, {
        displayMode: 'embedded', isOpen: true, modal: { style: {}, classList: classList() },
        closeEmbedded() { closed += 1; this.displayMode = 'closed'; this.isOpen = false; },
        updateSessionLists() {}, restoreLastSources() {}, applyTranslations() {},
        loadWorkspaceProfiles() {}, updatePathInput() {}, updatePaneBadge() {}, renderPane() {},
        renderWorkspaceChrome() {}, openSourceLauncher() {},
        isMobile() { return false; }, setActivePane() {}, updateMobilePaneTabs() {},
    });
    global.window.ModalManager = { open() { shown += 1; } };
    global.window.dispatchEvent = () => {};
    const originalGetElementById = global.document.getElementById;
    global.document.getElementById = () => ({ style: {}, classList: classList(), value: '' });

    manager.open();

    assert.equal(closed, 1);
    assert.equal(shown, 1);
    assert.equal(manager.displayMode, 'modal');
    global.document.getElementById = originalGetElementById;
    delete global.window.ModalManager;
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
            left: { type: 'ssh', sessionId: 'mobile-session', connectionId: null, path: '/incoming/reports' },
        },
        getTransferClient: () => ({
            uploadFile(file, remotePath, sessionId) {
                uploadRequests.push({ file, remotePath, sessionId });
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
        { file: files[0], remotePath: '/joined/incoming/reports/first report.txt', sessionId: 'mobile-session' },
        { file: files[1], remotePath: '/joined/incoming/reports/archive.zip', sessionId: 'mobile-session' },
    ]);
    assert.deepEqual(joinCalls, [
        { basePath: '/incoming/reports', filename: 'first report.txt' },
        { basePath: '/incoming/reports', filename: 'archive.zip' },
    ]);
    assert.equal(queued.length, 2);
    assert.equal(queued[0].id, 'mobile-first report.txt');
    assert.equal(queued[0].sessionId, 'mobile-session');
    assert.equal(queued[0].batchId, queued[1].batchId);
    assert.equal(typeof queued[0].batchId, 'string');
    assert.notEqual(queued[0].batchId, '');
    assert.equal(queued[1].id, 'mobile-archive.zip');
    assert.equal(queued[1].sessionId, 'mobile-session');
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
                type: 'ssh', path: '/', selected: new Set(),
                files: [{
                    name: 'quote" onmouseover="globalThis.injected=1',
                    is_dir: false, size: 1, permissions: '-rw-------',
                }],
            },
        },
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
        refreshBothPanes() { refreshes += 1; },
        showNotification() { notifications += 1; },
        t(_key, fallback) { return fallback; },
    });
    manager.setupSocketListeners();

    listeners.directory_created({ path: '/incoming/reports' });
    assert.equal(refreshes, 0);
    assert.equal(notifications, 0);

    manager.uploadBatches.clear();
    listeners.directory_created({ path: '/manual-folder' });
    assert.equal(refreshes, 1);
    assert.equal(notifications, 1);
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
            left: { sessionId: 'batch-session', connectionId: null },
            right: { sessionId: 'other-session', connectionId: null },
        },
        renderTransferQueue() {},
        processTransferQueue() {},
        showUploadProgress() {},
        showUploadComplete() {},
        createTransferClient: () => client,
        refreshPane(pane) { refreshed.push(pane); },
    });
    manager.getTransferClient();
    const batch = manager.startUploadBatch(3, 'batch-session');
    manager.queueTransfer({ id: 'done', type: 'upload', sessionId: 'batch-session', batchId: batch.id });
    manager.queueTransfer({ id: 'failed', type: 'upload', sessionId: 'batch-session', batchId: batch.id });
    manager.queueTransfer({ id: 'cancelled', type: 'upload', sessionId: 'batch-session', batchId: batch.id });

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
    const destinationState = {
        ...manager.createEmptyPaneState(),
        type: 'ssh',
        sessionId: 'upload-session',
        path: '/srv/upload',
    };
    manager.workspace.openTab('left', {
        key: 'ssh:upload-session', type: 'ssh', label: 'Upload', sessionId: 'upload-session',
    }, destinationState);
    manager.workspace.openTab('left', {
        key: 'ssh:other-session', type: 'ssh', label: 'Other', sessionId: 'other-session',
    }, {
        ...manager.createEmptyPaneState(),
        type: 'ssh',
        sessionId: 'other-session',
        path: '/srv/other',
    });
    manager.syncPaneFromWorkspace('left');
    Object.assign(manager, {
        displayMode: 'modal',
        isOpen: true,
        requestSequence: 0,
        socket: { emit(event, payload) { emitted.push({ event, payload }); } },
        showUploadProgress() {},
        showUploadComplete() {},
    });

    const batch = manager.startUploadBatch(1, 'upload-session', destinationState);
    manager.recordUploadTerminal({
        type: 'upload',
        sessionId: 'upload-session',
        batchId: batch.id,
    }, 'complete');
    await Promise.resolve();
    await Promise.resolve();

    assert.equal(manager.workspace.getActiveTab('left').paneState.path, '/srv/other');
    assert.deepEqual(emitted, [{
        event: 'list_directory',
        payload: {
            session_id: 'upload-session',
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
    const destinationState = {
        ...manager.createEmptyPaneState(),
        type: 'ssh',
        sessionId: 'upload-session',
        path: '/srv/upload',
        files: [{ name: 'old.txt' }],
    };
    manager.workspace.openTab('left', {
        key: 'ssh:upload-session', type: 'ssh', label: 'Upload', sessionId: 'upload-session',
    }, destinationState);
    manager.workspace.openTab('left', {
        key: 'ssh:other-session', type: 'ssh', label: 'Other', sessionId: 'other-session',
    }, {
        ...manager.createEmptyPaneState(),
        type: 'ssh',
        sessionId: 'other-session',
        path: '/srv/other',
    });
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

    const batch = manager.startUploadBatch(1, 'upload-session', destinationState);
    manager.recordUploadTerminal({
        type: 'upload',
        sessionId: 'upload-session',
        batchId: batch.id,
    }, 'complete');
    await Promise.resolve();
    await Promise.resolve();

    assert.deepEqual(emitted, [{
        event: 'list_directory',
        payload: {
            session_id: 'upload-session',
            remote_path: '/srv/upload',
            request_id: 'left:directory:1',
        },
    }]);

    listeners.directory_listing({
        session_id: 'upload-session',
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
        uploadSingleFileToSSH(file, basePath, sessionId, batchId) {
            uploaded.push({ name: file.name, basePath, sessionId, batchId });
        },
    });

    await manager.uploadDesktopItemsToSSH(
        [directory],
        { sessionId: 'paged-session', path: '/incoming' },
    );

    assert.equal(batchTotal, 2);
    assert.deepEqual(uploaded.map(item => item.name), ['first.txt', 'second.txt']);
    assert.equal(uploaded.every(item => item.batchId === 'paged-batch'), true);
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
    assert.deepEqual(listeners, ['progress', 'complete', 'error', 'cancel']);
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
            downloadFolder(path, sessionId) {
                requested = { path, sessionId };
                return 'folder-local-id';
            },
        }),
        queueTransfer(transfer) { queued = transfer; },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    manager.downloadFolderToBrowser('session', '/remote/reports', 'reports');

    assert.deepEqual(requested, { path: '/remote/reports', sessionId: 'session' });
    assert.equal(queued.id, 'folder-local-id');
    assert.equal(socketEvents.includes('download_folder_binary'), false);
});

test('server copies queue the server-owned cancellable transfer id', async () => {
    let request;
    let queued;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit(event, payload, ack) {
            request = { event, payload };
            ack({ success: true, transfer_id: 'server-transfer-id' });
        } },
        queueTransfer(transfer) { queued = transfer; },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    const terminal = manager.transferSSHtoSSH(
        '/source/file.bin', { sessionId: 'source-session' },
        '/target/file.bin', { sessionId: 'target-session' },
        { name: 'file.bin', is_dir: false, size: 10 },
    );
    await Promise.resolve();

    assert.equal(request.event, 'transfer_server_to_server');
    assert.equal(request.payload.transfer_id, undefined);
    assert.equal(queued.id, 'server-transfer-id');
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
                type: 'ssh', sessionId: 'source-session', path: '/source',
                files: [
                    { name: 'first.bin', is_dir: false, size: 1 },
                    { name: 'second.bin', is_dir: false, size: 2 },
                    { name: 'third.bin', is_dir: false, size: 3 },
                ],
                selected: new Set([0, 1, 2]),
            },
            right: {
                type: 'ssh', sessionId: 'target-session', path: '/target',
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
                acknowledgement({ success: true, transfer_id: id });
            },
        },
        renderTransferQueue() {},
        processTransferQueue: SFTPFileManager.prototype.processTransferQueue,
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });
    manager.workspace.openTab('left', {
        type: 'ssh', sessionId: 'source-session',
    }, manager.panes.left);
    manager.workspace.openTab('right', {
        type: 'ssh', sessionId: 'target-session',
    }, manager.panes.right);
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

    manager.failS2STransfer({ transfer_id: 'server-2', error: 'failed' });
    await flushAsync();
    assert.deepEqual(requests.map(request => request.sourcePath), [
        '/source/first.bin', '/source/second.bin', '/source/third.bin',
    ]);

    manager.cancelTransferById('server-3');
    await execution;
    assert.deepEqual(manager.transferQueue.map(transfer => transfer.status), [
        'complete', 'error', 'cancelled',
    ]);
});

test('an S2S terminal event received before its acknowledgement cannot strand the selection', async () => {
    let manager;
    manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        transferQueue: [],
        activeTransfers: new Map(),
        isTransferring: false,
        socket: {
            emit(_event, _payload, acknowledgement) {
                manager.completeS2STransfer({ transfer_id: 'fast-transfer' });
                acknowledgement({ success: true, transfer_id: 'fast-transfer' });
            },
        },
        renderTransferQueue() {},
        processTransferQueue() {},
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    let settled = false;
    const transfer = manager.transferSSHtoSSH(
        '/source/fast.bin', { sessionId: 'source-session' },
        '/target/fast.bin', { sessionId: 'target-session' },
        { name: 'fast.bin', is_dir: false, size: 1 },
    ).then(() => { settled = true; });
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(settled, true);
    assert.equal(manager.transferQueue[0].status, 'complete');
    await transfer;
});

test('server copy cancellation calls the server lifecycle and updates the queue', () => {
    let request;
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        socket: { emit(event, payload, ack) {
            request = { event, payload };
            ack({ success: true });
        } },
        transferQueue: [{ id: 's2s-id', type: 's2s', status: 'active' }],
        activeTransfers: new Map([['s2s-id', {}]]),
        isTransferring: true,
        renderTransferQueue() {},
        processTransferQueue() {},
    });

    manager.cancelQueuedTransfer('s2s-id');

    assert.deepEqual(request, {
        event: 'cancel_transfer', payload: { transfer_id: 's2s-id' },
    });
    assert.equal(manager.transferQueue[0].status, 'cancelled');
    assert.equal(manager.isTransferring, false);
});
