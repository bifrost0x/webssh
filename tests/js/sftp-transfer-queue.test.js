const assert = require('node:assert/strict');
const test = require('node:test');

global.window = {};
global.document = { getElementById: () => null };
require('../../static/js/sftp-file-manager.js');
const SFTPFileManager = global.window.SFTPFileManager;

function classList() {
    const values = new Set();
    return {
        add(...names) { names.forEach(name => values.add(name)); },
        remove(...names) { names.forEach(name => values.delete(name)); },
        contains(name) { return values.has(name); },
    };
}

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
    let closed = 0;
    let shown = 0;
    Object.assign(manager, {
        displayMode: 'embedded', isOpen: true, modal: { style: {}, classList: classList() },
        closeEmbedded() { closed += 1; this.displayMode = 'closed'; this.isOpen = false; },
        updateSessionLists() {}, restoreLastSources() {}, applyTranslations() {},
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

test('browser file upload queues the returned id and file size without buffering', async () => {
    const file = { name: 'large.bin', size: 987654 };
    let uploaded;
    let queued;
    const manager = Object.create(SFTPFileManager.prototype);
    manager.getTransferClient = () => ({
        uploadFile(value) {
            uploaded = value;
            return 'local-upload-id';
        },
    });
    manager.queueTransfer = transfer => { queued = transfer; };
    manager.showNotification = () => assert.fail('file read was reported as failed');

    await manager.transferBrowserToSSH(
        { name: file.name, is_dir: false, handle: { getFile: async () => file } },
        '/remote/large.bin',
        { sessionId: 'session' },
    );

    assert.equal(uploaded, file);
    assert.equal(queued.id, 'local-upload-id');
    assert.equal(queued.size, file.size);
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
        browserFS: { pathStack: [] },
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

test('SSH pane transfer streams into the selected browser directory and refreshes it', async () => {
    const targetDirectory = { name: 'selected-target' };
    const writable = { kind: 'writable' };
    let sinkRequest;
    let downloadRequest;
    let queued;
    const refreshed = [];
    const manager = Object.create(SFTPFileManager.prototype);
    Object.assign(manager, {
        activePane: 'left',
        panes: {
            left: {
                type: 'ssh', sessionId: 'ssh-session', connectionId: null,
                path: '/remote', files: [{ name: 'report.bin', is_dir: false, size: 12 }],
                selected: new Set([0]),
            },
            right: {
                type: 'browser-local', path: '/chosen', files: [],
                selected: new Set(),
            },
        },
        browserFS: {
            currentHandle: targetDirectory,
            async createWritableSink(name, directory) {
                sinkRequest = { name, directory };
                return writable;
            },
        },
        getTransferClient: () => ({
            downloadFileToWritable(path, sessionId, sinkFactory) {
                downloadRequest = { path, sessionId, sinkFactory };
                return { id: 'pane-local-id', done: Promise.resolve(true) };
            },
        }),
        queueTransfer(transfer) { queued = transfer; },
        async refreshBrowserPane(pane) { refreshed.push(pane); },
        showNotification() {},
        t(_key, fallback) { return fallback; },
    });

    await manager.executeTransfer();
    const sink = await downloadRequest.sinkFactory();

    assert.deepEqual(downloadRequest, {
        path: '/remote/report.bin',
        sessionId: 'ssh-session',
        sinkFactory: downloadRequest.sinkFactory,
    });
    assert.deepEqual(sinkRequest, {
        name: 'report.bin',
        directory: targetDirectory,
    });
    assert.equal(sink, writable);
    assert.equal(queued.id, 'pane-local-id');
    assert.deepEqual(refreshed, ['right']);
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
