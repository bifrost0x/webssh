const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
global.window = {};
const { validLeaf, validMode, FileMutationDialog } = require('../../static/js/file-mutation-dialog.js');

test('mode mismatch displays confirmed actual permissions and blocks retry', () => {
    for (const actual of ['640', 'u+x']) {
        const dialog = Object.create(FileMutationDialog.prototype);
        Object.assign(dialog, { pendingId: 'r', mode: { value: '777' }, status: {},
            syncChecks() { this.checkedMode = this.mode.value; }, update() {},
            manager: { t: (_, fallback) => fallback } });
        dialog.receive({ request_id: 'r', code: 'MODE_MISMATCH', actual_mode: actual, error: 'Permissions differ.' }, 'set_file_permissions', true);
        assert.equal(dialog.uncertain, true);
        assert.equal(dialog.mode.value, actual === '640' ? '640' : '777');
        if (actual === '640') {
            assert.equal(dialog.checkedMode, '640');
            assert.match(dialog.status.textContent, /640/);
        }
    }
});

test('file names are one bounded UTF-8 leaf and mode is exact ASCII octal', () => {
    for (const name of ['', '.', '..', 'a/b', 'a\\b', '\0', 'a\n', '\ud800', 'é'.repeat(128)]) assert.equal(validLeaf(name), false, name);
    for (const name of ['.env', '-script', 'a b', 'Überblick.txt', 'é'.repeat(127)]) assert.equal(validLeaf(name), true);
    for (const mode of ['600', '000', '777']) assert.equal(validMode(mode), true);
    for (const mode of [600, true, '0600', '888', 'u+x', '600\n', '６００']) assert.equal(validMode(mode), false);
});

test('a dialog cannot follow pane navigation, source replacement, or a closed workspace', () => {
    const state = { path: '/one', mutationViewVersion: 1, sourceId: 'sftp-session:a' };
    const dialog = Object.create(FileMutationDialog.prototype);
    dialog.target = { pane: 'left', state, sourceId: state.sourceId, parent: state.path, version: 1 };
    dialog.manager = { panes: { left: state }, isOpen: true, getPaneSourceId: value => value.sourceId };
    assert.equal(dialog.isCurrent(), true);
    state.path = '/two';
    assert.equal(dialog.isCurrent(), false);
    state.path = '/one';
    state.mutationViewVersion++;
    assert.equal(dialog.isCurrent(), false);
    state.mutationViewVersion = 1;
    state.sourceId = 'sftp-session:b';
    assert.equal(dialog.isCurrent(), false);
    state.sourceId = 'sftp-session:a';
    dialog.manager.isOpen = false;
    assert.equal(dialog.isCurrent(), false);
});

test('mutation response requires the pending source, request and operation', () => {
    const received = [];
    const pending = { sourceId: 'sftp-session:a', operation: 'create_file', mutationDialog: { receive: (...args) => received.push(args) } };
    const manager = { pendingOperationRequests: new Map([['r', pending]]), consumeOperationResponse: () => manager.pendingOperationRequests.delete('r') };
    assert.equal(FileMutationDialog.handle(manager, { request_id: 'r', source_id: 'sftp-session:b' }, 'create_file'), false);
    assert.equal(FileMutationDialog.handle(manager, { request_id: 'r', source_id: 'sftp-session:a' }, 'set_file_permissions'), false);
    assert.equal(received.length, 0);
    assert.equal(FileMutationDialog.handle(manager, { request_id: 'r', source_id: 'sftp-session:a' }, 'create_file'), true);
    assert.equal(received.length, 1);
    assert.equal(FileMutationDialog.handle(manager, { request_id: 'r', source_id: 'sftp-session:a' }, 'create_file'), false);
});

function signedFixture(snapshot = {}, stamp = 100) {
    return `${stamp}.${createHash('sha256').update(JSON.stringify(snapshot)).digest('hex')}.${'c'.repeat(64)}`;
}

function recheckDialog(snapshots = [{ mode: '600', path: '/a' }, { mode: '600', path: '/b' }]) {
    const dialog = Object.create(FileMutationDialog.prototype);
    const sent = [];
    Object.assign(dialog, {
        batch: true, batchPhase: 'applying', batchIndex: 0,
        targets: snapshots.map(snapshot => ({ path: snapshot.path, metadataToken: signedFixture(snapshot),
            metadataFingerprint: signedFixture(snapshot).split('.')[1], originalMode: snapshot.mode, outcome: 'inspected' })),
        applyMode: '640', closed: false, isCurrent: () => true,
        send: (operation, fields) => sent.push({ operation, fields }),
        renderBatch() {}, update() {}, syncChecks() {}, status: {}, mode: { value: '640' },
        manager: { t: (_, fallback) => fallback, refreshSource() {}, socket: { connected: true } }, target: { sourceId: 'sftp:a' },
    });
    return { dialog, sent };
}

function metadata(snapshot, stamp = 200) {
    return { mode: snapshot.mode, object_type: 'file', special_bits: 0, metadata_token: signedFixture(snapshot, stamp) };
}

test('bulk permissions recheck each fingerprint, use the fresh token and stop on server conflict', () => {
    const snapshot = { mode: '600', path: '/a' };
    const { dialog, sent } = recheckDialog();
    dialog.advanceBatch();
    assert.deepEqual(sent, [{ operation: 'get_file_permissions', fields: { path: '/a' } }]);
    dialog.receiveBatch(metadata(snapshot), 'get_file_permissions', false);
    assert.deepEqual(sent[1], { operation: 'set_file_permissions', fields: { path: '/a', mode: '640', expected_metadata: signedFixture(snapshot, 200) } });
    assert.notEqual(sent[1].fields.expected_metadata, dialog.targets[0].metadataToken);
    dialog.pendingId = 'r';
    dialog.receive({ request_id: 'r', code: 'METADATA_CHANGED', error: 'Changed.' }, 'set_file_permissions', true);
    assert.equal(sent.length, 2);
    assert.equal(dialog.targets[0].outcome, 'failed');
    assert.equal(dialog.targets[1].outcome, 'not-sent');
    assert.equal(dialog.batchPhase, 'stopped');
});

test('bulk permissions never continue after closing or a stale directory', () => {
    for (const reason of ['closed', 'stale']) {
        const dialog = Object.create(FileMutationDialog.prototype);
        Object.assign(dialog, { batch: true, batchPhase: 'applying', batchIndex: 0,
            targets: [{ path: '/a', outcome: 'pending' }], closed: reason === 'closed',
            isCurrent: () => reason !== 'stale', send() { assert.fail('sent after invalidation'); },
            renderBatch() {}, update() {}, status: {}, manager: { t: (_, fallback) => fallback, refreshSource() {} }, target: {} });
        dialog.advanceBatch();
        assert.equal(dialog.targets[0].outcome, 'not-sent');
    }
});

test('a stopped in-flight write remains unknown until its correlated result', () => {
    const dialog = Object.create(FileMutationDialog.prototype);
    let refreshed = 0;
    Object.assign(dialog, { batch: true, batchPhase: 'applying', batchIndex: 0, pending: true,
        targets: [{ path: '/a', outcome: 'in-flight' }, { path: '/b', outcome: 'inspected' }],
        batchStarted: true, target: { sourceId: 'sftp:a' }, closed: false,
        renderBatch() {}, update() {}, status: {},
        manager: { t: (_, fallback) => fallback, refreshSource: () => refreshed++ },
    });
    dialog.stopBatch('stop', 'Stopped');
    assert.equal(dialog.targets[0].outcome, 'unknown');
    assert.equal(dialog.targets[1].outcome, 'not-sent');
    assert.equal(refreshed, 0);
    dialog.pending = false;
    dialog.receiveBatch({}, 'set_file_permissions', false);
    assert.equal(dialog.targets[0].outcome, 'completed');
    assert.equal(refreshed, 1);
});

test('bulk completion freshly inspects skipped targets and refreshes once', () => {
    const snapshots = [{ path: '/a', mode: '600' }, { path: '/b', mode: '750' }];
    const { dialog, sent } = recheckDialog(snapshots);
    let refreshed = 0;
    dialog.manager.refreshSource = () => refreshed++;
    dialog.applyMode = '750';
    dialog.advanceBatch();
    dialog.receiveBatch(metadata(snapshots[0]), 'get_file_permissions', false);
    dialog.receiveBatch({}, 'set_file_permissions', false);
    assert.equal(sent.length, 3);
    assert.deepEqual(sent[2], { operation: 'get_file_permissions', fields: { path: '/b' } });
    dialog.receiveBatch(metadata(snapshots[1]), 'get_file_permissions', false);
    assert.equal(sent.length, 3);
    assert.deepEqual(dialog.targets.map(item => item.outcome), ['completed', 'unchanged']);
    assert.equal(dialog.batchPhase, 'done');
    assert.equal(refreshed, 1);
    dialog.refreshBatch();
    assert.equal(refreshed, 1);
});

test('bulk timeout marks only the sent item unknown and never starts another request', () => {
    const originalSetTimeout = global.setTimeout;
    let expire;
    global.setTimeout = fn => { expire = fn; return 1; };
    try {
        const dialog = Object.create(FileMutationDialog.prototype);
        const sent = [];
        const pending = new Map();
        Object.assign(dialog, { batch: true, batchPhase: 'applying', batchIndex: 0,
            targets: [{ path: '/a', outcome: 'in-flight' }, { path: '/b', outcome: 'inspected' }],
            closed: false, isCurrent: () => true, renderBatch() {}, update() {}, status: {}, target: { sourceId: 'a' },
            manager: { t: (_, fallback) => fallback, pendingOperationRequests: pending,
                registerOperationRequest: () => { pending.set('r', {}); return 'r'; },
                socket: { connected: true, emit: (...args) => sent.push(args) }, refreshSource() {} },
        });
        dialog.send('set_file_permissions', { path: '/a', expected_metadata: 'old-token', mode: '640' });
        expire();
        assert.deepEqual(dialog.targets.map(item => item.outcome), ['unknown', 'not-sent']);
        assert.equal(dialog.batchPhase, 'stopped');
        assert.equal(dialog.uncertain, true);
        assert.equal(sent.length, 1);
        assert.equal(pending.size, 0);
    } finally { global.setTimeout = originalSetTimeout; }
});

test('closed initial inspection cannot start a write or inspect another target', () => {
    const dialog = Object.create(FileMutationDialog.prototype);
    Object.assign(dialog, { batch: true, batchPhase: 'stopped', batchIndex: 0, closed: true,
        targets: [{ path: '/a', outcome: 'not-sent' }, { path: '/b', outcome: 'not-sent' }],
        send() { assert.fail('sent after close'); } });
    dialog.receiveBatch({ mode: '600', special_bits: 0, object_type: 'file', metadata_token: 'old-token' }, 'get_file_permissions', false);
    assert.deepEqual(dialog.targets.map(item => item.outcome), ['not-sent', 'not-sent']);
});

test('special bits, symlinks and failed initial inspection cannot enable writes', () => {
    for (const value of [{ special_bits: 0o1000, object_type: 'file' }, { special_bits: 0, object_type: 'symlink' }, { special_bits: 0, object_type: 'file', mode: '7777' }]) {
        const dialog = Object.create(FileMutationDialog.prototype);
        Object.assign(dialog, { batch: true, batchPhase: 'inspecting', batchIndex: 0, closed: false, isCurrent: () => true,
            targets: [{ path: '/a', outcome: 'pending' }, { path: '/b', outcome: 'pending' }],
            send() { assert.fail('sent after unsupported metadata'); }, renderBatch() {}, update() {}, status: {},
            manager: { t: (_, fallback) => fallback }, target: {},
        });
        dialog.receiveBatch({ mode: '600', metadata_token: signedFixture({}), ...value }, 'get_file_permissions', false);
        assert.equal(dialog.batchPhase, 'stopped');
        assert.deepEqual(dialog.targets.map(item => item.outcome), ['failed', 'not-sent']);
    }
});


test('every full snapshot or binding digest change stops before SET even with the same visible mode', () => {
    const original = { mode: '600', uid: 7, gid: 8, type: 'file', modified: 123, size: '9007199254740993', user: 1, path: '/a', source: 'sftp:a' };
    for (const key of Object.keys(original)) {
        const { dialog, sent } = recheckDialog([original, { mode: '600', path: '/b' }]);
        dialog.advanceBatch();
        dialog.receiveBatch({ ...metadata({ ...original, [key]: `changed-${key}` }), mode: '600' }, 'get_file_permissions', false);
        assert.equal(sent.length, 1, key);
        assert.equal(dialog.batchPhase, 'stopped', key);
        assert.deepEqual(dialog.targets.map(item => item.outcome), ['failed', 'not-sent'], key);
        assert.match(dialog.targets[0].error, /metadata changed/i);
    }
});

test('malformed or missing metadata tokens fail closed in initial and fresh inspection', () => {
    for (const token of [null, undefined, '', 'token', signedFixture({}, 1) + '\n', signedFixture({}).toUpperCase(), `1.${'a'.repeat(63)}.${'b'.repeat(64)}`]) {
        for (const phase of ['inspecting', 'applying']) {
            const { dialog, sent } = recheckDialog();
            dialog.batchPhase = phase;
            dialog.receiveBatch({ mode: '600', object_type: 'file', special_bits: 0, metadata_token: token }, 'get_file_permissions', false);
            assert.equal(dialog.batchPhase, 'stopped', `${phase}:${token}`);
            assert.equal(sent.length, 0);
        }
    }
});

test('recheck answers cannot write after closing, staleness, disconnect or an explicit stop', () => {
    for (const reason of ['closed', 'stale', 'disconnect', 'stopped']) {
        const { dialog, sent } = recheckDialog();
        dialog.advanceBatch();
        if (reason === 'closed') dialog.closed = true;
        if (reason === 'stale') dialog.isCurrent = () => false;
        if (reason === 'disconnect') dialog.manager.socket.connected = false;
        if (reason === 'stopped') dialog.stopBatch('stop', 'Stopped');
        dialog.receiveBatch(metadata({ mode: '600', path: '/a' }), 'get_file_permissions', false);
        assert.equal(sent.length, 1, reason);
        assert.equal(dialog.batchPhase, 'stopped', reason);
    }
});

test('GET timeout cannot claim an unknown chmod outcome, including after close or disconnect', () => {
    const originalSetTimeout = global.setTimeout;
    let expire;
    global.setTimeout = fn => { expire = fn; return 1; };
    try {
        for (const stopped of [false, true]) {
            const { dialog } = recheckDialog();
            dialog.manager.pendingOperationRequests = new Map();
            dialog.manager.registerOperationRequest = () => { dialog.manager.pendingOperationRequests.set('r', {}); return 'r'; };
            dialog.manager.socket.emit = () => {};
            dialog.send = FileMutationDialog.prototype.send;
            dialog.send('get_file_permissions', { path: '/a' });
            if (stopped) dialog.stopBatch('stop', 'Stopped');
            expire();
            assert.equal(dialog.targets[0].outcome, stopped ? 'not-sent' : 'failed');
            assert.equal(dialog.targets[1].outcome, 'not-sent');
            assert.equal(dialog.uncertain, false);
            assert.equal(dialog.batchPhase, 'stopped');
        }
    } finally { global.setTimeout = originalSetTimeout; }
});

test('late inspection after a completed write and close or disconnect refreshes once without another SET', () => {
    for (const reason of ['closed', 'disconnect']) {
        const { dialog, sent } = recheckDialog();
        let refreshed = 0;
        dialog.manager.refreshSource = () => refreshed++;
        dialog.batchStarted = true;
        dialog.targets[0].outcome = 'completed';
        dialog.batchIndex = 1;
        dialog.pending = true;
        dialog.pendingId = 'late-get';
        dialog.stopBatch('stop', 'Stopped');
        if (reason === 'closed') dialog.closed = true;
        else dialog.manager.socket.connected = false;
        assert.equal(refreshed, 0);
        dialog.receive({ ...metadata({ mode: '600', path: '/b' }), request_id: 'late-get' }, 'get_file_permissions', false);
        assert.equal(refreshed, 1, reason);
        assert.equal(sent.length, 0, reason);
        dialog.refreshBatch();
        assert.equal(refreshed, 1, reason);
    }
});

function dialogFixture({ directory = false, file = null, kind = 'sftp' } = {}) {
    const previousDocument = global.document;
    class Node {
        constructor() { this.nodes = new Map(); this.children = []; this.value = ''; this.checked = false; this.disabled = false; }
        querySelector(selector) { if (!this.nodes.has(selector)) this.nodes.set(selector, new Node()); return this.nodes.get(selector); }
        querySelectorAll() { return this.children.flatMap(child => child.children || []).filter(child => child.type === 'checkbox'); }
        append(...nodes) { this.children.push(...nodes); }
        appendChild(node) { this.children.push(node); }
        setAttribute() {}
        addEventListener() {}
        showModal() {}
        focus() {}
        close() {}
        remove() {}
    }
    global.document = { activeElement: null, body: new Node(), createElement: () => { const node = new Node(); node.dataset = {}; return node; }, createTextNode: text => ({ textContent: text }) };
    const state = { path: '/parent', source: { sourceId: `${kind}:one`, label: 'Source' } };
    const emitted = [];
    const manager = { panes: { left: state }, getPaneSourceId: value => value.source.sourceId, joinPath: (parent, name) => `${parent}/${name}`,
        t: (_, fallback) => fallback, sourceCan: () => true, pendingOperationRequests: new Map(),
        registerOperationRequest(sourceId, operation) { const id = `r${this.pendingOperationRequests.size}`; this.pendingOperationRequests.set(id, { sourceId, operation }); return id; },
        socket: { connected: true, on() {}, off() {}, emit: (...args) => emitted.push(args) }, refreshSource() {}, showNotification() {} };
    let dialog;
    try { dialog = new FileMutationDialog(manager, 'left', file, { createDirectory: directory }); }
    finally { global.document = previousDocument; }
    return { dialog, manager, state, emitted };
}

test('folder dialog sends the existing mkdir contract once for SFTP and SMB and retains failed draft', () => {
    for (const kind of ['sftp', 'smb']) {
        const { dialog, emitted, manager } = dialogFixture({ directory: true, kind });
        assert.equal(dialog.dialog.querySelector('h3').textContent, 'New Folder');
        assert.equal(dialog.dialog.querySelector('.fm-mutation-edit').hidden, true);
        dialog.name.value = 'Reports';
        dialog.submit();
        dialog.submit();
        assert.equal(emitted.length, 1);
        assert.deepEqual(emitted[0], ['create_directory', { source_id: `${kind}:one`, request_id: 'r0', remote_path: '/parent/Reports' }]);
        dialog.receive({ request_id: 'r0', error: 'Failed to create directory: File or directory already exists' }, 'create_directory', true);
        assert.equal(dialog.name.value, 'Reports');
        assert.equal(dialog.status.textContent, 'An item with this name already exists.');
        assert.equal(dialog.button.disabled, false);
        dialog.close();
        assert.equal(manager.pendingOperationRequests.size, 1);
    }
});

test('folder submit rejects invalid leaves and a revoked mkdir capability', () => {
    const { dialog, manager, emitted } = dialogFixture({ directory: true });
    for (const name of ['', '.', '..', 'a/b', 'a\\b', 'a\n', 'é'.repeat(128)]) { dialog.name.value = name; dialog.submit(); }
    dialog.name.value = 'valid';
    manager.sourceCan = () => false;
    dialog.submit();
    assert.equal(dialog.button.disabled, true);
    assert.deepEqual(emitted, []);
    dialog.close();
});

test('folder submit remains bound to its original pane directory and navigation version', () => {
    for (const change of [state => { state.path = '/other'; }, state => { state.mutationViewVersion = 1; }, state => { state.source.sourceId = 'smb:other'; }]) {
        const { dialog, state, emitted } = dialogFixture({ directory: true });
        dialog.name.value = 'Draft';
        change(state);
        dialog.submit();
        assert.deepEqual(emitted, []);
        assert.equal(dialog.name.value, 'Draft');
        dialog.close();
    }
});

test('folder permission inspection explicitly explains nonrecursive changes and traverse', () => {
    const { dialog, emitted } = dialogFixture({ file: { name: 'folder', is_dir: true } });
    dialog.receive({ request_id: 'r0', mode: '750', special_bits: 0, object_type: 'directory', metadata_token: signedFixture({}) }, 'get_file_permissions', false);
    assert.match(dialog.dialog.querySelector('.fm-mutation-scope').textContent, /Only this folder.*files and subfolders.*not changed/i);
    assert.match(dialog.dialog.querySelector('.fm-mutation-hint').textContent, /traverse.*contents.*unchanged/i);
    assert.equal(emitted.length, 1);
    dialog.close();
});

test('folder errors use localized safe reasons and never expose unexpected backend detail', () => {
    for (const [error, expected] of [
        ['Failed to create directory: Permission denied', 'Permission denied. Choose a directory where you can create folders.'],
        ['Failed to create directory: File or directory already exists', 'An item with this name already exists.'],
        ['Backend failure /private/server/path token=secret', 'The folder could not be created. Check the source connection and try again.'],
    ]) {
        const { dialog } = dialogFixture({ directory: true });
        dialog.name.value = 'Draft';
        dialog.pendingId = 'failed';
        dialog.receive({ request_id: 'failed', error }, 'create_directory', true);
        assert.equal(dialog.status.textContent, expected);
        assert.equal(dialog.name.value, 'Draft');
        dialog.close();
    }
});

test('folder success restores the created name without opening the editor', () => {
    const { dialog, manager, state } = dialogFixture({ directory: true });
    const refreshed = [];
    const notices = [];
    manager.refreshSource = sourceId => refreshed.push(sourceId);
    manager.showNotification = (...args) => notices.push(args);
    window.FilePreview = { openForEditing() { assert.fail('folder opened in editor'); } };
    dialog.name.value = 'New folder';
    dialog.submit();
    dialog.receive({ request_id: 'r0', path: '/parent/New folder' }, 'create_directory', false);
    assert.equal(dialog.closed, true);
    assert.equal(state.restoreFocusName, 'New folder');
    assert.deepEqual(refreshed, ['sftp:one']);
    assert.deepEqual(notices, [['Folder created', 'success']]);
    delete window.FilePreview;
});

test('file creation keeps its separate request and opt-in editor behavior', () => {
    const { dialog, manager, emitted } = dialogFixture();
    const edited = [];
    manager.refreshSource = () => {};
    window.FilePreview = { openForEditing: (...args) => edited.push(args) };
    dialog.name.value = 'notes.txt';
    dialog.dialog.querySelector('[name="edit"]').checked = true;
    dialog.submit();
    assert.deepEqual(emitted, [['create_file', { source_id: 'sftp:one', request_id: 'r0', parent_path: '/parent', name: 'notes.txt' }]]);
    dialog.receive({ request_id: 'r0', path: '/parent/notes.txt' }, 'create_file', false);
    assert.deepEqual(edited, [['sftp:one', '/parent/notes.txt', 'notes.txt']]);
    delete window.FilePreview;
});

test('directory_created routes correlated dialog results before legacy upload refresh handling', () => {
    require('../../static/js/file-directory-requests.js');
    require('../../static/js/sftp-file-manager.js');
    const manager = Object.create(window.SFTPFileManager.prototype);
    const listeners = {};
    const received = [];
    Object.assign(manager, {
        socket: { on(event, callback) { listeners[event] = callback; } },
        uploadBatches: new Map([['batch', {}]]),
        pendingOperationRequests: new Map([['mkdir', { sourceId: 'smb:one', operation: 'create_directory', mutationDialog: { receive: (...args) => received.push(args) } }]]),
        refreshSource() { assert.fail('legacy refresh should not handle dialog result'); },
    });
    manager.setupSocketListeners();
    const response = { source_id: 'smb:one', request_id: 'mkdir', path: '/new' };
    listeners.directory_created({ ...response, source_id: 'smb:wrong' });
    assert.equal(received.length, 0);
    listeners.directory_created(response);
    assert.deepEqual(received, [[response, 'create_directory', false]]);
    assert.equal(manager.pendingOperationRequests.size, 0);
});
