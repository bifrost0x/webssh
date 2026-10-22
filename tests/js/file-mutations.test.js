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
