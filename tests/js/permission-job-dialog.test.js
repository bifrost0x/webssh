const test = require('node:test');
const assert = require('node:assert/strict');
global.window = {};
const { PermissionJobDialog, validMode, dangerousModes } = require('../../static/js/permission-job-dialog.js');

test('permission modes are exact three ASCII octal digits and owner lockout is explicit', () => {
    for (const mode of ['644', '755', '000']) assert.equal(validMode(mode), true);
    for (const mode of ['0755', '755\n', 755, 'u+x', '８００']) assert.equal(validMode(mode), false);
    assert.equal(dangerousModes('644', '755'), false);
    assert.equal(dangerousModes('400', '755'), true);
    assert.equal(dangerousModes('644', '600'), true);
});

test('permissions responses require request, source and operation identity', () => {
    const received = [];
    const manager = { pendingOperationRequests: new Map([['r', { sourceId: 'sftp:a', operation: 'prepare_file_permissions', permissionJobDialog: { receive: value => received.push(value) } }]]), consumeOperationResponse(data) { this.pendingOperationRequests.delete(data.request_id); } };
    for (const data of [{ request_id: 'r', source_id: 'sftp:b', operation: 'prepare_file_permissions' }, { request_id: 'r', source_id: 'sftp:a', operation: 'apply_file_permissions_job' }]) assert.equal(PermissionJobDialog.handle(manager, data), false);
    assert.equal(received.length, 0);
    assert.equal(PermissionJobDialog.handle(manager, { request_id: 'r', source_id: 'sftp:a', operation: 'prepare_file_permissions' }), true);
    assert.equal(received.length, 1);
});

test('immutable permissions plan can apply only once and only while the bound view is current', () => {
    const sent = [];
    const dialog = Object.create(PermissionJobDialog.prototype);
    Object.assign(dialog, { state: 'ready', pending: false, jobId: 'job', closed: false, isCurrent: () => true, status: {}, manager: { t: (_, fallback) => fallback }, plan: { file_mode: '644', directory_mode: '755' }, acknowledgment: { checked: false }, send: (...args) => sent.push(args), update() {} });
    dialog.apply();
    dialog.apply();
    assert.deepEqual(sent, [['apply_file_permissions_job', { job_id: 'job' }]]);
    dialog.state = 'ready';
    dialog.isCurrent = () => false;
    dialog.apply();
    assert.equal(sent.length, 1);
    dialog.isCurrent = () => true;
    dialog.plan.file_mode = '000';
    dialog.apply();
    assert.equal(sent.length, 1);
});

test('permission jobs cannot follow source replacement, navigation or closed manager', () => {
    const state = { path: '/one', mutationViewVersion: 1, sourceId: 'sftp:a' };
    const dialog = Object.create(PermissionJobDialog.prototype);
    dialog.target = { pane: 'left', state, sourceId: 'sftp:a', parent: '/one', version: 1 };
    dialog.manager = { panes: { left: state }, isOpen: true, getPaneSourceId: value => value.sourceId };
    assert.equal(dialog.isCurrent(), true);
    state.path = '/other'; assert.equal(dialog.isCurrent(), false);
    state.path = '/one'; state.mutationViewVersion++; assert.equal(dialog.isCurrent(), false);
    state.mutationViewVersion = 1; state.sourceId = 'sftp:b'; assert.equal(dialog.isCurrent(), false);
});

test('ready plans expire locally without applying or changing their target modes', () => {
    const dialog = Object.create(PermissionJobDialog.prototype);
    const sent = [];
    Object.assign(dialog, { state: 'ready', readyUntil: Date.now() - 1, pending: false, closed: false, isCurrent: () => true, send: (...args) => sent.push(args), update() {}, status: {}, manager: { t: (_, fallback) => fallback } });
    dialog.apply();
    assert.equal(sent.length, 0);
    assert.equal(dialog.state, 'expired');
});

test('danger acknowledgment considers only object types present in the preview', () => {
    const dialog = Object.create(PermissionJobDialog.prototype);
    dialog.plan = { file_mode: '000', directory_mode: '755' };
    dialog.counts = { files: 0, directories: 1 };
    assert.equal(dialog.needsAcknowledgment(), false);
    dialog.counts.files = 1;
    assert.equal(dialog.needsAcknowledgment(), true);
});

test('single selection starts with its listed mode without copying special bits or guessing absent metadata', () => {
    const { initialModes } = require('../../static/js/permission-job-dialog.js');
    assert.deepEqual(initialModes([{ is_dir: false, mode: 0o100600 }]), { file: '600', directory: '755' });
    assert.deepEqual(initialModes([{ is_dir: true, mode: 0o40700 }]), { file: '644', directory: '700' });
    assert.deepEqual(initialModes([{ is_dir: false }]), { file: '644', directory: '755' });
    assert.deepEqual(initialModes([{ is_dir: false, mode: 0o104755 }, { is_dir: false, mode: 0o100600 }]), { file: '644', directory: '755' });
});

test('stopping remaining work keeps the dialog open for confirmed partial results', () => {
    const dialog = Object.create(PermissionJobDialog.prototype);
    const sent = [];
    Object.assign(dialog, { state: 'running', pending: false, jobId: 'job', closed: false, send: (...args) => sent.push(args) });
    dialog.stop();
    assert.deepEqual(sent, [['cancel_file_permissions_job', { job_id: 'job' }]]);
    assert.equal(dialog.closed, false);
    dialog.pending = true;
    dialog.stop();
    assert.equal(sent.length, 1);
});

for (const order of ['close-first', 'complete-first']) {
    test(`confirmed permission changes refresh the bound source once with ${order}`, () => {
        const refreshed = [];
        const dialog = Object.create(PermissionJobDialog.prototype);
        Object.assign(dialog, { state: 'running', closed: order === 'close-first', pending: true, jobId: 'job', target: { sourceId: 'sftp:bound' }, isCurrent: () => true,
            manager: { refreshSource: source => refreshed.push(source), t: (_, fallback) => fallback }, cancelOwnedJob() {}, renderCounts() {}, update() {}, status: {} });
        dialog.receive({ job_id: 'job', state: 'completed', changed: 2 });
        dialog.closed = true;
        dialog.receive({ job_id: 'job', state: 'completed', changed: 2 });
        assert.deepEqual(refreshed, ['sftp:bound']);
        assert.equal(dialog.closed, true);
    });
}

test('a late closed result with a partial mutation or uncertain failure refreshes only its bound source', () => {
    for (const response of [{ state: 'running', changed: 1 }, { state: 'failed', changed: 0, code: 'OUTCOME_UNKNOWN' }]) {
        const refreshed = [];
        const dialog = Object.create(PermissionJobDialog.prototype);
        Object.assign(dialog, { closed: true, pending: true, jobId: 'job', target: { sourceId: 'sftp:bound' }, manager: { refreshSource: source => refreshed.push(source) }, cancelOwnedJob() {} });
        dialog.receive({ job_id: 'job', ...response });
        assert.deepEqual(refreshed, ['sftp:bound']);
    }
});
