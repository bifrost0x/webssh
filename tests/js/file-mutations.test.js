const test = require('node:test');
const assert = require('node:assert/strict');
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
