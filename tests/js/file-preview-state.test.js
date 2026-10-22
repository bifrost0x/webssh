const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup() {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const part = source.slice(source.indexOf('const FilePreview = {'), source.indexOf('window.FilePreview = FilePreview;'));
    const classes = () => ({ add() {}, remove() {} });
    const fields = Object.fromEntries(['editorStatus', 'previewFilename', 'previewSize', 'editorReview', 'editorReviewTarget', 'editorReviewDiff', 'editorReviewLimited', 'editorReviewOriginal', 'editorReviewEdited', 'editorCommitBtn', 'editorBackupBtn'].map(id => [id, { classList: classes(), focus() {} }]));
    fields.editorContent = { value: 'one', classList: classes() };
    const events = [];
    const context = { setTimeout: fn => { context.timeout = fn; return 1; }, clearTimeout() {}, window: { confirm: () => true, removeEventListener() {}, addEventListener() {}, ModalManager: { open() {} } }, document: { getElementById: id => fields[id] || null }, socket: { connected: true, emit: (event, data) => events.push({event, data}) }, showNotification() {}, console };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/file-edit-diff.js'), 'utf8'), context);
    vm.runInNewContext(part + '\nglobalThis.preview = FilePreview;', context);
    const preview = context.preview;
    Object.assign(preview, { currentSourceId: 'sftp-session:s', currentPath: '/a', editMode: true, dirty: true, editRevision: 'r1', editBaseline: '', editTarget: { sourceId: 'sftp-session:s', path: '/a', endpoint: 'user@first.example:22' } });
    preview.refresh = () => { preview.refreshed = true; };
    return { preview, fields, events, context };
}

function save(preview) {
    preview.saveEdit();
    preview.commitReviewedEdit();
}

test('unconfirmed save blocks another mutation and preserves the draft', () => {
    const {preview, events, fields, context} = setup();
    save(preview);
    context.timeout();
    save(preview);
    assert.equal(events.length, 1);
    assert.equal(fields.editorContent.value, 'one');
    assert.equal(preview.saveOutcomeUnknown, true);
});

for (const warning of [undefined, 'SMB_RECOVERY_BACKUP_RETAINED']) {
    test(`retained editor invalidates original-byte backup after save (${warning || 'late acknowledgement'})`, () => {
        const {preview, fields, events, context} = setup();
        preview.editOriginalBytes = 'b3JpZ2luYWw=';
        save(preview);
        context.timeout();
        fields.editorContent.value = 'second edit';
        preview.handleFileSaved({...events[0].data, revision: 'r2', warning_code: warning});
        preview.saveEdit();
        assert.equal(preview.editBaseline, 'one');
        assert.equal(preview.editOriginalBytes, null);
        assert.equal(fields.editorBackupBtn.disabled, true);
        assert.equal(fields.editorReviewOriginal.value, 'one');
    });
}

test('save acknowledgement preserves text entered while saving and updates revision', () => {
    const {preview, fields, events} = setup();
    save(preview);
    const sent = events[0].data;
    fields.editorContent.value = 'two';
    preview.markDirty();
    preview.handleFileSaved({...sent, revision: 'r2'});
    assert.equal(preview.editMode, true);
    assert.equal(preview.dirty, true);
    assert.equal(preview.editRevision, 'r2');
    assert.equal(preview.refreshed, undefined);
    save(preview);
    assert.equal(events[1].data.content, 'two');
    assert.equal(events[1].data.expected_revision, 'r2');
});

test('opening another file clears old copy content until fresh response', async () => {
    const {preview, context} = setup();
    preview.showLoading = () => {};
    preview._previewFullContent = 'old file';
    let copied = false;
    context.TerminalManager = { writeTextToClipboard: async () => { copied = true; } };
    preview.open('sftp-session:s', '/b', 'b.txt');
    await preview.copyToClipboard();
    assert.equal(copied, false);
    assert.equal(preview._previewFullContent, null);
});

test('copy uses existing clipboard helper when browser Clipboard API is absent', async () => {
    const {preview, context} = setup();
    preview._previewFullContent = 'current file\n';
    context.navigator = {};
    let copied;
    context.TerminalManager = { writeTextToClipboard: async text => { copied = text; } };
    await preview.copyToClipboard();
    assert.equal(copied, 'current file\n');
});

test('unchanged successful save closes editor and duplicate submission is ignored', () => {
    const {preview, events} = setup();
    save(preview);
    save(preview);
    assert.equal(events.length, 1);
    preview.handleFileSaved({...events[0].data, revision: 'r2'});
    assert.equal(preview.editMode, false);
    assert.equal(preview.dirty, false);
    assert.equal(preview.refreshed, true);
});

test('failed save retains dirty text and permits a deliberate retry', () => {
    const {preview, events} = setup();
    save(preview);
    preview.handleSocketError({...events[0].data, operation: 'save_file', error: 'failed'});
    assert.equal(preview.dirty, true);
    save(preview);
    assert.equal(events.length, 2);
});

test('late acknowledgement reconciles uncertainty before another save is allowed', () => {
    const {preview, fields, events, context} = setup();
    save(preview);
    const first = events[0].data;
    context.timeout();
    assert.equal(preview.dirty, true);
    save(preview);
    assert.equal(events.length, 1);
    fields.editorContent.value = 'new draft';
    preview.handleFileSaved({...first, revision: 'late'});
    assert.equal(preview.editRevision, 'late');
    assert.equal(preview.editMode, true);
    save(preview);
    assert.equal(events.length, 2);
    preview.handleSocketError({...events[1].data, operation: 'save_file', error: 'conflict'});
    fields.editorContent.value = 'new draft';
    save(preview);
    assert.equal(events[2].data.expected_revision, 'late');
});

test('late acknowledgement reconciles revision and retains newer text', () => {
    const {preview, fields, events, context} = setup();
    save(preview);
    context.timeout();
    fields.editorContent.value = 'new draft';
    preview.handleFileSaved({...events[0].data, revision: 'r2'});
    assert.equal(preview.editMode, true);
    assert.equal(preview.dirty, true);
    save(preview);
    assert.equal(events[1].data.expected_revision, 'r2');
    assert.equal(events[1].data.content, 'new draft');
});

test('older acknowledgement cannot roll revision back after newer success', () => {
    const {preview, fields, events, context} = setup();
    save(preview);
    context.timeout();
    fields.editorContent.value = 'two';
    preview.handleFileSaved({...events[0].data, revision: 'r2'});
    save(preview);
    fields.editorContent.value = 'three';
    preview.handleFileSaved({...events[1].data, revision: 'r3'});
    preview.handleFileSaved({...events[0].data, revision: 'r2'});
    assert.equal(preview.editRevision, 'r3');
    assert.equal(fields.editorContent.value, 'three');
});

test('reopening the same file ignores acknowledgement from abandoned editor', () => {
    const {preview, events, context} = setup();
    save(preview);
    context.timeout();
    preview.showLoading = () => {};
    preview.open('sftp-session:s', '/a', 'a.txt');
    preview.editMode = true;
    preview.editRevision = 'reopened';
    preview.handleFileSaved({...events[0].data, revision: 'old'});
    assert.equal(preview.editRevision, 'reopened');
});

test('disconnect preserves the draft and blocks retry until the result is reconciled', () => {
    const {preview, events, context} = setup();
    save(preview);
    context.socket.connected = false;
    preview.interruptSave();
    save(preview);
    assert.equal(events.length, 1);
    context.socket.connected = true;
    save(preview);
    assert.equal(events.length, 1);
    assert.equal(preview.saveOutcomeUnknown, true);
});


test('save requires deliberate review and commit with exact baseline and target', () => {
    const { preview, fields, events } = setup();
    preview.saveEdit();
    assert.equal(events.length, 0);
    assert.equal(fields.editorReviewOriginal.value, '');
    assert.equal(fields.editorReviewEdited.value, 'one');
    assert.match(fields.editorReviewTarget.textContent, /user@first.example:22/);
    assert.match(fields.editorReviewTarget.textContent, /\/a/);
    preview.commitReviewedEdit();
    assert.equal(events.length, 1);
    assert.equal(events[0].data.content, 'one');
    assert.equal(events[0].data.expected_revision, 'r1');
});

test('edited text and changed revision invalidate an earlier review', () => {
    for (const change of ['text', 'revision', 'path', 'source']) {
        const { preview, fields, events } = setup();
        preview.saveEdit();
        if (change === 'text') fields.editorContent.value = 'unreviewed';
        if (change === 'revision') preview.editRevision = 'r2';
        if (change === 'path') preview.currentPath = '/other';
        if (change === 'source') preview.currentSourceId = 'smb-quick:other';
        preview.commitReviewedEdit();
        assert.equal(events.length, 0, change);
        assert.equal(fields.editorContent.value, change === 'text' ? 'unreviewed' : 'one');
    }
});

test('dirty state clears when content returns to the loaded baseline', () => {
    const { preview, fields } = setup();
    fields.editorContent.value = '';
    preview.markDirty();
    assert.equal(preview.dirty, false);
});

test('opening another source cannot discard a draft without confirmation', () => {
    const { preview, fields, context, events } = setup();
    context.window.confirm = () => false;
    preview.open('smb-quick:other', '/other', 'other.txt');
    assert.equal(preview.currentSourceId, 'sftp-session:s');
    assert.equal(preview.currentPath, '/a');
    assert.equal(fields.editorContent.value, 'one');
    assert.equal(events.length, 0);
});

test('non-atomic SMB consent cannot save content changed since the review', () => {
    const { preview, fields, context, events } = setup();
    save(preview);
    fields.editorContent.value = 'unreviewed';
    context.window.confirm = () => true;
    preview.handleSocketError({ ...events[0].data, operation: 'save_file', code: 'SMB_RECOVERABLE_REPLACE_REQUIRED', save_challenge: 'challenge' });
    assert.equal(events.length, 1);
    assert.equal(fields.editorContent.value, 'unreviewed');
});

test('duplicate edit response cannot overwrite a draft or its captured revision', () => {
    const { preview, fields } = setup();
    fields.editorContent.focus = () => {};
    preview.currentEditRequestId = 'load';
    const data = { source_id: 'sftp-session:s', path: '/a', request_id: 'load', content: 'loaded', revision: 'loaded-revision', original_bytes: 'bG9hZGVk', endpoint: 'authoritative.example:22' };
    preview.handleEditData(data);
    assert.equal(preview.editBaseline, 'loaded');
    assert.equal(preview.editOriginalBytes, 'bG9hZGVk');
    assert.equal(preview.editTarget.endpoint, 'authoritative.example:22');
    fields.editorContent.value = 'draft';
    preview.handleEditData({ ...data, content: 'stale', revision: 'stale' });
    assert.equal(fields.editorContent.value, 'draft');
    assert.equal(preview.editRevision, 'loaded-revision');
});

test('pending save still requires confirmation after a draft is reverted', () => {
    const { preview, fields, context, events } = setup();
    save(preview);
    fields.editorContent.value = '';
    preview.markDirty();
    assert.equal(preview.dirty, false);
    context.window.confirm = () => false;
    preview.open('smb-quick:other', '/other', 'other.txt');
    assert.equal(preview.currentSourceId, 'sftp-session:s');
    assert.equal(events.length, 1);
});

test('oversized pasted draft is retained without generating a review or a save', () => {
    const { preview, fields, events } = setup();
    fields.editorContent.value = 'a'.repeat(5 * 1024 * 1024 + 1);
    preview.saveEdit();
    assert.equal(preview.editReview, null);
    assert.match(fields.editorStatus.textContent, /too large/i);
    assert.equal(events.length, 0);
    assert.equal(fields.editorContent.value.length, 5 * 1024 * 1024 + 1);
});
