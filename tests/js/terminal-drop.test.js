const assert = require('node:assert/strict');
const test = require('node:test');
const DragDropManager = require('../../static/js/drag-drop-manager');

function harness() {
    const listeners = new Map();
    const dom = new Map();
    const uploads = [];
    const requests = [];
    const notifications = [];
    const first = {id: 'first', username: 'alice', host: 'first.example', connected: true};
    const active = {id: 'active', username: 'bob', host: 'active.example', connected: true};
    const state = {activeId: active.id, visible: false};
    const element = id => {
        if (!dom.has(id)) dom.set(id, {value: '', textContent: '', handlers: {},
            classList: {contains: () => state.visible},
            addEventListener(name, fn) {this.handlers[name] = fn;}});
        return dom.get(id);
    };
    global.document = {getElementById: element, addEventListener() {}};
    global.window = {
        socket: {connected: true, on(name, fn) {if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name).add(fn);},
            off(name, fn) {listeners.get(name)?.delete(fn);}, emit(name, payload) {requests.push({name, payload});}},
        SessionManager: {getWorkspaceSession: () => state.activeId, getActiveSession: () => first.id,
            getSession: id => [first, active].find(s => s.id === id)},
        ModalManager: {open() {state.visible = true;}, close() {state.visible = false;}},
        showNotification: message => notifications.push(message),
    };
    global.FileTransferManager = {uploadFile: (...args) => uploads.push(args)};
    const manager = new DragDropManager();
    manager.setupUploadDialog();
    return {manager, first, active, state, uploads, requests, notifications, element,
        receive(name, data) {for (const fn of [...(listeners.get(name) || [])]) fn(data);},
        listenerCount: () => [...listeners.values()].reduce((n, set) => n + set.size, 0),
        drop() {manager.handleDrop({preventDefault() {}, stopPropagation() {},
            dataTransfer: {types: ['Files'], files: [{name: 'note.txt', size: 1}]}});},
        submit: () => element('dropUploadForm').handlers.submit({preventDefault() {}}),
    };
}

test('binds the active target at drop time, requires confirmation and honors destination folder', async () => {
    const h = harness(); h.drop();
    assert.equal(h.uploads.length, 0);
    assert.equal(h.element('dropUploadTarget').textContent, 'bob@active.example:22');
    assert.equal(h.element('dropUploadPath').value, '.');
    h.state.activeId = h.first.id;
    h.element('dropUploadPath').value = '/chosen/';
    await h.submit();
    assert.equal(h.uploads.length, 1);
    assert.equal(h.uploads[0][0], 'sftp-session:active');
    assert.equal(h.uploads[0][2], '/chosen/note.txt');
});

test('cancel sends nothing and a disconnected target never falls back to another server', async () => {
    const h = harness(); h.drop();
    h.element('cancelDropUploadBtn').handlers.click(); await h.submit();
    assert.equal(h.uploads.length, 0);
    h.drop(); h.active.connected = false; await h.submit();
    assert.equal(h.uploads.length, 0);
    assert.equal(h.notifications.length, 1);
    h.state.activeId = null;
    assert.equal(h.manager.getActiveSession(), null);
});

test('reads every directory batch and waits for correlated mkdir success before uploading children', async () => {
    const h = harness(); let reads = 0;
    const file = name => ({name, isFile: true, file: done => done({name, size: 1})});
    const directory = {name: 'folder', createReader: () => ({readEntries(done) {
        reads++; done(reads <= 2 ? Array.from({length: 100}, (_, i) => file(`${reads}-${i}.txt`)) : []);
    }})};
    const operation = h.manager.uploadDirectory(directory, h.active, '.');
    assert.equal(reads, 0); assert.equal(h.uploads.length, 0);
    const request = h.requests[0].payload;
    h.receive('directory_created', {...request, request_id: 'unrelated'});
    assert.equal(reads, 0);
    h.receive('directory_created', request);
    await operation;
    assert.equal(reads, 3); assert.equal(h.uploads.length, 200);
    assert.equal(h.uploads[199][2], './folder/2-99.txt');
    assert.equal(h.listenerCount(), 0);
});

test('mkdir failure or disconnect stops children and releases response listeners', async () => {
    for (const failure of ['error', 'disconnect']) {
        const h = harness(); let read = false;
        const operation = h.manager.uploadDirectory({name: 'folder', createReader() {read = true;}}, h.active, '.');
        h.receive(failure, {...h.requests[0].payload, error: 'Permission denied'});
        await assert.rejects(operation);
        assert.equal(read, false); assert.equal(h.uploads.length, 0); assert.equal(h.listenerCount(), 0);
    }
});
