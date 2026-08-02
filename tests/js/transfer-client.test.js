const assert = require('node:assert/strict');
const test = require('node:test');

global.document = {
    querySelector: () => ({ content: 'csrf' }),
    createElement: () => ({ click() {}, remove() {}, style: {} }),
    body: { appendChild() {} },
};
global.AbortController = class { constructor() { this.signal = {}; } abort() {} };

const BinaryTransferClient = require('../../static/js/binary-transfer-client.js');

function flushTasks() {
    return new Promise(resolve => setImmediate(resolve));
}

function controlledSocket() {
    const handlers = new Map();
    const preparations = [];
    const cancellations = [];
    const socket = {
        on(event, callback) {
            if (!handlers.has(event)) handlers.set(event, []);
            handlers.get(event).push(callback);
        },
        emit(event, payload, acknowledgement) {
            if (event === 'prepare_transfer') {
                preparations.push({ payload, acknowledgement });
            } else if (event === 'cancel_transfer') {
                cancellations.push({ payload, acknowledgement });
            }
        },
    };
    return {
        socket,
        preparations,
        cancellations,
        receive(event, payload) {
            for (const callback of handlers.get(event) || []) callback(payload);
        },
    };
}

test('uploads the File directly over HTTP after socket metadata preparation', async () => {
    const emitted = [];
    const socket = { on() {}, emit(event, payload, ack) {
        emitted.push([event, payload]);
        if (event === 'prepare_transfer') ack({ success: true, transfer_id: 'server-id', url: '/api/transfers/token/upload' });
    }};
    let request;
    global.fetch = async (url, options) => { request = { url, options }; return { ok: true }; };
    const client = new BinaryTransferClient(socket);
    client.uploadFile({ name: 'large.bin', size: 9 }, '/remote/large.bin', 'session');
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(emitted[0][0], 'prepare_transfer');
    assert.equal(request.url, '/api/transfers/token/upload');
    assert.equal(request.options.body.name, 'large.bin');
    assert.equal(request.options.headers['X-CSRFToken'], 'csrf');
});

test('a listener exception does not prevent later transfer listeners', () => {
    const socket = { on() {}, emit() {} };
    const client = new BinaryTransferClient(socket);
    let called = false;
    client.on('progress', () => { throw new Error('listener'); });
    client.on('progress', () => { called = true; });
    client.emit('progress', {});
    assert.equal(called, true);
});

test('folder downloads use archive metadata and native HTTP navigation', async () => {
    const emitted = [];
    let clicked = false;
    global.document.createElement = () => ({
        click() { clicked = true; }, remove() {}, style: {}, href: '', download: '',
    });
    const socket = { on() {}, emit(event, payload, ack) {
        emitted.push([event, payload]);
        if (event === 'prepare_transfer') {
            ack({ success: true, transfer_id: 'folder-id', url: '/folder-download' });
        }
    }};
    const client = new BinaryTransferClient(socket);

    client.downloadFolder('/remote/reports', 'session');
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(emitted[0][0], 'prepare_transfer');
    assert.equal(emitted[0][1].archive, true);
    assert.equal(clicked, true);
});

test('pane downloads pipe the HTTP body into a writable stream without native navigation', async () => {
    const emitted = [];
    let clicked = false;
    let piped;
    const writable = { kind: 'browser-file-writable' };
    global.document.createElement = () => ({
        click() { clicked = true; }, remove() {}, style: {}, href: '', download: '',
    });
    const socket = { on() {}, emit(event, payload, ack) {
        emitted.push([event, payload]);
        if (event === 'prepare_transfer') {
            ack({ success: true, transfer_id: 'pane-id', url: '/pane-download' });
        }
    }};
    global.fetch = async () => ({
        ok: true,
        body: {
            async pipeTo(destination, options) {
                piped = { destination, options };
            },
        },
    });
    const client = new BinaryTransferClient(socket);

    const transfer = client.downloadFileToWritable(
        '/remote/report.bin',
        'session',
        async () => writable,
    );
    await transfer.done;

    assert.equal(emitted[0][0], 'prepare_transfer');
    assert.equal(piped.destination, writable);
    assert.ok(piped.options.signal);
    assert.equal(clicked, false);
});

test('a browser-file write failure cancels the server transfer', async () => {
    const emitted = [];
    let aborted = false;
    const writable = {
        async abort() { aborted = true; },
    };
    const socket = { on() {}, emit(event, payload, ack) {
        emitted.push([event, payload]);
        if (event === 'prepare_transfer') {
            ack({ success: true, transfer_id: 'failed-pane-id', url: '/pane-download' });
        }
    }};
    global.fetch = async () => ({
        ok: true,
        body: {
            async pipeTo() { throw new Error('local write failed'); },
        },
    });
    const client = new BinaryTransferClient(socket);

    const transfer = client.downloadFileToWritable(
        '/remote/report.bin',
        'session',
        async () => writable,
    );
    await assert.rejects(transfer.done, /local write failed/);

    assert.equal(aborted, true);
    assert.equal(emitted.some(([event, payload]) => (
        event === 'cancel_transfer'
        && payload.transfer_id === 'failed-pane-id'
    )), true);
});

test('a local write failure after server completion rejects without stale cancellation', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    let failLocalWrite;
    global.fetch = async () => ({
        ok: true,
        body: {
            pipeTo() {
                return new Promise((_resolve, reject) => { failLocalWrite = reject; });
            },
        },
    });

    const writable = client.downloadFileToWritable(
        '/remote/report.bin',
        'session',
        async () => ({ async abort() {} }),
    );
    await flushTasks();
    transport.preparations[0].acknowledgement({
        success: true,
        transfer_id: 'completed-before-local-write',
        url: '/pane-download',
    });
    await flushTasks();
    transport.receive('transfer_finished', {
        transfer_id: 'completed-before-local-write',
        status: 'completed',
    });
    failLocalWrite(new Error('local disk full'));

    await assert.rejects(writable.done, /local disk full/);
    assert.equal(transport.cancellations.length, 0);
});

test('cancelling a writable after server completion only cancels the local sink', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    let finishLocalWrite;
    global.fetch = async () => ({
        ok: true,
        body: {
            pipeTo() {
                return new Promise(resolve => { finishLocalWrite = resolve; });
            },
        },
    });

    const writable = client.downloadFileToWritable(
        '/remote/report.bin',
        'session',
        async () => ({ kind: 'destination' }),
    );
    await flushTasks();
    transport.preparations[0].acknowledgement({
        success: true,
        transfer_id: 'server-already-complete',
        url: '/pane-download',
    });
    await flushTasks();
    transport.receive('transfer_finished', {
        transfer_id: 'server-already-complete',
        status: 'completed',
    });

    client.cancelTransfer(writable.id);
    assert.equal(await writable.done, false);
    assert.equal(transport.cancellations.length, 0);
    assert.equal(client.activeTransfers.has(writable.id), false);
    finishLocalWrite();
});

test('forSocket returns one browser transfer coordinator per socket', () => {
    const firstSocket = controlledSocket().socket;
    const secondSocket = controlledSocket().socket;

    assert.equal(
        BinaryTransferClient.forSocket(firstSocket),
        BinaryTransferClient.forSocket(firstSocket),
    );
    assert.notEqual(
        BinaryTransferClient.forSocket(firstSocket),
        BinaryTransferClient.forSocket(secondSocket),
    );
});

test('upload file folder and writable starts are serialized until terminalization', async () => {
    const transport = controlledSocket();
    const client = BinaryTransferClient.forSocket(transport.socket);
    let navigationCount = 0;
    global.document.createElement = () => ({
        click() { navigationCount += 1; }, remove() {}, style: {}, href: '', download: '',
    });
    global.fetch = async url => {
        if (url === '/writable') {
            return {
                ok: true,
                body: { async pipeTo() {} },
            };
        }
        return { ok: true };
    };

    client.uploadFile({ name: 'one.bin', size: 1 }, '/one.bin', 'session');
    client.downloadFile('/two.bin', 'session');
    client.downloadFolder('/three', 'session');
    const writable = client.downloadFileToWritable(
        '/four.bin',
        'session',
        async () => ({ kind: 'destination' }),
    );
    await flushTasks();

    assert.equal(transport.preparations.length, 1);
    assert.equal(transport.preparations[0].payload.remote_path, '/one.bin');

    transport.preparations[0].acknowledgement({
        success: true, transfer_id: 'upload-one', url: '/upload',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 2);
    assert.equal(transport.preparations[1].payload.remote_path, '/two.bin');

    transport.preparations[1].acknowledgement({
        success: true, transfer_id: 'download-two', url: '/download',
    });
    await flushTasks();
    assert.equal(navigationCount, 1);
    assert.equal(transport.preparations.length, 2);

    transport.receive('transfer_finished', {
        transfer_id: 'download-two', status: 'completed',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 3);
    assert.equal(transport.preparations[2].payload.archive, true);

    transport.preparations[2].acknowledgement({
        success: true, transfer_id: 'folder-three', url: '/folder',
    });
    await flushTasks();
    transport.receive('transfer_finished', {
        transfer_id: 'folder-three', status: 'completed',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 4);
    assert.equal(transport.preparations[3].payload.remote_path, '/four.bin');

    transport.preparations[3].acknowledgement({
        success: true, transfer_id: 'writable-four', url: '/writable',
    });
    assert.equal(await writable.done, true);
});

test('cancelling a queued writable never prepares it and settles done', async () => {
    const transport = controlledSocket();
    const client = BinaryTransferClient.forSocket(transport.socket);
    let finishUpload;
    global.fetch = () => new Promise(resolve => { finishUpload = resolve; });

    client.uploadFile({ name: 'active.bin', size: 1 }, '/active.bin', 'session');
    const queued = client.downloadFileToWritable(
        '/cancelled.bin',
        'session',
        async () => ({ kind: 'unused' }),
    );
    client.downloadFile('/next.bin', 'session');
    await flushTasks();

    assert.equal(transport.preparations.length, 1);
    client.cancelTransfer(queued.id);
    assert.equal(await queued.done, false);
    assert.equal(transport.cancellations.length, 0);

    transport.preparations[0].acknowledgement({
        success: true, transfer_id: 'active-upload', url: '/upload',
    });
    await flushTasks();
    finishUpload({ ok: true });
    await flushTasks();

    assert.equal(transport.preparations.length, 2);
    assert.equal(transport.preparations[1].payload.remote_path, '/next.bin');
    assert.equal(
        transport.preparations.some(entry => entry.payload.remote_path === '/cancelled.bin'),
        false,
    );
});

test('duplicate completion error and cancellation signals release one queue slot once', async () => {
    const transport = controlledSocket();
    const client = BinaryTransferClient.forSocket(transport.socket);
    let finishFirstUpload;
    global.fetch = url => {
        if (url === '/first-upload') {
            return new Promise(resolve => { finishFirstUpload = resolve; });
        }
        return new Promise(() => {});
    };

    const first = client.uploadFile({ name: 'first.bin', size: 1 }, '/first.bin', 'session');
    client.downloadFile('/second.bin', 'session');
    const third = client.uploadFile({ name: 'third.bin', size: 1 }, '/third.bin', 'session');
    client.downloadFile('/fourth.bin', 'session');
    await flushTasks();

    transport.preparations[0].acknowledgement({
        success: true, transfer_id: 'first-server', url: '/first-upload',
    });
    await flushTasks();
    transport.receive('transfer_finished', {
        transfer_id: 'first-server', status: 'completed',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 2);

    finishFirstUpload({ ok: true });
    transport.receive('transfer_finished', {
        transfer_id: 'first-server', status: 'completed',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 2);
    assert.equal(client.activeTransfers.has(first), false);

    transport.preparations[1].acknowledgement({ success: false });
    await flushTasks();
    assert.equal(transport.preparations.length, 3);
    transport.preparations[2].acknowledgement({
        success: true, transfer_id: 'third-server', url: '/third-upload',
    });
    await flushTasks();

    client.cancelTransfer(third);
    client.cancelTransfer(third);
    assert.equal(transport.cancellations.length, 1);
    assert.equal(transport.preparations.length, 3);
    transport.cancellations[0].acknowledgement({ success: true });
    transport.cancellations[0].acknowledgement({ success: true });
    transport.receive('transfer_finished', {
        transfer_id: 'third-server', status: 'cancelled',
    });
    await flushTasks();

    assert.equal(transport.preparations.length, 4);
    assert.equal(transport.preparations[3].payload.remote_path, '/fourth.bin');
});

test('FileTransferManager and DragDropManager use the shared socket coordinator', () => {
    const transport = controlledSocket();
    const notifications = [];
    global.window = {
        socket: transport.socket,
        BinaryTransferClient,
        addEventListener() {},
        showNotification(...args) { notifications.push(args); },
    };

    delete require.cache[require.resolve('../../static/js/file-transfer.js')];
    delete require.cache[require.resolve('../../static/js/drag-drop-manager.js')];
    const FileTransferManager = require('../../static/js/file-transfer.js');
    const DragDropManager = require('../../static/js/drag-drop-manager.js');
    const shared = BinaryTransferClient.forSocket(transport.socket);
    const dragDropManager = new DragDropManager();
    dragDropManager.createOverlay = () => {};
    dragDropManager.attachGlobalListeners = () => {};
    dragDropManager.init();

    assert.equal(FileTransferManager.getTransferClient(), shared);
    assert.equal(dragDropManager.transferClient, shared);

    FileTransferManager.ownedTransfers.add('drop-upload');
    shared.emit('start', {
        transferId: 'drop-upload', type: 'upload', filename: 'report.txt',
    });
    shared.emit('complete', {
        transferId: 'drop-upload', type: 'upload', filename: 'report.txt',
    });
    assert.deepEqual(notifications, [
        ['Uploading report.txt...', 'info'],
        ['Upload complete: report.txt', 'success'],
    ]);
});
