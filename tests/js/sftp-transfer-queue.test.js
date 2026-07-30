const assert = require('node:assert/strict');
const test = require('node:test');

global.window = {};
global.document = { getElementById: () => null };
require('../../static/js/sftp-file-manager.js');
const SFTPFileManager = global.window.SFTPFileManager;

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

    await manager.transferSSHtoSSH(
        '/source/file.bin', { sessionId: 'source-session' },
        '/target/file.bin', { sessionId: 'target-session' },
        { name: 'file.bin', is_dir: false, size: 10 },
    );

    assert.equal(request.event, 'transfer_server_to_server');
    assert.equal(request.payload.transfer_id, undefined);
    assert.equal(queued.id, 'server-transfer-id');
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
