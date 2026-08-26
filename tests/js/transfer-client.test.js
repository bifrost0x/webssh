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
    client.uploadFile(
        { name: 'large.bin', size: 9 },
        '/remote/large.bin',
        'sftp-session:session',
    );
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(emitted[0][0], 'prepare_transfer');
    assert.equal(emitted[0][1].source_id, 'sftp-session:session');
    assert.match(emitted[0][1].request_id, /^transfer_/);
    assert.equal(Object.hasOwn(emitted[0][1], 'session_id'), false);
    assert.equal(request.url, '/api/transfers/token/upload');
    assert.equal(request.options.body.name, 'large.bin');
    assert.equal(request.options.headers['X-CSRFToken'], 'csrf');
});

test('failed upload preserves the safe HTTP reason and structured code', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const failures = [];
    client.on('error', data => failures.push(data));
    global.fetch = async () => ({
        ok: false,
        status: 403,
        async json() {
            return {
                error_code: 'PERMISSION_DENIED',
                error: 'No write permission for the destination.',
                retryable: false,
            };
        },
    });

    client.uploadFile(
        { name: 'report.txt', size: 7 },
        '/report.txt',
        'smb-quick:readonly',
    );
    await flushTasks();
    transport.preparations[0].acknowledgement({
        success: true,
        transfer_id: 'server-permission',
        url: '/upload',
    });
    await flushTasks();

    assert.deepEqual(failures, [{
        transferId: failures[0].transferId,
        filename: 'report.txt',
        error: 'No write permission for the destination.',
        errorCode: 'PERMISSION_DENIED',
        retryable: false,
    }]);
    assert.match(failures[0].transferId, /^transfer_/);

    transport.receive('transfer_finished', {
        transfer_id: 'server-permission',
        status: 'failed',
        error_code: 'TRANSFER_UNAVAILABLE',
        error: 'The transfer could not be completed.',
        retryable: false,
    });
    assert.equal(failures.length, 1);
    assert.equal(failures[0].errorCode, 'PERMISSION_DENIED');
});

test('socket terminal failure carries its safe reason into the client event', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const failures = [];
    client.on('error', data => failures.push(data));
    global.fetch = () => new Promise(() => {});

    client.uploadFile(
        { name: 'report.txt', size: 7 },
        '/report.txt',
        'smb-quick:readonly',
    );
    await flushTasks();
    transport.preparations[0].acknowledgement({
        success: true,
        transfer_id: 'server-terminal-permission',
        url: '/upload',
    });
    await flushTasks();
    transport.receive('transfer_finished', {
        transfer_id: 'server-terminal-permission',
        status: 'failed',
        error_code: 'PERMISSION_DENIED',
        error: 'No write permission for the destination.',
        retryable: false,
    });

    assert.equal(failures.length, 1);
    assert.equal(failures[0].errorCode, 'PERMISSION_DENIED');
    assert.equal(failures[0].error, 'No write permission for the destination.');
    assert.equal(failures[0].retryable, false);
});

test('conflict overwrite retries with a fresh replace token', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const decisions = [];
    const completed = [];
    client.on('complete', data => completed.push(data));
    const responses = [
        {
            ok: false,
            status: 409,
            async json() {
                return {
                    error_code: 'CONFLICT',
                    error: 'A file or folder already exists at the destination.',
                    retryable: false,
                };
            },
        },
        { ok: true, status: 200 },
    ];
    global.fetch = async () => responses.shift();

    client.uploadFile(
        { name: 'report.txt', size: 7 },
        '/report.txt',
        'smb-quick:writable',
        {
            async onConflict(details) {
                decisions.push(details);
                return 'replace';
            },
        },
    );
    await flushTasks();
    const firstRequestId = transport.preparations[0].payload.request_id;
    transport.preparations[0].acknowledgement({
        success: true, transfer_id: 'conflict-token', url: '/upload/conflict',
    });
    await flushTasks();

    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].filename, 'report.txt');
    assert.equal(transport.preparations.length, 2);
    assert.equal(transport.preparations[0].payload.conflict_policy, 'error');
    assert.equal(transport.preparations[1].payload.conflict_policy, 'replace');
    assert.notEqual(transport.preparations[1].payload.request_id, firstRequestId);

    transport.preparations[1].acknowledgement({
        success: true, transfer_id: 'replacement-token', url: '/upload/replace',
    });
    await flushTasks();

    assert.equal(completed.length, 1);
});

test('uploads without a caller resolver still offer conflict replacement', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const previousWindow = global.window;
    const prompts = [];
    global.window = {
        confirm(message) {
            prompts.push(message);
            return true;
        },
    };
    const responses = [
        {
            ok: false,
            status: 409,
            async json() {
                return {
                    error_code: 'CONFLICT',
                    error: 'A file or folder already exists at the destination.',
                    retryable: false,
                };
            },
        },
        { ok: true, status: 200 },
    ];
    global.fetch = async () => responses.shift();

    try {
        client.uploadFile(
            { name: 'terminal-drop.txt', size: 7 },
            '/terminal-drop.txt',
            'sftp-session:terminal',
        );
        await flushTasks();
        transport.preparations[0].acknowledgement({
            success: true, transfer_id: 'default-conflict', url: '/upload',
        });
        await flushTasks();

        assert.equal(prompts.length, 1);
        assert.match(prompts[0], /terminal-drop\.txt/);
        assert.equal(transport.preparations.length, 2);
        assert.equal(
            transport.preparations[1].payload.conflict_policy,
            'replace',
        );
    } finally {
        global.window = previousWindow;
    }
});

for (const decision of ['skip', 'cancel']) {
    test(`conflict ${decision} ends locally without a replacement token`, async () => {
        const transport = controlledSocket();
        const client = new BinaryTransferClient(transport.socket);
        const terminal = [];
        client.on('skip', data => terminal.push(['skip', data]));
        client.on('cancel', data => terminal.push(['cancel', data]));
        global.fetch = async () => ({
            ok: false,
            status: 409,
            async json() {
                return {
                    error_code: 'CONFLICT',
                    error: 'A file or folder already exists at the destination.',
                    retryable: false,
                };
            },
        });

        client.uploadFile(
            { name: 'report.txt', size: 7 },
            '/report.txt',
            'smb-quick:writable',
            { onConflict: async () => decision },
        );
        await flushTasks();
        transport.preparations[0].acknowledgement({
            success: true, transfer_id: `conflict-${decision}`, url: '/upload',
        });
        await flushTasks();

        assert.equal(transport.preparations.length, 1);
        assert.equal(terminal.length, 1);
        assert.equal(terminal[0][0], decision);
    });
}

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
    assert.equal(emitted[0][1].source_id, 'sftp-session:session');
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

    const cancellations = [];
    client.on('cancelling', data => cancellations.push(data));
    assert.equal(client.cancelTransfer(third), true);
    assert.equal(client.cancelTransfer(third), false);
    assert.equal(transport.cancellations.length, 1);
    assert.deepEqual(cancellations, [{ transferId: third }]);
    assert.equal(transport.preparations.length, 3);
    assert.equal(client.activeTransfers.has(third), true);
    transport.cancellations[0].acknowledgement({
        success: true, state: 'cancelled',
    });
    await flushTasks();
    assert.equal(client.activeTransfers.has(third), false);
    assert.equal(transport.preparations.length, 4);
    assert.equal(transport.preparations[3].payload.remote_path, '/fourth.bin');

    // A late duplicate terminal event cannot reopen or advance the queue twice.
    transport.receive('transfer_finished', {
        transfer_id: 'third-server', status: 'cancelled',
    });
    await flushTasks();
    assert.equal(transport.preparations.length, 4);
});

test('known oversized upload fails before preparation with exact safe context', async () => {
    const previousWindow = global.window;
    global.window = {
        WEBSSH_TRANSFER_LIMITS: Object.freeze({ uploadBytes: 100 * 1024 * 1024 }),
    };
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const failures = [];
    client.on('error', data => failures.push(data));

    try {
        client.uploadFile(
            { name: 'large.bin', size: 142 * 1024 * 1024 },
            '/large.bin',
            'smb-quick:writable',
        );
        await flushTasks();
    } finally {
        global.window = previousWindow;
    }

    assert.equal(transport.preparations.length, 0);
    assert.equal(failures.length, 1);
    assert.equal(failures[0].errorCode, 'LIMIT_EXCEEDED');
    assert.equal(failures[0].limitKind, 'upload');
    assert.equal(failures[0].limitBytes, 100 * 1024 * 1024);
    assert.equal(failures[0].actualBytes, 142 * 1024 * 1024);
});

test('cancelling during preparation emits once after the server id arrives', async () => {
    const transport = controlledSocket();
    const client = new BinaryTransferClient(transport.socket);
    const cancelling = [];
    client.on('cancelling', data => cancelling.push(data));

    const localId = client.downloadFile('/slow.bin', 'smb-quick:slow');
    await flushTasks();
    assert.equal(transport.preparations.length, 1);

    assert.equal(client.cancelTransfer(localId), true);
    assert.equal(client.cancelTransfer(localId), false);
    assert.deepEqual(cancelling, [{ transferId: localId }]);
    assert.equal(transport.cancellations.length, 0);

    transport.preparations[0].acknowledgement({
        success: true, transfer_id: 'slow-server', url: '/slow-download',
    });
    await flushTasks();

    assert.equal(transport.cancellations.length, 1);
    assert.deepEqual(transport.cancellations[0].payload, {
        transfer_id: 'slow-server',
    });
    assert.equal(client.activeTransfers.has(localId), true);

    transport.cancellations[0].acknowledgement({
        success: true, state: 'cancelled',
    });
    await flushTasks();
    assert.equal(client.activeTransfers.has(localId), false);

    transport.receive('transfer_finished', {
        transfer_id: 'slow-server', status: 'cancelled',
    });
    await flushTasks();
    assert.equal(client.activeTransfers.has(localId), false);
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

    FileTransferManager.ownedTransfers.add('failed-upload');
    shared.emit('error', {
        transferId: 'failed-upload',
        filename: 'report.txt',
        error: 'No write permission for the destination.',
        errorCode: 'PERMISSION_DENIED',
        retryable: false,
    });
    assert.deepEqual(notifications.at(-1), [
        'Transfer failed: report.txt — No write permission for the destination.',
        'error',
    ]);
});
