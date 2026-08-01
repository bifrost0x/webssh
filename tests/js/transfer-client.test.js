const assert = require('node:assert/strict');
const test = require('node:test');

global.document = {
    querySelector: () => ({ content: 'csrf' }),
    createElement: () => ({ click() {}, remove() {}, style: {} }),
    body: { appendChild() {} },
};
global.AbortController = class { constructor() { this.signal = {}; } abort() {} };

const BinaryTransferClient = require('../../static/js/binary-transfer-client.js');

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
