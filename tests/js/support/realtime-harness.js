'use strict';

// Loads the realtime shim the way the Go pages do (plain scripts on window)
// against an in-memory WebSocket whose server side the tests drive.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '../../..');
const SCRIPTS = [
    'static/js/realtime-emitter.js',
    'static/js/realtime-acks.js',
    'static/js/realtime-wire.js',
    'static/js/realtime-catalog.js',
    'static/js/realtime-terminal.js',
    'static/js/realtime-shim.js',
];

class FakeWebSocket {
    constructor(url, protocols) {
        this.url = url;
        this.protocols = protocols;
        this.sent = [];
        this.closed = false;
        FakeWebSocket.instances.push(this);
    }

    send(data) {
        if (this.closed) throw new Error('send after close');
        this.sent.push(typeof data === 'string' ? data : new Uint8Array(data));
    }

    close(code = 1000, reason = '') {
        if (this.closed) return;
        this.closed = true;
        this.closeCode = code;
        queueMicrotask(() => this.onclose?.({code, reason}));
    }

    // Server side ---------------------------------------------------------

    // Completes the upgrade with the negotiated subprotocol ('' for none).
    accept(protocol = 'webssh.v1') {
        if (this.opened) return;
        this.opened = true;
        this.protocol = protocol;
        this.onopen?.({});
    }

    serverClose(code, reason = '') {
        this.closed = true;
        this.onclose?.({code, reason});
    }

    serverText(text) { this.onmessage?.({data: text}); }

    serverSend(type, payload, id) {
        const envelope = {v: 1, t: type, p: payload};
        if (id !== undefined) envelope.id = id;
        this.serverText(JSON.stringify(envelope));
    }

    hello(restorable = [], username = 'alice') {
        this.accept();
        this.serverSend('hello', {user: {username, is_admin: false}, schema: 1, restorable});
    }

    reply(id, p = {}) { this.serverSend('result', {ok: true, p}, id); }

    fail(id, err) { this.serverSend('result', {ok: false, err}, id); }

    output(channel, seq, bytes, flags = 0) {
        const data = typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
        const frame = new Uint8Array(14 + data.length);
        const view = new DataView(frame.buffer);
        view.setUint8(0, 1);
        view.setUint8(1, flags);
        view.setUint32(2, channel);
        view.setBigUint64(6, BigInt(seq));
        frame.set(data, 14);
        this.onmessage?.({data: frame.buffer});
    }

    requests(type) {
        return this.sent.filter(entry => typeof entry === 'string').map(entry => JSON.parse(entry))
            .filter(envelope => type === undefined || envelope.t === type);
    }

    lastRequest(type) { return this.requests(type).at(-1); }

    frames(kind) {
        return this.sent.filter(entry => typeof entry !== 'string').map(bytes => {
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            return {
                kind: view.getUint8(0), flags: view.getUint8(1), channel: view.getUint32(2),
                seq: Number(view.getBigUint64(6)), data: new TextDecoder().decode(bytes.subarray(14)),
            };
        }).filter(frame => kind === undefined || frame.kind === kind);
    }
}
FakeWebSocket.instances = [];

function loadShim(extra = {}, scripts = SCRIPTS) {
    FakeWebSocket.instances = [];
    const events = new EventTarget();
    const context = {
        console,
        setTimeout,
        clearTimeout,
        queueMicrotask,
        TextDecoder,
        TextEncoder,
        crypto: globalThis.crypto,
        CustomEvent,
        Event,
        WebSocket: FakeWebSocket,
        location: {protocol: 'http:', host: 'webssh.test'},
        addEventListener: events.addEventListener.bind(events),
        removeEventListener: events.removeEventListener.bind(events),
        dispatchEvent: events.dispatchEvent.bind(events),
        WebSSHSocketProtocol: {WIRE_REVISION: 2},
        ...extra,
    };
    context.window = context;
    vm.createContext(context);
    for (const script of scripts) {
        vm.runInContext(fs.readFileSync(path.join(ROOT, script), 'utf8'), context, {filename: script});
    }
    return context;
}

const tick = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

// Opens a socket and completes the handshake.
async function connected(window, options = {}, restorable = []) {
    const socket = window.io({path: '/socket.io', autoConnect: false, reconnectionDelay: 1, randomizationFactor: 0, ...options});
    socket.connect();
    const ws = FakeWebSocket.instances.at(-1);
    ws.hello(restorable);
    await tick();
    return {socket, ws};
}

module.exports = {FakeWebSocket, loadShim, connected, tick, ROOT, SCRIPTS};
