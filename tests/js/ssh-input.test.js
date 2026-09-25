const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const {TextDecoder, TextEncoder} = require('node:util');

function loadSSHInput(socket = {emit() {}}, maxEventBytes = 64 * 1024) {
    if (socket.connected === undefined) socket.connected = true;
    const window = {
        socket,
        setTimeout,
        clearTimeout,
        TextDecoder,
        TextEncoder,
        WEBSSH_SSH_INPUT_LIMITS: {maxEventBytes},
    };
    const context = vm.createContext({
        window,
        TextDecoder,
        TextEncoder,
    });
    vm.runInContext(
        fs.readFileSync('static/js/ssh-input.js', 'utf8'),
        context,
    );
    return window.SSHInput;
}

test('splits large multibyte paste into exact UTF-8-safe chunks', () => {
    const input = `prefix-${'😀é'.repeat(50000)}-suffix`;
    const transport = loadSSHInput();
    const chunks = transport.byteChunks(input);
    const encoder = new TextEncoder();

    assert.ok(chunks.length > 1);
    assert.equal(chunks.join(''), input);
    assert.ok(chunks.every(chunk => encoder.encode(chunk).length <= 64 * 1024));
});

test('small input keeps the one-event latency path', async () => {
    const emissions = [];
    const transport = loadSSHInput({
        emit(event, payload) {
            emissions.push([event, payload]);
        },
    });

    assert.equal(await transport.send('session-1', 'ls\r'), true);
    assert.equal(JSON.stringify(emissions), JSON.stringify([[
        'ssh_input',
        {session_id: 'session-1', data: 'ls\r'},
    ]]));
});

test('large input retries acknowledgement backpressure without reordering', async () => {
    const delivered = [];
    let first = true;
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            if (first) {
                first = false;
                acknowledgement({
                    success: false,
                    code: 'ssh_input_backpressure',
                    retry_after_ms: 1,
                });
                return;
            }
            delivered.push(payload.data);
            acknowledgement({success: true});
        },
    });
    const input = 'x'.repeat(70 * 1024);

    assert.equal(await transport.send('session-1', input), true);
    assert.equal(delivered.join(''), input);
    assert.equal(delivered.length, 2);
});

test('concurrent typing waits behind a backpressured paste for one session', async () => {
    const delivered = [];
    let backpressureOnce = true;
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            if (backpressureOnce) {
                backpressureOnce = false;
                acknowledgement({
                    success: false,
                    code: 'ssh_input_backpressure',
                    retry_after_ms: 1,
                });
                return;
            }
            delivered.push(payload.data);
            acknowledgement?.({success: true});
        },
    });
    const paste = 'x'.repeat(70 * 1024);

    const pasteResult = transport.send('session-1', paste);
    const typingResult = transport.send('session-1', 'k');

    assert.equal(await pasteResult, true);
    assert.equal(await typingResult, true);
    assert.equal(delivered.join(''), `${paste}k`);
});

test('queued single-chunk input retries backpressure after a paste', async () => {
    const delivered = [];
    let queuedAttempts = 0;
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            if (payload.data === 'k') {
                queuedAttempts += 1;
                if (queuedAttempts === 1) {
                    acknowledgement?.({
                        success: false,
                        code: 'ssh_input_backpressure',
                        retry_after_ms: 1,
                    });
                    return;
                }
            }
            delivered.push(payload.data);
            acknowledgement?.({success: true});
        },
    });
    const paste = 'x'.repeat(70 * 1024);

    const pasteResult = transport.send('session-1', paste);
    const typingResult = transport.send('session-1', 'k');

    assert.equal(await pasteResult, true);
    assert.equal(await typingResult, true);
    assert.equal(queuedAttempts, 2);
    assert.equal(delivered.join(''), `${paste}k`);
});

test('client chunks at the effective server limit below 64 KiB', () => {
    const transport = loadSSHInput({emit() {}}, 4 * 1024);
    const chunks = transport.byteChunks('x'.repeat(10 * 1024));
    const encoder = new TextEncoder();

    assert.equal(transport.CHUNK_BYTES, 4 * 1024);
    assert.ok(chunks.every(chunk => encoder.encode(chunk).length <= 4 * 1024));
});

function connectedSocket(emit) {
    const handlers = new Map();
    return {
        connected: true,
        emit,
        on(event, handler) { handlers.set(event, handler); },
        off(event) { handlers.delete(event); },
        disconnect() {
            this.connected = false;
            handlers.get('disconnect')?.();
        },
    };
}

test('disconnected Socket.IO never buffers interactive input', async () => {
    const io = require('../../static/vendor/socketio/socket.io.min.js');
    const socket = io('http://127.0.0.1:1', {autoConnect: false, reconnection: false});
    const transport = loadSSHInput(socket);
    assert.equal(await transport.send('session-1', 'echo offline\r'), false);
    assert.equal(socket.sendBuffer.length, 0);
    socket.disconnect();
});

test('partial paste failure cancels dependent Enter but permits fresh input and other sessions', async () => {
    const delivered = [];
    const transport = loadSSHInput(connectedSocket((_event, payload, ack) => {
        if (payload.data === 'efgh') ack({success: false, error: 'Remote input rejected'});
        else { delivered.push([payload.session_id, payload.data]); ack?.({success: true}); }
    }), 4);
    const paste = transport.send('session-1', 'abcdefgh');
    const enter = transport.send('session-1', '\r');
    const dependent = transport.send('session-1', 'x');
    assert.equal(await transport.send('session-2', 'ok'), true);
    assert.equal(await paste, false);
    assert.equal(await enter, false);
    assert.equal(await dependent, false);
    assert.equal(await transport.send('session-1', 'new'), true);
    assert.deepEqual(delivered, [['session-1', 'abcd'], ['session-2', 'ok'], ['session-1', 'new']]);
});

test('disconnect cancels unacknowledged paste and queued input even after immediate reconnect', async () => {
    const delivered = [];
    let delayedAck;
    const socket = connectedSocket((_event, payload, ack) => {
        delivered.push(payload.data);
        if (payload.data === 'abcd') delayedAck = ack;
        else ack?.({success: true});
    });
    const transport = loadSSHInput(socket, 4);
    const paste = transport.send('session-1', 'abcdefgh');
    const enter = transport.send('session-1', '\r');
    socket.disconnect();
    socket.connected = true;
    delayedAck({success: true});
    assert.equal(await paste, false);
    assert.equal(await enter, false);
    assert.equal(await transport.send('session-1', 'new'), true);
    assert.deepEqual(delivered, ['abcd', 'new']);
});


test('disconnect settles a pending acknowledgement without waiting for its timeout', async () => {
    const socket = connectedSocket(() => {});
    const transport = loadSSHInput(socket, 4);
    const paste = transport.send('session-1', 'abcdefgh');
    socket.disconnect();
    assert.equal(await Promise.race([paste, new Promise(resolve => setImmediate(() => resolve('pending')))]), false);
});

test('disconnect cancels backpressure retry timers', async () => {
    const delivered = [];
    const socket = connectedSocket((_event, payload, ack) => {
        delivered.push(payload.data);
        ack?.({success: false, code: 'ssh_input_backpressure', retry_after_ms: 5000});
    });
    const transport = loadSSHInput(socket, 4);
    const paste = transport.send('session-1', 'abcdefgh');
    await Promise.resolve();
    socket.disconnect();
    socket.connected = true;
    assert.equal(await Promise.race([paste, new Promise(resolve => setImmediate(() => resolve('pending')))]), false);
    assert.deepEqual(delivered, ['abcd']);
});

test('ending one session cancels its paste without cancelling another session', async () => {
    const delivered = [];
    const acks = new Map();
    const socket = connectedSocket((_event, payload, ack) => {
        delivered.push([payload.session_id, payload.data]);
        if (payload.data === 'abcd') acks.set(payload.session_id, ack);
        else ack?.({success: true});
    });
    const transport = loadSSHInput(socket, 4);
    const first = transport.send('session-1', 'abcdefgh');
    const second = transport.send('session-2', 'abcdefgh');
    const enter = transport.send('session-1', '\r');
    transport.cancelSession('session-1');
    acks.get('session-1')({success: true});
    acks.get('session-2')({success: true});
    assert.equal(await first, false);
    assert.equal(await enter, false);
    assert.equal(await second, true);
    assert.deepEqual(delivered, [['session-1', 'abcd'], ['session-2', 'abcd'], ['session-2', 'efgh']]);
});

test('LF control input passes through send byte-identical', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.send('s', '\n'), true);
    assert.equal(emitted.join(''), '\n');
});

test('LF newlines normalize to CR on explicit text input', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.sendText('s', 'echo a\necho b\n'), true);
    assert.equal(emitted.join(''), 'echo a\recho b\r');
});

test('CRLF newlines normalize to CR on explicit text input', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.sendText('s', 'line1\r\nline2\r\n'), true);
    assert.equal(emitted.join(''), 'line1\rline2\r');
});

test('lone CR passes through byte-identical on explicit text input', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.sendText('s', 'ls\r'), true);
    assert.equal(emitted.join(''), 'ls\r');
});

test('mixed newline styles normalize to CR on explicit text input', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.sendText('s', 'a\r\nb\nc\rd'), true);
    assert.equal(emitted.join(''), 'a\rb\rc\rd');
});

test('chunked multiline paste round-trips with CR normalization', async () => {
    const delivered = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            delivered.push(payload.data);
            acknowledgement?.({success: true});
        },
    }, 4);

    assert.equal(await transport.sendText('s', 'ab\ncd\nef'), true);
    assert.equal(delivered.join(''), 'ab\rcd\ref');
});

test('bracketed paste payload passes through send byte-identical', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.send('s', '\x1b[200~a\nb\x1b[201~'), true);
    assert.equal(emitted.join(''), '\x1b[200~a\nb\x1b[201~');
});

test('tiny-limit multibyte paste rejoins normalized with no lone surrogate', async () => {
    const delivered = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            delivered.push(payload.data);
            acknowledgement?.({success: true});
        },
    }, 4);
    const encoder = new TextEncoder();

    assert.equal(await transport.sendText('s', '😀é\r\nx'), true);
    assert.equal(delivered.join(''), '😀é\rx');
    assert.ok(!delivered.join('').includes('�'));
    assert.ok(delivered.every(chunk => encoder.encode(chunk).length <= 4));
});

test('noteInput spy sees normalized value preserving submitted semantics', async () => {
    const seen = [];
    const socket = {connected: true, emit() {}};
    const window = {
        socket,
        setTimeout,
        clearTimeout,
        TextDecoder,
        TextEncoder,
        WEBSSH_SSH_INPUT_LIMITS: {maxEventBytes: 64 * 1024},
        SessionDirectorySync: {noteInput: (id, v) => seen.push([id, v])},
    };
    const context = vm.createContext({window, TextDecoder, TextEncoder});
    vm.runInContext(fs.readFileSync('static/js/ssh-input.js', 'utf8'), context);
    const transport = window.SSHInput;

    assert.equal(await transport.sendText('s', 'a\nb'), true);
    assert.equal(seen.length, 1);
    assert.equal(seen[0][0], 's');
    assert.equal(seen[0][1], 'a\rb');
    assert.ok(seen[0][1].includes('\r'));
    assert.ok(!seen[0][1].includes('\n'));
});

test('DA-style reply passes through send byte-identical', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.send('s', '\x1b[?25c'), true);
    assert.equal(emitted.join(''), '\x1b[?25c');
});

test('degenerate text newlines preserve CR semantics and empty early-returns', async () => {
    const emitted = [];
    const transport = loadSSHInput({
        emit(_event, payload, acknowledgement) {
            emitted.push(payload.data);
            acknowledgement?.({success: true});
        },
    });

    assert.equal(await transport.sendText('s', '\r\r'), true);
    assert.equal(await transport.sendText('s', 'x\n'), true);
    assert.equal(await transport.sendText('s', ''), false);
    assert.equal(await transport.sendText('s', '\n'), true);
    assert.deepEqual(emitted, ['\r\r', 'x\r', '\r']);
});
