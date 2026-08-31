const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const {TextDecoder, TextEncoder} = require('node:util');

function loadSSHInput(socket = {emit() {}}, maxEventBytes = 64 * 1024) {
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

test('client chunks at the effective server limit below 64 KiB', () => {
    const transport = loadSSHInput({emit() {}}, 4 * 1024);
    const chunks = transport.byteChunks('x'.repeat(10 * 1024));
    const encoder = new TextEncoder();

    assert.equal(transport.CHUNK_BYTES, 4 * 1024);
    assert.ok(chunks.every(chunk => encoder.encode(chunk).length <= 4 * 1024));
});
