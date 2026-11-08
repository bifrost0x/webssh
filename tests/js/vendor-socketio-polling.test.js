const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

function pollingChannel() {
    const sent = [];
    class XMLHttpRequest {
        constructor() { this.responseType = ''; }
        open(method, url) { this.method = method; this.url = url; }
        setRequestHeader() {}
        send(body) { this.body = body; sent.push(this); }
        abort() {}
        respond(status, body) {
            this.status = status;
            this.responseText = body;
            this.readyState = 4;
            this.onreadystatechange?.();
        }
    }
    const context = {
        module: { exports: {} }, exports: {}, XMLHttpRequest,
        setTimeout, clearTimeout, console,
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,
        '../../static/vendor/socketio/socket.io.min.js'), 'utf8'), context);
    const manager = new context.module.exports.Manager('http://localhost', {
        autoConnect: false, reconnection: false, timeout: false,
        transports: ['polling'], upgrade: false,
    });
    manager.open();
    sent[0].respond(200, '0' + JSON.stringify({
        sid: 'polling-test', upgrades: [], pingInterval: 25000,
        pingTimeout: 20000, maxPayload: 1000000,
    }));
    assert.equal(manager.engine.readyState, 'open');
    return { manager, sent };
}

test('failed polling reports the original error without writing a close packet', async () => {
    const { manager, sent } = pollingChannel();
    const errors = [];
    manager.engine.on('error', error => errors.push(error));
    const closed = new Promise(resolve => manager.engine.once('close',
        (reason, error) => resolve({ reason, error })));
    const request = sent.at(-1);
    const count = sent.length;
    request.respond(0, '');
    const result = await closed;
    assert.equal(errors.length, 1);
    assert.equal(errors[0].message, 'xhr poll error');
    assert.equal(errors[0].description, 0);
    assert.equal(result.reason, 'transport error');
    assert.equal(result.error, errors[0]);
    assert.equal(manager.engine.readyState, 'closed');
    assert.equal(sent.length, count, 'failed transport must not start a close POST');
});

test('normal polling shutdown still sends its close packet', () => {
    const { manager, sent } = pollingChannel();
    manager.engine.close();
    assert.equal(sent.at(-1).method, 'POST');
    assert.equal(sent.at(-1).body, '1');
    assert.equal(manager.engine.readyState, 'closed');
});

test('failed polling writes preserve the error and do not replay the payload', async () => {
    const { manager, sent } = pollingChannel();
    manager.engine.write('do-not-replay');
    const request = sent.at(-1);
    assert.equal(request.method, 'POST');
    assert.equal(request.body, '4do-not-replay');
    const count = sent.length;
    const closed = new Promise(resolve => manager.engine.once('close',
        (reason, error) => resolve({ reason, error })));
    request.respond(0, '');
    const result = await closed;
    assert.equal(result.reason, 'transport error');
    assert.equal(result.error.message, 'xhr post error');
    assert.equal(result.error.description, 0);
    assert.equal(manager.engine.readyState, 'closed');
    assert.equal(sent.length, count);
});

test('an HTTP error retains its status and normal close handshake', async () => {
    const { manager, sent } = pollingChannel();
    const closed = new Promise(resolve => manager.engine.once('close',
        (reason, error) => resolve({ reason, error })));
    sent.at(-1).respond(503, 'Unavailable');
    const result = await closed;
    assert.equal(result.reason, 'transport error');
    assert.equal(result.error.description, 503);
    assert.equal(sent.at(-1).method, 'POST');
    assert.equal(sent.at(-1).body, '1');
});
