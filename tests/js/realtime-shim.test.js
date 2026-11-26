const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const {FakeWebSocket, loadShim, connected, tick, ROOT} = require('./support/realtime-harness.js');

test('io() opens the native endpoint under the application root with the v1 subprotocol', () => {
    const window = loadShim();
    const socket = window.io({path: '/webssh/socket.io', autoConnect: false});
    assert.equal(FakeWebSocket.instances.length, 0, 'autoConnect false must not connect');
    socket.connect();
    const [ws] = FakeWebSocket.instances;
    assert.equal(ws.url, 'ws://webssh.test/webssh/ws');
    assert.deepEqual([...ws.protocols], ['webssh.v1']);
    assert.equal(ws.binaryType, 'arraybuffer');
    socket.disconnect();

    const secure = loadShim({location: {protocol: 'https:', host: 'h.test:8443'}});
    const secureSocket = secure.io({path: '/socket.io'});
    assert.equal(FakeWebSocket.instances[0].url, 'wss://h.test:8443/ws');
    secureSocket.disconnect();
});

test('hello emits connect and then connected with the frontend wire revision', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    const order = [];
    socket.on('connect', () => order.push(['connect', socket.connected]));
    socket.on('connected', data => order.push(['connected', data]));
    socket.connect();
    assert.equal(socket.connected, false);
    FakeWebSocket.instances[0].hello([], 'alice');
    await tick();
    assert.deepEqual(JSON.parse(JSON.stringify(order)), [
        ['connect', true],
        ['connected', {status: 'success', username: 'alice', wire_revision: 2}],
    ]);
    assert.match(socket.id, /^[0-9a-f]{24}$/);
    socket.disconnect();
    assert.equal(socket.id, undefined);
});

test('a message before hello or a malformed envelope is a protocol violation', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', reconnection: false});
    const errors = [];
    socket.on('connect_error', error => errors.push(error.message));
    const ws = FakeWebSocket.instances[0];
    const originalError = console.error;
    console.error = () => {};
    try {
        ws.serverSend('terminal.closed', {session_id: 's'});
        await tick();
    } finally {
        console.error = originalError;
    }
    assert.equal(ws.closeCode, 4002);
    assert.deepEqual(errors, ['websocket error']);
});

test('emits while disconnected are never buffered and fail at once', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    const results = [];
    socket.emit('save_notepad', {text: 'x'}, result => results.push(['plain', result]));
    socket.timeout(1000).emit('save_jump_host', {}, (error, result) => results.push(['timed', error, result]));
    socket.emit('ssh_input', {session_id: 's', data: 'ls\r'});
    await tick();
    assert.equal(FakeWebSocket.instances.length, 0);
    assert.equal(results.length, 2);
    assert.equal(results[0][1].success, false);
    assert.equal(results[0][1].code, 'unavailable');
    assert.equal(results[1][1], null);
    assert.equal(results[1][2].code, 'unavailable');
});

test('ssh-input.js sends nothing through a disconnected shim', async () => {
    const window = loadShim({showNotification() {}});
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'static/js/ssh-input.js'), 'utf8'), window);
    window.socket = window.io({path: '/socket.io', autoConnect: false});
    assert.equal(await window.SSHInput.send('session-1', 'echo offline\r'), false);
    window.socket.connect();
    const ws = FakeWebSocket.instances[0];
    ws.hello();
    await tick();
    assert.equal(ws.sent.length, 0, 'the offline input must not be replayed after connecting');
    window.socket.disconnect();
});

test('a dropped connection reconnects with attempts on socket.io and resets them after hello', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('disconnect', reason => seen.push(['disconnect', reason]));
    socket.io.on('reconnect_attempt', attempt => seen.push(['attempt', attempt]));
    socket.io.on('reconnect', attempt => seen.push(['reconnect', attempt]));
    socket.on('connect', () => seen.push(['connect']));
    ws.serverClose(1006);
    assert.equal(socket.connected, false);
    await tick(20);
    assert.equal(FakeWebSocket.instances.length, 2);
    FakeWebSocket.instances[1].hello();
    await tick();
    assert.deepEqual(seen, [['disconnect', 'transport close'], ['attempt', 1], ['reconnect', 1], ['connect']]);
    assert.equal(socket.connected, true);
    socket.disconnect();
});

test('failed reconnect attempts report connect_error and back off', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const errors = [];
    const attempts = [];
    socket.on('connect_error', error => errors.push(error.message));
    socket.io.on('reconnect_attempt', attempt => attempts.push(attempt));
    ws.serverClose(1006);
    await tick(20);
    FakeWebSocket.instances[1].serverClose(1006);
    await tick(20);
    assert.deepEqual(attempts, [1, 2]);
    assert.deepEqual(errors, ['websocket error']);
    socket.disconnect();
    await tick(20);
    assert.equal(FakeWebSocket.instances.length, 3, 'disconnect() stops reconnecting');
});

test('an ended session closes with io server disconnect and does not reconnect', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const reasons = [];
    socket.on('disconnect', reason => reasons.push(reason));
    ws.serverClose(4003, 'session ended');
    await tick(20);
    assert.deepEqual(reasons, ['io server disconnect']);
    assert.equal(FakeWebSocket.instances.length, 1);

    const before = loadShim();
    const pending = before.io({path: '/socket.io', reconnectionDelay: 1});
    const errors = [];
    pending.on('connect_error', error => errors.push(error.data?.code));
    FakeWebSocket.instances[0].serverClose(4003);
    await tick(20);
    assert.deepEqual(errors, ['authentication_required']);
    assert.equal(FakeWebSocket.instances.length, 1);
});

test('an unsupported version reaches the existing mismatch handling', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', reconnectionDelay: 1});
    const errors = [];
    socket.on('connect_error', error => errors.push(error.data));
    FakeWebSocket.instances[0].serverClose(4001, 'supported: webssh.v2');
    await tick(20);
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, 'socket_protocol_mismatch');
    assert.equal(errors[0].status, 'reload_required');
    assert.equal(FakeWebSocket.instances.length, 1, 'no reconnect into the same mismatch');

    const live = await connected(loadShim());
    const mismatch = [];
    live.socket.on('socket_protocol_mismatch', data => mismatch.push(data.code));
    live.ws.serverClose(4001);
    assert.deepEqual(mismatch, ['socket_protocol_mismatch']);
});

test('listeners, once and off follow the Socket.IO emitter', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    const calls = [];
    const first = data => calls.push(['first', data]);
    socket.on('profiles_list', first);
    socket.once('profiles_list', data => calls.push(['once', data]));
    assert.equal(socket.listeners('profiles_list').length, 2);
    socket.listeners('profiles_list').forEach(listener => listener(1));
    socket.listeners('profiles_list').forEach(listener => listener(2));
    assert.deepEqual(calls, [['first', 1], ['once', 1], ['first', 2]]);
    socket.off('profiles_list', first);
    assert.equal(socket.listeners('profiles_list').length, 0);
    socket.on('preview_data', () => {});
    socket.on('preview_data', () => {});
    socket.off('preview_data');
    assert.equal(socket.hasListeners('preview_data'), false);
    assert.throws(() => socket.emit('connect'), /reserved/);
});

test('an emit patched on the instance still sends through the original', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const original = socket.emit.bind(socket);
    const seen = [];
    socket.emit = function wrapped(event, ...args) {
        seen.push(event);
        return original(event, ...args);
    };
    socket.timeout(5000).emit('save_jump_host', {name: 'j'}, () => {});
    assert.deepEqual(seen, ['save_jump_host']);
    assert.equal(ws.lastRequest('hosts.jump.save').p.name, 'j');
    socket.disconnect();
});

test('a lost connection fails pending requests instead of leaving them open', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window, {reconnection: false});
    const results = [];
    socket.emit('save_notepad', {text: 'draft'}, result => results.push(result));
    ws.serverClose(1006);
    await tick();
    assert.equal(results.length, 1);
    assert.equal(results[0].success, false);
});

test('a throwing listener does not stop the other listeners', async () => {
    const reported = [];
    const window = loadShim({reportError: error => reported.push(error.message)});
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('notepad_data', () => { throw new Error('listener failed'); });
    socket.on('notepad_data', data => seen.push(data.notepad));
    socket.emit('get_notepad');
    ws.reply(ws.lastRequest('notes.get').id, {text: 'hi'});
    await tick();
    assert.deepEqual(seen, ['hi']);
    assert.deepEqual(reported, ['listener failed']);
    socket.disconnect();
});

test('the Python pages keep loading Socket.IO and never the shim', () => {
    for (const file of fs.readdirSync(path.join(ROOT, 'templates'))) {
        if (!file.endsWith('.html')) continue;
        const source = fs.readFileSync(path.join(ROOT, 'templates', file), 'utf8');
        assert.doesNotMatch(source, /realtime-|preview-notice/, file);
    }
    const index = fs.readFileSync(path.join(ROOT, 'templates/index.html'), 'utf8');
    assert.match(index, /vendor\/socketio\/socket\.io\.min\.js/);
});
