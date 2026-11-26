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
    assert.equal(results[1][1].message, 'operation has timed out', 'a timed ack fails with an Error like Socket.IO');
    assert.equal(results[1][2], undefined);
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

test('a connection limit and a maintenance close reconnect with backoff', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', reconnectionDelay: 1, reconnectionDelayMax: 1});
    const errors = [];
    socket.on('connect_error', error => errors.push([error.message, error.data]));
    FakeWebSocket.instances[0].serverClose(1013, 'connection_limit_user: at most 32 realtime connections per user are open');
    await tick(20);
    assert.deepEqual(JSON.parse(JSON.stringify(errors)), [[
        'at most 32 realtime connections per user are open',
        {code: 'connection_limit', scope: 'user', message: 'at most 32 realtime connections per user are open'},
    ]]);
    assert.equal(FakeWebSocket.instances.length, 2, 'a refused connection is retried');
    socket.disconnect();

    const live = await connected(loadShim());
    const reasons = [];
    live.socket.on('disconnect', reason => reasons.push(reason));
    live.ws.serverClose(4503, 'shutdown');
    await tick(20);
    assert.deepEqual(reasons, ['transport close']);
    assert.equal(FakeWebSocket.instances.length, 2, 'maintenance or shutdown reconnects');
    live.socket.disconnect();
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
    socket.emit('save_notepad', {text: 'draft'}, result => results.push(['plain', result.success]));
    socket.timeout(15000).emit('save_jump_host', {name: 'j'}, (error, result) => results.push(['timed', error?.message, result]));
    ws.serverClose(1006);
    await tick();
    assert.deepEqual(results, [['plain', false], ['timed', 'operation has timed out', undefined]]);
});

test('a request without a result fails after the request timeout', async () => {
    const window = loadShim();
    const {socket} = await connected(window, {requestTimeout: 20});
    const results = [];
    socket.timeout(15000).emit('save_socks_proxy', {name: 's'}, (error, result) => results.push(['timed', error?.message, result]));
    socket.emit('save_notepad', {text: 'x'}, result => results.push(['plain', result.code]));
    await tick(40);
    assert.deepEqual(results, [['timed', 'operation has timed out', undefined], ['plain', 'timeout']]);
    socket.disconnect();
});

test('a server error still reaches a timed ack as its response', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const results = [];
    socket.timeout(15000).emit('save_jump_host', {name: 'j'}, (error, result) => results.push([error, result.code]));
    ws.fail(ws.lastRequest('hosts.jump.save').id, {code: 'invalid_value', message: 'Port is invalid.'});
    await tick();
    assert.deepEqual(results, [[null, 'invalid_value']]);
    socket.disconnect();
});

test('connected waits for restores only for a bounded time', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false, restoreTimeout: 20});
    const order = [];
    socket.on('connected', () => order.push('connected'));
    socket.on('ssh_session_restored', data => order.push(`restored ${data.session_id}`));
    socket.connect();
    const ws = FakeWebSocket.instances.at(-1);
    ws.hello([{session_id: 'slow', host: 'h', port: 22, username: 'u', auth_type: 'password', last_seq: 0}]);
    await tick(40);
    assert.deepEqual(order, ['connected']);
    const attach = ws.lastRequest('terminal.attach');
    ws.reply(attach.id, {ch: attach.p.ch, session_id: 'slow', seq: 0, full: true});
    await tick();
    assert.deepEqual(order, ['connected', 'restored slow']);
    socket.disconnect();
});

test('an upgrade without the v1 subprotocol is treated as a version mismatch', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', reconnectionDelay: 1});
    const errors = [];
    socket.on('connect_error', error => errors.push(error.data?.code));
    const ws = FakeWebSocket.instances[0];
    ws.accept('');
    await tick(20);
    assert.deepEqual(errors, ['socket_protocol_mismatch']);
    assert.equal(ws.closed, true);
    assert.equal(FakeWebSocket.instances.length, 1, 'no reconnect into the same mismatch');
});

test('event names that exist on Object.prototype are plain unavailable events', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    const sent = ws.sent.length;
    for (const name of ['toString', 'constructor', 'hasOwnProperty']) socket.emit(name, {}, ack => acks.push(ack.code));
    await tick();
    assert.deepEqual(acks, ['not_available_in_preview', 'not_available_in_preview', 'not_available_in_preview']);
    assert.equal(ws.sent.length, sent);
    socket.disconnect();
});

test('a throwing emit does not leak its flags into the next emit', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window, {requestTimeout: 1000});
    assert.throws(() => socket.timeout(5).emit('connect'), /reserved/);
    const results = [];
    socket.emit('save_notepad', {text: 'x'}, result => results.push(result.success));
    await tick(20);
    assert.deepEqual(results, [], 'the earlier 5 ms timeout must not apply');
    ws.reply(ws.lastRequest('notes.save').id, {text: 'x'});
    await tick();
    assert.deepEqual(results, [true]);
    socket.disconnect();
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

// A browser cannot read why an upgrade was refused. After repeated
// failures the shim asks the session status endpoint (same origin,
// no-store) and goes to the sign-in at once on 401.
function statusWindow(status, body) {
    const calls = [];
    const navigation = {assigned: [], reloads: 0};
    const window = loadShim({
        fetch: (url, init) => {
            calls.push({url, init});
            return Promise.resolve({status, ok: status >= 200 && status < 300, json: () => Promise.resolve(body)});
        },
        location: {
            protocol: 'http:', host: 'webssh.test',
            assign(url) { navigation.assigned.push(url); },
            reload() { navigation.reloads += 1; },
        },
    });
    return {window, calls, navigation};
}

async function failConnects(window, count, path = '/socket.io') {
    const socket = window.io({path, reconnectionDelay: 1, reconnectionDelayMax: 1, randomizationFactor: 0});
    for (let i = 0; i < count; i += 1) {
        FakeWebSocket.instances.at(-1).serverClose(1006);
        await tick(20);
    }
    return socket;
}

test('repeated failures ask the session status and go to the sign-in on 401', async () => {
    const {window, calls, navigation} = statusWindow(401, {success: false, code: 'authentication_required', schema: 1});
    const socket = await failConnects(window, 2, '/webssh/socket.io');
    assert.equal(calls.length, 0, 'no status check before the third failure');
    FakeWebSocket.instances.at(-1).serverClose(1006);
    await tick(20);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/webssh/api/realtime/status');
    assert.equal(calls[0].init.credentials, 'same-origin');
    assert.equal(calls[0].init.cache, 'no-store');
    assert.deepEqual(navigation.assigned, ['/webssh/login']);
    const opened = FakeWebSocket.instances.length;
    await tick(30);
    assert.equal(FakeWebSocket.instances.length, opened, 'no further reconnects after the redirect');
    socket.disconnect();
});

test('a valid session keeps retrying; another schema or a recovery session reloads', async () => {
    const ok = statusWindow(200, {success: true, authenticated: true, recovery: false, schema: 1});
    const socket = await failConnects(ok.window, 3);
    assert.equal(ok.calls.length, 1);
    assert.deepEqual(ok.navigation, {assigned: [], reloads: 0});
    socket.disconnect();

    for (const body of [{success: true, recovery: false, schema: 2}, {success: true, recovery: true, schema: 1}]) {
        const other = statusWindow(200, body);
        const s = await failConnects(other.window, 3);
        assert.equal(other.navigation.reloads, 1, JSON.stringify(body));
        s.disconnect();
    }
});

test('a session ended before hello checks the status at once', async () => {
    const {window, calls, navigation} = statusWindow(401, {schema: 1});
    window.io({path: '/socket.io', reconnectionDelay: 1});
    FakeWebSocket.instances[0].serverClose(4003, 'session_ended');
    await tick(20);
    assert.equal(calls.length, 1);
    assert.deepEqual(navigation.assigned, ['/login']);
});
