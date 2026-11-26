const assert = require('node:assert/strict');
const test = require('node:test');
const {loadShim, connected, tick} = require('./support/realtime-harness.js');

// Values built inside the page context have that realm's prototypes.
const plain = value => JSON.parse(JSON.stringify(value));

const KIND_INPUT = 2;
const KIND_ACK = 3;
const INFO = {
    session_id: 'sess-1', host: 'h.test', port: 22, username: 'u', auth_type: 'password',
    key_id: '', profile_id: '', via_jump: '', jump_host_id: '', socks_proxy_id: '', via_socks: false,
    reconnect_route_known: true, use_tmux: false, tmux_session_name: '', display_name: '',
    detected_platform: '', last_seq: 0,
};

// Opens one terminal through ssh_connect and returns its channel.
async function openTerminal(socket, ws, sessionId = 'sess-1') {
    socket.emit('ssh_connect', {host: 'h.test', port: '22', username: 'u', auth_type: 'password', password: 'pw', client_request_id: `req_${sessionId}`});
    const open = ws.requests('terminal.open').at(-1);
    ws.reply(open.id, {session_id: sessionId, info: {...INFO, session_id: sessionId}});
    await tick();
    return open.p.ch;
}

test('ssh_connect becomes terminal.open and early output follows ssh_connected', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('ssh_connected', data => seen.push(['connected', data]));
    socket.on('ssh_output', (data, ack) => {
        seen.push(['output', data.data, data.sequence]);
        ack();
    });
    socket.emit('ssh_connect', {
        host: 'h.test', port: '2222', username: 'u', auth_type: 'password', password: 'pw',
        client_request_id: 'req_1', use_tmux: true, display_name: 'web', ssh_interaction: 1,
    });
    const open = ws.lastRequest('terminal.open');
    assert.deepEqual(open.p, {
        ch: 1, request_id: 'req_1', cols: 80, rows: 24,
        target: {auth_type: 'password', host: 'h.test', username: 'u', password: 'pw', port: 2222, use_tmux: true},
    });
    ws.output(1, 1, 'motd\r\n');
    ws.reply(open.id, {session_id: 'sess-1', info: INFO});
    await tick();
    assert.equal(seen[0][0], 'connected');
    assert.equal(seen[0][1].client_request_id, 'req_1');
    assert.equal(seen[0][1].profile_id, null, 'empty strings stand for null');
    assert.equal(Object.hasOwn(seen[0][1], 'last_seq'), false);
    assert.deepEqual(seen[1], ['output', 'motd\r\n', 1]);
    socket.disconnect();
});

test('a reconnect to a persistent tmux session sends its name', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    socket.emit('ssh_connect', {
        host: 'h.test', username: 'u', auth_type: 'key', key_id: 'k1', client_request_id: 'req_t',
        use_tmux: true, reconnect_tmux_name: 'webssh_u_h_test_22_0a0b0c0d', display_name: 'Build',
    });
    assert.deepEqual(plain(ws.lastRequest('terminal.open').p.target), {
        auth_type: 'key', host: 'h.test', username: 'u', key_id: 'k1',
        use_tmux: true, tmux_session_name: 'webssh_u_h_test_22_0a0b0c0d',
    });
    socket.emit('ssh_connect', {
        host: 'h.test', username: 'u', auth_type: 'key', key_id: 'k1', client_request_id: 'req_u',
        use_tmux: 'yes', reconnect_tmux_name: 'webssh_x',
    });
    assert.deepEqual(plain(ws.lastRequest('terminal.open').p.target), {
        auth_type: 'key', host: 'h.test', username: 'u', key_id: 'k1',
    }, 'a name without use_tmux is not sent');
    socket.disconnect();
});

test('a failed open and an unsupported target become ssh_error with the request id', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const errors = [];
    socket.on('ssh_error', data => errors.push(data));
    socket.emit('ssh_connect', {host: 'h', username: 'u', auth_type: 'password', client_request_id: 'req_a'});
    ws.fail(ws.lastRequest('terminal.open').id, {code: 'unreachable', message: 'The host could not be reached.'});
    const sent = ws.sent.length;
    socket.emit('ssh_connect', {host: 'h', username: 'u', auth_type: 'tailscale', client_request_id: 'req_b'});
    socket.emit('ssh_connect', {host: 'h', username: 'u', auth_type: 'password', proxy_jump: {host: 'j'}, client_request_id: 'req_c'});
    await tick();
    assert.equal(ws.sent.length, sent, 'unsupported targets never reach the server');
    assert.deepEqual(errors.map(e => [e.client_request_id, e.code]), [
        ['req_b', 'not_available_in_preview'],
        ['req_c', 'not_available_in_preview'],
        ['req_a', 'unreachable'],
    ]);
    assert.equal(errors[2].error, 'The host could not be reached.');
    socket.disconnect();
});

test('UTF-8 split across frames is decoded per channel', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const output = {};
    socket.on('ssh_output', (data, ack) => {
        output[data.session_id] = (output[data.session_id] || '') + data.data;
        ack();
    });
    const a = await openTerminal(socket, ws, 'a');
    const b = await openTerminal(socket, ws, 'b');
    const textA = 'Grüße 😀 ok';
    const textB = 'Ünïcödé 🎉';
    const bytesA = new TextEncoder().encode(textA);
    const bytesB = new TextEncoder().encode(textB);
    // Split inside the multi-byte sequences and interleave the channels.
    ws.output(a, 1, bytesA.subarray(0, 3));
    ws.output(b, 1, bytesB.subarray(0, 1));
    ws.output(a, 2, bytesA.subarray(3, 10));
    ws.output(b, 2, bytesB.subarray(1, 13));
    ws.output(a, 3, bytesA.subarray(10));
    ws.output(b, 3, bytesB.subarray(13));
    assert.equal(output.a, textA);
    assert.equal(output.b, textB);
    await tick(60);
    const acks = ws.frames(KIND_ACK);
    assert.deepEqual(acks.filter(f => f.channel === a).at(-1).seq, 3);
    assert.deepEqual(acks.filter(f => f.channel === b).at(-1).seq, 3);
    socket.disconnect();
});

test('the cumulative ack waits for every earlier chunk and batches per frame', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.on('ssh_output', (data, ack) => acks.push(ack));
    const ch = await openTerminal(socket, ws);
    ws.output(ch, 1, 'one');
    ws.output(ch, 2, 'two');
    ws.output(ch, 3, 'three');
    acks[2]();
    acks[1]();
    await tick(60);
    assert.deepEqual(ws.frames(KIND_ACK), [], 'chunk 1 is still being written');
    acks[0]();
    acks[0]();
    await tick(60);
    assert.deepEqual(ws.frames(KIND_ACK).map(f => [f.channel, f.seq, f.data]), [[ch, 3, '']]);
    socket.disconnect();
});

test('a chunk that decodes to nothing is acknowledged without an event', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('ssh_output', (data, ack) => {
        seen.push(data.data);
        ack();
    });
    const ch = await openTerminal(socket, ws);
    const emoji = new TextEncoder().encode('😀');
    ws.output(ch, 1, emoji.subarray(0, 2));
    ws.output(ch, 2, emoji.subarray(2));
    await tick(60);
    assert.deepEqual(seen, ['😀']);
    assert.equal(ws.frames(KIND_ACK).at(-1).seq, 2);
    socket.disconnect();
});

test('restorable sessions are attached and restored before connected', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    const order = [];
    socket.on('ssh_session_restored', data => order.push(['restored', data.session_id, data.buffered_output, data.output_sequence, data.profile_id]));
    socket.on('ssh_output', (data, ack) => {
        order.push(['output', data.data, data.sequence]);
        ack();
    });
    socket.on('connected', () => order.push(['connected']));
    socket.connect();
    const {FakeWebSocket} = require('./support/realtime-harness.js');
    const ws = FakeWebSocket.instances.at(-1);
    ws.hello([{...INFO, last_seq: 2}]);
    const attach = ws.lastRequest('terminal.attach');
    assert.deepEqual(attach.p, {ch: 1, session_id: 'sess-1', after_seq: 0});
    const bytes = new TextEncoder().encode('ä');
    ws.output(1, 1, new Uint8Array([...new TextEncoder().encode('history '), bytes[0]]), 3);
    ws.output(1, 2, bytes.subarray(1), 2);
    ws.output(1, 3, ' live');
    ws.reply(attach.id, {ch: 1, session_id: 'sess-1', seq: 2, full: true});
    await tick(60);
    assert.deepEqual(order, [
        ['restored', 'sess-1', 'history ä', 2, null],
        ['output', ' live', 3],
        ['connected'],
    ]);
    assert.equal(ws.frames(KIND_ACK).at(-1).seq, 3);
    socket.disconnect();
});

test('an attach under backpressure is retried and a lost session is skipped', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    const restored = [];
    let isConnected = false;
    socket.on('ssh_session_restored', data => restored.push(data.session_id));
    socket.on('connected', () => { isConnected = true; });
    socket.connect();
    const {FakeWebSocket} = require('./support/realtime-harness.js');
    const ws = FakeWebSocket.instances.at(-1);
    ws.hello([{...INFO, session_id: 'gone'}, {...INFO, session_id: 'busy'}]);
    const [gone, busy] = ws.requests('terminal.attach');
    ws.fail(gone.id, {code: 'not_found'});
    ws.fail(busy.id, {code: 'backpressure', retry_after_ms: 50});
    await tick(80);
    const retry = ws.requests('terminal.attach').at(-1);
    assert.equal(retry.p.session_id, 'busy');
    ws.reply(retry.id, {ch: retry.p.ch, session_id: 'busy', seq: 0, full: true});
    await tick();
    assert.deepEqual(restored, ['busy']);
    assert.equal(isConnected, true);
    socket.disconnect();
});

test('resync_required re-attaches the stream on a new channel', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const restored = [];
    const output = [];
    socket.on('ssh_session_restored', data => restored.push([data.session_id, data.buffered_output]));
    socket.on('ssh_output', (data, ack) => { output.push(data.data); ack(); });
    const ch = await openTerminal(socket, ws);
    ws.serverSend('terminal.resync_required', {ch, session_id: 'sess-1', reason: 'backpressure'});
    const attach = ws.lastRequest('terminal.attach');
    assert.notEqual(attach.p.ch, ch);
    assert.deepEqual(ws.lastRequest('terminal.detach').p, {ch}, 'the old channel is released on the server too');
    ws.output(ch, 9, 'stale');
    ws.output(attach.p.ch, 9, 'screen', 3);
    ws.reply(attach.id, {ch: attach.p.ch, session_id: 'sess-1', seq: 9, full: true});
    await tick();
    assert.deepEqual(restored, [['sess-1', 'screen']]);
    assert.deepEqual(output, []);
    socket.disconnect();
});

test('input uses binary frames, acknowledges on request and follows Go-Back-N', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const errors = [];
    socket.on('ssh_error', data => errors.push(data.code));
    const ch = await openTerminal(socket, ws);
    const acks = [];
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'ls'});
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'paste-1', acknowledge_backpressure: true}, r => acks.push(['p1', r]));
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'paste-2', acknowledge_backpressure: true}, r => acks.push(['p2', r]));
    assert.deepEqual(ws.frames(KIND_INPUT).map(f => [f.channel, f.seq, f.flags, f.data]), [
        [ch, 1, 0, 'ls'], [ch, 2, 1, 'paste-1'], [ch, 3, 1, 'paste-2'],
    ]);
    ws.serverSend('terminal.input_ack', {ch, iseq: 2});
    ws.serverSend('terminal.input_rejected', {ch, iseq: 3, code: 'ssh_input_backpressure', retry_after_ms: 40});
    assert.deepEqual(plain(acks[0]), ['p1', {success: true}]);
    assert.equal(acks[1][1].success, false);
    assert.equal(acks[1][1].code, 'ssh_input_backpressure');
    assert.equal(acks[1][1].retry_after_ms, 40);
    assert.deepEqual(errors, [], 'a paste that handles backpressure stays quiet');
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'paste-2'}, () => {});
    assert.equal(ws.frames(KIND_INPUT).at(-1).seq, 3, 'the rejected sequence is sent again');
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'x'});
    ws.serverSend('terminal.input_rejected', {ch, iseq: 4, code: 'ssh_input_backpressure', retry_after_ms: 5});
    ws.serverSend('terminal.input_rejected', {ch, iseq: 9, code: 'ssh_input_backpressure'});
    assert.deepEqual(errors, ['ssh_input_backpressure'], 'a lost keystroke is reported once; stale rejections are ignored');
    socket.disconnect();
});

test('a listener of ssh_connected or ssh_session_restored can type at once', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window, {}, []);
    socket.on('ssh_connected', data => socket.emit('ssh_input', {session_id: data.session_id, data: 'tmux attach\r'}));
    socket.on('ssh_session_restored', data => socket.emit('ssh_input', {session_id: data.session_id, data: 'again\r'}));
    const ch = await openTerminal(socket, ws);
    ws.serverSend('terminal.resync_required', {ch, session_id: 'sess-1', reason: 'backpressure'});
    const attach = ws.lastRequest('terminal.attach');
    ws.reply(attach.id, {ch: attach.p.ch, session_id: 'sess-1', seq: 0, full: true});
    await tick();
    assert.deepEqual(ws.frames(KIND_INPUT).map(f => [f.channel, f.seq, f.data]), [
        [ch, 1, 'tmux attach\r'], [attach.p.ch, 1, 'again\r'],
    ]);
    socket.disconnect();
});

test('oversized or orphaned input fails without reaching the server', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    await openTerminal(socket, ws);
    const results = [];
    socket.emit('ssh_input', {session_id: 'nope', data: 'x'}, r => results.push(r.code));
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'é'.repeat(70000)}, r => results.push(r.code));
    assert.deepEqual(results, ['not_found', 'ssh_input_too_large']);
    assert.equal(ws.frames(KIND_INPUT).length, 0);
    socket.disconnect();
});

test('resize, rename and keepalive are fire-and-forget messages', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const ch = await openTerminal(socket, ws);
    socket.emit('ssh_resize', {session_id: 'sess-1', rows: 40, cols: 120});
    socket.emit('save_session_name', {session_id: 'sess-1', display_name: 'prod'});
    socket.emit('keep_alive');
    const tail = ws.requests().slice(-3);
    assert.deepEqual(tail.map(r => [r.t, r.id, r.p]), [
        ['terminal.resize', undefined, {ch, cols: 120, rows: 40}],
        ['terminal.rename', undefined, {session_id: 'sess-1', name: 'prod'}],
        ['session.keepalive', undefined, {}],
    ]);
    socket.disconnect();
});

test('a closed session is announced once', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const closed = [];
    socket.on('ssh_disconnected', data => closed.push([data.session_id, data.reason]));
    await openTerminal(socket, ws);
    socket.emit('ssh_disconnect', {session_id: 'sess-1', preserve_tmux: true});
    const close = ws.lastRequest('terminal.close');
    assert.deepEqual(close.p, {session_id: 'sess-1'});
    ws.serverSend('terminal.closed', {session_id: 'sess-1', reason: 'User disconnected'});
    ws.reply(close.id, {});
    await tick();
    assert.deepEqual(closed, [['sess-1', 'User disconnected']]);
    socket.disconnect();
});

test('host-key and banner prompts map to the existing events and decisions', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    for (const event of ['ssh_host_key', 'ssh_auth_banner', 'ssh_host_key_closed']) socket.on(event, data => seen.push([event, data]));
    ws.serverSend('prompt.host_key', {prompt_id: 'p1', request_id: 'req_1', context: 'target', host: 'h', port: 22, key_type: 'ssh-ed25519', fingerprint: 'SHA256:x'});
    ws.serverSend('prompt.banner', {prompt_id: 'p2', request_id: 'req_1', context: 'jump_host', host: 'j', port: 22, banner: 'Welcome'});
    ws.serverSend('prompt.closed', {prompt_id: 'p2', request_id: 'req_1'});
    ws.serverSend('prompt.closed', {prompt_id: 'p1', request_id: 'req_1'});
    assert.deepEqual(seen.map(([event, data]) => [event, data.prompt_id, data.client_request_id]), [
        ['ssh_host_key', 'p1', 'req_1'], ['ssh_auth_banner', 'p2', 'req_1'], ['ssh_host_key_closed', 'p1', 'req_1'],
    ]);
    const answers = [];
    socket.emit('ssh_host_key_decision', {prompt_id: 'p1', client_request_id: 'req_1', accepted: true}, r => answers.push(r));
    socket.emit('ssh_auth_banner_decision', {prompt_id: 'p2', accepted: 'yes'});
    const [hostKey, banner] = ws.requests('prompt.answer');
    assert.deepEqual(hostKey.p, {prompt_id: 'p1', kind: 'host_key', accepted: true});
    assert.deepEqual(banner.p, {prompt_id: 'p2', kind: 'banner', accepted: false});
    ws.reply(hostKey.id, {});
    await tick();
    assert.deepEqual(plain(answers), [{success: true}]);
    socket.disconnect();
});

test('connect cancellation maps the result onto the acknowledgement of the Python release', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    for (const err of [null, {code: 'not_found'}, {code: 'conflict'}, {code: 'rate_limited'}]) {
        socket.emit('ssh_connect_cancel', {client_request_id: 'req_1'}, r => acks.push(r));
        const request = ws.lastRequest('terminal.cancel');
        assert.deepEqual(request.p, {request_id: 'req_1'});
        if (err) ws.fail(request.id, err);
        else ws.reply(request.id, {});
        await tick();
    }
    assert.deepEqual(plain(acks), [
        {success: true, cancelled: true},
        {success: false, cancelled: false, reason: 'not_found'},
        {success: false, cancelled: false, reason: 'already_committed'},
        {success: false, cancelled: false, reason: 'rate_limited'},
    ]);
    socket.disconnect();
});

test('a cancellation whose answer is lost is not reported as committed', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window, {reconnection: false});
    const acks = [];
    socket.emit('ssh_connect_cancel', {client_request_id: 'req_1'}, r => acks.push(r));
    ws.serverClose(1006);
    await tick();
    assert.deepEqual(plain(acks), [{success: false, cancelled: false, reason: 'unavailable'}]);
});

test('a late connection is discarded with the request id of its attempt', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('ssh_discard_late_connection', {session_id: 'sess-9', client_request_id: 'req_9'}, r => acks.push(r));
    const request = ws.lastRequest('terminal.discard_late');
    assert.deepEqual(request.p, {session_id: 'sess-9', request_id: 'req_9'});
    ws.reply(request.id, {});
    await tick();
    assert.deepEqual(plain(acks), [{success: true}]);
    socket.disconnect();
});

test('a failed re-attach ends the session in the page instead of leaving it connected', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const closed = [];
    socket.on('ssh_disconnected', data => closed.push([data.session_id, data.reason]));
    const ch = await openTerminal(socket, ws);
    ws.serverSend('terminal.resync_required', {ch, session_id: 'sess-1', reason: 'backpressure'});
    ws.fail(ws.lastRequest('terminal.attach').id, {code: 'not_found', message: 'Not found.'});
    await tick();
    assert.deepEqual(closed, [['sess-1', 'Not found.']]);
    const results = [];
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'x'}, r => results.push(r.code));
    assert.deepEqual(results, ['not_found']);
    socket.disconnect();
});

test('a duplicate rejection cannot rewind input before the rejected frame was resent', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const ch = await openTerminal(socket, ws);
    const acks = [];
    for (const data of ['a', 'b', 'c']) socket.emit('ssh_input', {session_id: 'sess-1', data, acknowledge_backpressure: true}, r => acks.push([data, r.success]));
    ws.serverSend('terminal.input_rejected', {ch, iseq: 2, code: 'ssh_input_backpressure', retry_after_ms: 5});
    ws.serverSend('terminal.input_rejected', {ch, iseq: 2, code: 'ssh_input_backpressure', retry_after_ms: 5});
    ws.serverSend('terminal.input_rejected', {ch, iseq: 1, code: 'ssh_input_backpressure', retry_after_ms: 5});
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'b'}, () => {});
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'c'}, () => {});
    assert.deepEqual(ws.frames(KIND_INPUT).map(f => [f.seq, f.data]), [[1, 'a'], [2, 'b'], [3, 'c'], [2, 'b'], [3, 'c']]);
    assert.deepEqual(acks, [['b', false], ['c', false]]);
    ws.serverSend('terminal.input_rejected', {ch, iseq: 2, code: 'ssh_input_backpressure', retry_after_ms: 5});
    socket.emit('ssh_input', {session_id: 'sess-1', data: 'b'}, () => {});
    assert.deepEqual(ws.frames(KIND_INPUT).at(-1), {kind: KIND_INPUT, flags: 1, channel: ch, seq: 2, data: 'b'},
        'a rejection of the resent frame is honoured again');
    socket.disconnect();
});

test('the input limit follows the runtime limits of the page', async () => {
    const window = loadShim({WEBSSH_SSH_INPUT_LIMITS: {maxEventBytes: 8}});
    const {socket, ws} = await connected(window);
    await openTerminal(socket, ws);
    const results = [];
    socket.emit('ssh_input', {session_id: 'sess-1', data: '12345678'}, r => results.push(r.success));
    socket.emit('ssh_input', {session_id: 'sess-1', data: '123456789'}, r => results.push(r.code));
    assert.deepEqual(results, ['ssh_input_too_large']);
    assert.equal(ws.frames(KIND_INPUT).length, 1);
    socket.disconnect();
});
