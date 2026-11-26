const assert = require('node:assert/strict');
const test = require('node:test');
const {loadShim, connected, tick} = require('./support/realtime-harness.js');
const catalog = require('../../static/js/realtime-catalog.js');

const plain = value => JSON.parse(JSON.stringify(value));

test('every mapped event targets a type of the v1 catalog', () => {
    const v1 = new Set([
        'hosts.profile.list', 'hosts.profile.save', 'hosts.profile.delete', 'hosts.profile.organize',
        'hosts.profile.move', 'hosts.jump.list', 'hosts.jump.save', 'hosts.jump.delete',
        'hosts.socks.list', 'hosts.socks.save', 'hosts.socks.delete', 'keys.list', 'keys.upload',
        'keys.rename', 'keys.replace', 'keys.delete', 'settings.theme.set', 'settings.confirm_close.set',
        'settings.disconnect_action.set', 'notes.get', 'notes.save',
    ]);
    const mapped = new Set(Object.values(catalog.REQUESTS).map(entry => entry.type));
    assert.deepEqual([...mapped].sort(), [...v1].sort());
});

test('a save pushes the Python event before the acknowledgement', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const order = [];
    socket.on('profile_saved', data => order.push(['push', data]));
    socket.emit('save_profile', {name: 'web', host: 'h', tailscale_authorized: true}, ack => order.push(['ack', ack]));
    const request = ws.lastRequest('hosts.profile.save');
    assert.deepEqual(request.p, {name: 'web', host: 'h'});
    assert.match(request.id, /^c\d+$/);
    ws.reply(request.id, {profile: {id: 'p1', name: 'web'}});
    await tick();
    assert.deepEqual(plain(order), [
        ['push', {success: true, profile: {id: 'p1', name: 'web'}}],
        ['ack', {success: true, profile: {id: 'p1', name: 'web'}}],
    ]);
    socket.disconnect();
});

test('a failure keeps the code, repeats as error where Python did and pushes nothing', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('error', data => seen.push(['error', data]));
    socket.on('key_uploaded', data => seen.push(['push', data]));
    socket.emit('upload_key', {name: 'k', key_content: 'x', step_up: 'g'}, ack => seen.push(['ack', ack]));
    const request = ws.lastRequest('keys.upload');
    assert.equal(request.p.step_up, 'g');
    ws.fail(request.id, {code: 'invalid_value', message: 'Unsupported or invalid private key format'});
    await tick();
    assert.deepEqual(plain(seen), [
        ['error', {success: false, error: 'Unsupported or invalid private key format', code: 'invalid_value'}],
        ['ack', {success: false, code: 'invalid_value', error: 'Unsupported or invalid private key format'}],
    ]);
    socket.disconnect();
});

test('key changes the page answers itself are not repeated as error', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('error', data => seen.push(['error', data]));
    socket.emit('upload_key', {name: 'k', key_content: 'x'}, ack => seen.push(['ack', ack]));
    ws.fail(ws.lastRequest('keys.upload').id, {code: 'step_up_required', message: 'Confirm your identity to continue.'});
    socket.emit('replace_key', {key_id: 'k1', key_content: 'x'}, ack => seen.push(['ack', ack]));
    ws.fail(ws.lastRequest('keys.replace').id, {
        code: 'invalid_value', message: 'Enter the passphrase.', details: {passphrase_required: true},
    });
    socket.emit('delete_key', {key_id: 'k1'}, ack => seen.push(['ack', ack]));
    ws.fail(ws.lastRequest('keys.delete').id, {code: 'step_up_required', message: 'Confirm your identity to continue.'});
    await tick();
    assert.deepEqual(plain(seen), [
        ['ack', {success: false, code: 'step_up_required', error: 'Confirm your identity to continue.'}],
        ['ack', {passphrase_required: true, success: false, code: 'invalid_value', error: 'Enter the passphrase.'}],
        ['ack', {success: false, code: 'step_up_required', error: 'Confirm your identity to continue.'}],
    ]);
    socket.disconnect();
});

test('err.details reach the acknowledgement without replacing its own members', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('delete_jump_host', {jump_host_id: 'j'}, ack => acks.push(ack));
    ws.fail(ws.lastRequest('hosts.jump.delete').id, {
        code: 'conflict', message: 'In use.', details: {usages: ['web-01'], success: true, code: 'x'},
    });
    await tick();
    assert.deepEqual(plain(acks), [{usages: ['web-01'], success: false, code: 'conflict', error: 'In use.'}]);
    socket.disconnect();
});

test('host mutations repeat their failure as error like the Python release', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const errors = [];
    socket.on('error', data => errors.push(plain(data)));
    const cases = [
        ['delete_profile', 'hosts.profile.delete', {profile_id: 'p'}],
        ['save_jump_host', 'hosts.jump.save', {name: 'j'}],
        ['delete_jump_host', 'hosts.jump.delete', {jump_host_id: 'j'}],
        ['list_socks_proxies', 'hosts.socks.list', {}],
        ['save_socks_proxy', 'hosts.socks.save', {name: 's'}],
        ['delete_socks_proxy', 'hosts.socks.delete', {socks_proxy_id: 's'}],
    ];
    for (const [event, type, data] of cases) {
        socket.emit(event, data, () => {});
        ws.fail(ws.lastRequest(type).id, {code: 'conflict', message: 'In use.'});
    }
    await tick();
    assert.equal(errors.length, cases.length);
    assert.deepEqual(errors[0], {success: false, error: 'In use.', code: 'conflict'});
    socket.disconnect();
});

test('delete events carry the id of the request and key changes refresh the list', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('key_deleted', data => seen.push(['deleted', data.key_id]));
    socket.on('keys_list', data => seen.push(['list', data.keys.length]));
    socket.emit('delete_key', {key_id: 'k1'});
    ws.reply(ws.lastRequest('keys.delete').id, {});
    await tick();
    ws.reply(ws.lastRequest('keys.list').id, {keys: [{id: 'k2'}]});
    await tick();
    assert.deepEqual(seen, [['deleted', 'k1'], ['list', 1]]);
    socket.disconnect();
});

test('settings acknowledgements and the notepad keep their Python shapes', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    const notes = [];
    socket.on('notepad_data', data => notes.push(data.notepad));
    socket.emit('set_confirm_session_close', {enabled: true}, ack => acks.push(ack));
    ws.reply(ws.lastRequest('settings.confirm_close.set').id, {enabled: false});
    socket.emit('set_disconnect_session_action', {action: 'close'}, ack => acks.push(ack));
    ws.reply(ws.lastRequest('settings.disconnect_action.set').id, {});
    socket.emit('get_notepad');
    const get = ws.lastRequest('notes.get');
    assert.deepEqual(get.p, {});
    ws.reply(get.id, {text: 'todo'});
    socket.emit('save_notepad', {text: 'done'}, ack => acks.push(ack));
    ws.reply(ws.lastRequest('notes.save').id, {text: 'done'});
    await tick();
    assert.deepEqual(plain(acks), [
        {success: true, confirm_session_close: false},
        {success: true},
        {success: true},
    ], 'the stored value is reported, never the requested one');
    assert.deepEqual(notes, ['todo']);
    socket.disconnect();
});

test('events without a v1 type are answered locally and reported to the notice', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const reported = [];
    window.addEventListener('webssh:preview-unavailable', event => reported.push(event.detail.feature));
    const seen = [];
    socket.on('commands_list', data => seen.push(['commands', data]));
    socket.on('session_sftp_capability', data => seen.push(['sftp', data]));
    socket.on('error', data => seen.push(['error', data]));
    const sent = ws.sent.length;
    socket.emit('list_commands', {os_filter: 'all'});
    socket.emit('probe_session_sftp', {session_id: 's', request_id: 'r1'});
    socket.emit('request_herdr_snapshot', {session_id: 's'}, ack => seen.push(['ack', ack]));
    socket.timeout(10000).emit('resolve_command_set_parameters', {}, (error, ack) => seen.push(['timed', error, ack.code]));
    socket.emit('list_directory', {source_id: 'src', request_id: 'r2', path: '/'});
    socket.emit('file_source_disconnect', {});
    await tick();
    assert.equal(ws.sent.length, sent, 'nothing reaches the server');
    assert.deepEqual(plain(seen), [
        ['commands', {commands: [], available: false}],
        ['sftp', {success: true, session_id: 's', request_id: 'r1', available: false, reason: 'not_available_in_preview'}],
        ['ack', {success: false, code: 'not_available_in_preview', error: 'Not available in this preview yet.'}],
        ['timed', null, 'not_available_in_preview'],
        ['error', {success: false, code: 'not_available_in_preview', error: 'Not available in this preview yet.', source_id: 'src', request_id: 'r2', path: '/'}],
    ]);
    assert.deepEqual(reported, ['commands', 'files', 'terminalTools', 'commandSets', 'files', 'files']);
    socket.disconnect();
});

test('the unavailable message follows the page language', async () => {
    const window = loadShim({i18n: {t: key => (key === 'previewNotice.notAvailable' ? 'In dieser Vorschau noch nicht verfügbar.' : key)}});
    const {socket} = await connected(window);
    let message;
    socket.emit('list_directory', {}, ack => { message = ack.error; });
    await tick();
    assert.equal(message, 'In dieser Vorschau noch nicht verfügbar.');
    socket.disconnect();
});

test('volatile emits are dropped offline like any other emit', async () => {
    const window = loadShim();
    const socket = window.io({path: '/socket.io', autoConnect: false});
    assert.equal(typeof socket.volatile.emit, 'function');
    socket.volatile.emit('smb_quick_connect', {request_id: 'r'});
    assert.deepEqual(plain(socket.flags), {});
});
