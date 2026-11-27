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
        'prompt.respond', 'gateway.input', 'gateway.ack',
        'insights.sample', 'inventory.sample', 'herdr.snapshot',
        'files.list', 'files.list.cancel', 'files.home', 'files.preview', 'files.preview.image', 'files.edit.open',
        'files.edit.save', 'files.mkdir', 'files.create', 'files.rename', 'files.delete', 'files.source.close',
        'files.quick.open', 'files.quick.cancel', 'files.quick.close', 'files.session.probe', 'files.session.directory',
        'smb.share.list', 'smb.share.save', 'smb.share.delete', 'smb.connect', 'smb.connect.cancel',
        'permissions.get', 'permissions.set', 'permissions.job.prepare', 'permissions.job.get',
        'permissions.job.apply', 'permissions.job.cancel',
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

test('the error event of a refused deletion carries the usages like the Python release', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const errors = [];
    socket.on('error', data => errors.push(plain(data)));
    socket.emit('delete_socks_proxy', {socks_proxy_id: 's'}, () => {});
    ws.fail(ws.lastRequest('hosts.socks.delete').id, {
        code: 'conflict', message: 'SOCKS proxy is used by 2 profiles', details: {usages: ['web-01', 'db']},
    });
    socket.emit('delete_jump_host', {jump_host_id: 'j'});
    ws.fail(ws.lastRequest('hosts.jump.delete').id, {
        code: 'conflict', message: 'Jump host is used by 1 profile', details: {usages: ['web-01']},
    });
    await tick();
    assert.deepEqual(errors, [
        {usages: ['web-01', 'db'], success: false, code: 'conflict', error: 'SOCKS proxy is used by 2 profiles'},
        {usages: ['web-01'], success: false, code: 'conflict', error: 'Jump host is used by 1 profile'},
    ]);
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
    socket.emit('list_command_sets', {}, ack => seen.push(['ack', ack]));
    socket.timeout(10000).emit('resolve_command_set_parameters', {}, (error, ack) => seen.push(['timed', error, ack.code]));
    socket.emit('cancel_transfer', {source_id: 'src', request_id: 'r2', path: '/'});
    await tick();
    assert.equal(ws.sent.length, sent, 'nothing reaches the server');
    assert.deepEqual(plain(seen), [
        ['commands', {commands: [], available: false}],
        ['ack', {success: false, code: 'not_available_in_preview', error: 'Not available in this preview yet.'}],
        ['timed', null, 'not_available_in_preview'],
        ['error', {success: false, code: 'not_available_in_preview', error: 'Not available in this preview yet.', source_id: 'src', request_id: 'r2', path: '/'}],
    ]);
    assert.deepEqual(reported, ['commands', 'commandSets', 'commandSets', 'files']);
    socket.disconnect();
});

test('the unavailable message follows the page language', async () => {
    const window = loadShim({i18n: {t: key => (key === 'previewNotice.notAvailable' ? 'In dieser Vorschau noch nicht verfügbar.' : key)}});
    const {socket} = await connected(window);
    let message;
    socket.emit('prepare_transfer', {}, ack => { message = ack.error; });
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

// The end-to-end hooks: e2e_<name> is requested as e2e.<name> and
// acknowledged with the plain result; the server event e2e.<name> arrives
// as e2e_<name>.
test('end-to-end hooks map to the reserved e2e namespace', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('e2e_workspace_restore', {count: 2}, result => acks.push(result));
    const restore = ws.lastRequest('e2e.workspace_restore');
    assert.deepEqual(restore.p, {count: 2});
    ws.reply(restore.id, {ok: true, session_ids: ['a', 'b']});
    socket.emit('e2e_output_load', result => acks.push(result));
    const load = ws.lastRequest('e2e.output_load');
    assert.deepEqual(load.p, {});
    ws.fail(load.id, {code: 'unknown_type', message: 'Unknown message type.'});
    const done = [];
    socket.on('e2e_output_load_done', data => done.push(data));
    ws.serverSend('e2e.output_load_done', {counts: [1], peak: 3, elapsed_ms: 10, aborted: false});
    await tick();
    assert.deepEqual(plain(acks), [
        {ok: true, session_ids: ['a', 'b']},
        {success: false, code: 'unknown_type', error: 'Unknown message type.'},
    ]);
    assert.deepEqual(plain(done), [{counts: [1], peak: 3, elapsed_ms: 10, aborted: false}]);
    assert.equal(catalog.e2eEvent('e2e.Bad'), null);
    assert.equal(catalog.e2eEvent('hosts.profile.list'), null);
    socket.disconnect();
});

test('gateway prompts, setup and output arrive as the Socket.IO events of today', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    for (const name of ['ssh_gateway_challenge', 'ssh_gateway_progress', 'ssh_gateway_output']) {
        socket.on(name, data => seen.push([name, plain(data)]));
    }
    ws.serverSend('prompt.interactive', {prompt_id: 'p1', request_id: 'gateway_1', context: 'target', title: 'Warpgate',
        instructions: 'Code', prompts: [{label: 'OTP: ', echo: true}], expires_in: 120});
    ws.serverSend('gateway.setup', {request_id: 'gateway_1', phase: 'setup'});
    ws.serverSend('gateway.output', {request_id: 'gateway_1', sequence: 1, data: 'Trust? '});
    await tick();
    assert.deepEqual(seen, [
        ['ssh_gateway_challenge', {client_request_id: 'gateway_1', challenge_id: 'p1', context: 'target', title: 'Warpgate',
            instructions: 'Code', prompts: [{label: 'OTP: ', echo: true}]}],
        ['ssh_gateway_progress', {client_request_id: 'gateway_1', phase: 'setup'}],
        ['ssh_gateway_output', {client_request_id: 'gateway_1', sequence: 1, data: 'Trust? '}],
    ]);
    socket.disconnect();
});

test('detected host facts arrive as host_platform and host_maintenance', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    for (const name of ['host_platform', 'host_maintenance']) {
        socket.on(name, data => seen.push([name, plain(data)]));
    }
    const identity = {state: 'detected', platform: 'debian', family: null, os_id: null, os_version: '12', virt: 'vm',
        graphical: false, guests: null, services: ['docker'], container_access: 'ok'};
    ws.serverSend('hostops.discovery.platform', {profile_id: 'p1', platform: 'debian', services: ['docker'], identity});
    ws.serverSend('hostops.discovery.platform', {profile_id: 'p2'});
    ws.serverSend('hostops.discovery.maintenance', {profile_id: 'p3'});
    await tick();
    assert.deepEqual(seen, [
        ['host_platform', {profile_id: 'p1', platform: 'debian', services: ['docker'], identity}],
        ['host_platform', {profile_id: 'p2'}],
        ['host_maintenance', {profile_id: 'p3'}],
    ]);
    socket.disconnect();
});

test('gateway answers, input and acks become v1 requests', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('ssh_gateway_answer', {client_request_id: 'gateway_1', challenge_id: 'p1', answers: ['123456']}, a => acks.push(a));
    const answer = ws.lastRequest('prompt.respond');
    assert.deepEqual(answer.p, {request_id: 'gateway_1', prompt_id: 'p1', answers: ['123456']});
    ws.reply(answer.id, {});
    socket.emit('ssh_gateway_input', {client_request_id: 'gateway_1', data: 'y'});
    assert.deepEqual(ws.lastRequest('gateway.input').p, {request_id: 'gateway_1', data: 'y'});
    socket.emit('ssh_gateway_ack', {client_request_id: 'gateway_1', sequence: 3});
    assert.deepEqual(ws.lastRequest('gateway.ack').p, {request_id: 'gateway_1', sequence: 3});
    await tick();
    assert.deepEqual(plain(acks), [{success: true}]);
    socket.disconnect();
});

test('insights, the inventory and Herdr reach the server and answer as Python did', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('session_insights', data => seen.push(['insights', data]));
    socket.on('session_runtime_inventory', data => seen.push(['inventory', data]));
    socket.emit('request_session_insights', {session_id: 's1', request_id: 'r1', include_diagnostics: true});
    const insights = ws.lastRequest('insights.sample');
    assert.deepEqual(plain(insights.p), {session_id: 's1', request_id: 'r1', include_diagnostics: true});
    ws.reply(insights.id, {success: true, session_id: 's1', request_id: 'r1', stats: {os_name: 'Linux'}});
    socket.emit('request_session_runtime_inventory', {session_id: 7, request_id: 'r2', extra: 'x'});
    const inventory = ws.lastRequest('inventory.sample');
    assert.deepEqual(plain(inventory.p), {session_id: '', request_id: 'r2'}, 'only strings reach the server');
    ws.reply(inventory.id, {success: false, session_id: '', request_id: '', error: 'Runtime inventory unavailable'});
    let herdr;
    socket.emit('request_herdr_snapshot', {session_id: 's1'}, ack => { herdr = ack; });
    const snapshot = ws.lastRequest('herdr.snapshot');
    assert.deepEqual(plain(snapshot.p), {session_id: 's1'});
    ws.reply(snapshot.id, {success: false, agents: [], truncated: false, reason: 'not_enabled'});
    await tick();
    assert.deepEqual(plain(seen), [
        ['insights', {success: true, session_id: 's1', request_id: 'r1', stats: {os_name: 'Linux'}}],
        ['inventory', {success: false, session_id: '', request_id: '', error: 'Runtime inventory unavailable'}],
    ]);
    assert.deepEqual(plain(herdr), {success: false, agents: [], truncated: false, reason: 'not_enabled'});
    socket.disconnect();
});

test('permission jobs reach the server and answer as the Python events', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('file_permissions_job', data => seen.push(['job', data]));
    socket.on('file_permissions_changed', data => seen.push(['changed', data]));
    socket.on('error', data => seen.push(['error', data]));
    socket.emit('prepare_file_permissions', {source_id: 'src', request_id: 'r1', paths: ['/a'], recursive: true, file_mode: '640', directory_mode: '750', extra: 1});
    const prepare = ws.lastRequest('permissions.job.prepare');
    assert.deepEqual(prepare.p, {source_id: 'src', request_id: 'r1', paths: ['/a'], recursive: true, file_mode: '640', directory_mode: '750'});
    ws.reply(prepare.id, {job_id: 'j1', state: 'scanning'});
    await tick();
    socket.emit('apply_file_permissions_job', {source_id: 'src', request_id: 'r2', job_id: 'j1', paths: ['/b'], file_mode: '777'});
    const apply = ws.lastRequest('permissions.job.apply');
    assert.deepEqual(apply.p, {source_id: 'src', request_id: 'r2', job_id: 'j1'});
    ws.fail(apply.id, {code: 'busy', message: 'Another permission change is still running. Try again in a moment.'});
    await tick();
    socket.emit('set_file_permissions', {source_id: 'src', request_id: 'r3', path: '/a', mode: '640', expected_metadata: 't'});
    const set = ws.lastRequest('permissions.set');
    ws.fail(set.id, {code: 'MODE_MISMATCH', message: 'x', details: {actual_mode: '600'}});
    await tick();
    assert.deepEqual(plain(seen), [
        ['job', {job_id: 'j1', state: 'scanning', operation: 'prepare_file_permissions', source_id: 'src', request_id: 'r1'}],
        ['error', {success: false, code: 'BUSY', error: 'Another permission change is still running. Try again in a moment.',
            operation: 'apply_file_permissions_job', source_id: 'src', request_id: 'r2'}],
        ['error', {actual_mode: '600', success: false, code: 'MODE_MISMATCH', error: 'x', operation: 'set_file_permissions', source_id: 'src', request_id: 'r3'}],
    ]);
    socket.disconnect();
});
