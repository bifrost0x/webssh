const assert = require('node:assert/strict');
const test = require('node:test');
const {loadShim, connected, tick} = require('./support/realtime-harness.js');

const plain = value => JSON.parse(JSON.stringify(value));

test('a directory page becomes directory_listing with the cursor of the request', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('directory_listing', data => seen.push(data));
    socket.emit('list_directory', {source_id: 'sftp-quick:a', request_id: 'r1', remote_path: '/srv', cursor: 0, extra: 1});
    let request = ws.lastRequest('files.list');
    assert.deepEqual(request.p, {source_id: 'sftp-quick:a', request_id: 'r1', remote_path: '/srv'});
    ws.reply(request.id, {source_id: 'sftp-quick:a', request_id: 'r1', path: '/srv', files: [{name: 'a'}], next_cursor: 'v1.x.1.y'});
    await tick();
    socket.emit('list_directory', {source_id: 'sftp-quick:a', request_id: 'r2', remote_path: '/srv', cursor: 'v1.x.1.y'});
    request = ws.lastRequest('files.list');
    assert.equal(request.p.cursor, 'v1.x.1.y');
    ws.reply(request.id, {source_id: 'sftp-quick:a', request_id: 'r2', path: '/srv', files: [], next_cursor: null});
    await tick();
    assert.deepEqual(plain(seen), [
        {source_id: 'sftp-quick:a', request_id: 'r1', path: '/srv', files: [{name: 'a'}], cursor: 0, next_cursor: 'v1.x.1.y'},
        {source_id: 'sftp-quick:a', request_id: 'r2', path: '/srv', files: [], cursor: 'v1.x.1.y', next_cursor: null},
    ]);
    socket.disconnect();
});

test('file failures arrive as error with the correlation members and the Python codes', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('error', data => seen.push(['error', data]));
    socket.on('preview_error', data => seen.push(['preview_error', data]));
    socket.on('edit_error', data => seen.push(['edit_error', data]));
    socket.emit('list_directory', {source_id: 's:a', request_id: 'r1', remote_path: '/x'});
    ws.fail(ws.lastRequest('files.list').id, {code: 'SOURCE_UNAVAILABLE', message: 'gone'});
    socket.emit('preview_file', {source_id: 's:a', request_id: 'r2', path: '/f'});
    ws.fail(ws.lastRequest('files.preview').id, {code: 'invalid_request', message: 'bad'});
    socket.emit('open_file_for_edit', {source_id: 's:a', request_id: 'r3', path: '/f'});
    ws.fail(ws.lastRequest('files.edit.open').id, {code: 'FILE_BINARY', message: 'Binary file cannot be edited.'});
    socket.emit('save_file', {source_id: 's:a', request_id: 'r4', path: '/f', content: 'x', expected_revision: 'e'});
    ws.fail(ws.lastRequest('files.edit.save').id, {code: 'SMB_RECOVERABLE_REPLACE_REQUIRED', message: 'm', details: {save_challenge: 'tok'}});
    await tick();
    assert.deepEqual(plain(seen), [
        ['error', {success: false, code: 'SOURCE_UNAVAILABLE', error: 'gone', operation: 'list_directory', source_id: 's:a', request_id: 'r1', path: '/x'}],
        ['preview_error', {success: false, code: 'INVALID_REQUEST', error: 'bad', operation: 'preview_file', source_id: 's:a', request_id: 'r2', path: '/f'}],
        ['edit_error', {success: false, code: 'FILE_BINARY', error: 'Binary file cannot be edited.', operation: 'open_file_for_edit', source_id: 's:a', request_id: 'r3', path: '/f'}],
        ['error', {save_challenge: 'tok', success: false, code: 'SMB_RECOVERABLE_REPLACE_REQUIRED', error: 'm', operation: 'save_file', source_id: 's:a', request_id: 'r4', path: '/f'}],
    ]);
    socket.disconnect();
});

test('rename acknowledges and pushes; its failure reaches the acknowledgement too', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('file_renamed', data => seen.push(['push', data]));
    socket.on('error', data => seen.push(['error', data.code]));
    const data = {source_id: 's:a', request_id: 'r1', old_path: '/a', new_path: '/b'};
    socket.emit('rename_file', data, ack => seen.push(['ack', ack]));
    ws.reply(ws.lastRequest('files.rename').id, data);
    socket.emit('rename_file', data, ack => seen.push(['ack', ack.code, ack.old_path]));
    ws.fail(ws.lastRequest('files.rename').id, {code: 'CONFLICT', message: 'exists'});
    await tick();
    assert.deepEqual(plain(seen), [
        ['push', {old_path: '/a', new_path: '/b', source_id: 's:a', request_id: 'r1'}],
        ['ack', {success: true, source_id: 's:a', request_id: 'r1', old_path: '/a', new_path: '/b'}],
        ['error', 'CONFLICT'],
        ['ack', 'CONFLICT', '/a'],
    ]);
    socket.disconnect();
});

test('cancelling a listing always succeeds and the image preview needs for_preview', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('cancel_directory_listing', {source_id: 's:a', request_id: 'r', cursor: 'v1.x.1.y'}, ack => acks.push(ack));
    ws.fail(ws.lastRequest('files.list.cancel').id, {code: 'rate_limited', message: 'slow down'});
    socket.emit('download_file_binary', {source_id: 's:a', request_id: 'r2', remote_path: '/i.png', for_preview: true});
    const image = ws.lastRequest('files.preview.image');
    assert.deepEqual(image.p, {source_id: 's:a', request_id: 'r2', remote_path: '/i.png', for_preview: true});
    const ready = [];
    socket.on('file_download_ready_binary', data => ready.push(data));
    ws.reply(image.id, {source_id: 's:a', request_id: 'r2', path: '/i.png', filename: 'i.png', file_data: 'UE5H', size: 3, for_preview: true, encoding: 'base64'});
    await tick();
    assert.deepEqual(plain(acks), [{success: true}]);
    assert.deepEqual(plain(ready), [{source_id: 's:a', request_id: 'r2', filename: 'i.png', file_data: 'UE5H', size: 3, for_preview: true, encoding: 'base64'}]);
    socket.disconnect();
});

test('Quick SFTP maps onto files.quick.open and answers with the events of today', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('quick_connect_success', data => seen.push(['ok', data]));
    socket.on('quick_connect_error', data => seen.push(['err', data]));
    socket.on('quick_disconnect_success', data => seen.push(['closed', data]));
    socket.emit('quick_connect', {host: 'h', port: '2222', username: 'u', credential_id: 'c1', credential_target_token: 'tok',
        password: 'ignored', client_request_id: 'quick_1', gateway_interaction: 1});
    let request = ws.lastRequest('files.quick.open');
    assert.deepEqual(plain(request.p), {host: 'h', username: 'u', credential_target_token: 'tok', client_request_id: 'quick_1',
        auth_type: 'password', interactive: true, port: 2222, saved_password: true, credential_id: 'c1'});
    ws.reply(request.id, {client_request_id: 'quick_1', connection_id: 'hX', host: 'h', port: 2222, username: 'u', file_source: {source_id: 'sftp-quick:hX'}});
    socket.emit('quick_connect', {host: 'h', username: 'u', key_id: 'k', client_request_id: 'quick_2'});
    request = ws.lastRequest('files.quick.open');
    assert.equal(request.p.auth_type, 'key');
    ws.fail(request.id, {code: 'busy', message: 'Maximum number of quick connections reached'});
    socket.emit('quick_disconnect', {connection_id: 'hX'});
    ws.reply(ws.lastRequest('files.quick.close').id, {connection_id: 'hX'});
    await tick();
    assert.deepEqual(plain(seen), [
        ['ok', {client_request_id: 'quick_1', connection_id: 'hX', host: 'h', port: 2222, username: 'u', file_source: {source_id: 'sftp-quick:hX'}}],
        ['err', {error: 'Maximum number of quick connections reached', code: 'busy', client_request_id: 'quick_2'}],
        ['closed', {connection_id: 'hX'}],
    ]);
    socket.disconnect();
});

test('a gateway Quick SFTP attempt is cancelled with the acknowledgement of the Python handler', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const acks = [];
    socket.emit('ssh_gateway_quick_cancel', {client_request_id: 'quick_1'}, ack => acks.push(ack));
    let request = ws.lastRequest('files.quick.cancel');
    assert.deepEqual(plain(request.p), {client_request_id: 'quick_1'});
    ws.reply(request.id, {});
    socket.emit('ssh_gateway_quick_cancel', {client_request_id: 'quick_1'}, ack => acks.push(ack));
    ws.fail(ws.lastRequest('files.quick.cancel').id, {code: 'not_found', message: ''});
    socket.emit('ssh_gateway_quick_cancel', {client_request_id: 'quick_2'}, ack => acks.push(ack));
    ws.fail(ws.lastRequest('files.quick.cancel').id, {code: 'conflict', message: 'The connection was already established.'});
    await tick();
    assert.deepEqual(plain(acks), [
        {success: true},
        {success: false, reason: 'not_found'},
        {success: false, reason: 'already_committed'},
    ]);
    socket.disconnect();
});

test('the session probe and the terminal directory reach the server', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('session_sftp_capability', data => seen.push(data));
    socket.emit('probe_session_sftp', {session_id: 's', request_id: 'r1'});
    ws.reply(ws.lastRequest('files.session.probe').id, {session_id: 's', request_id: 'r1', available: true});
    socket.emit('probe_session_sftp', {session_id: 's', request_id: 'r2'});
    ws.fail(ws.lastRequest('files.session.probe').id, {code: 'channel_rejected', message: 'refused'});
    const acks = [];
    socket.emit('request_session_directory', {session_id: 's'}, ack => acks.push(ack));
    ws.reply(ws.lastRequest('files.session.directory').id, {directory: {path: '/srv', shell: 'bash'}, reason: null});
    socket.emit('request_session_directory', {session_id: 's'}, ack => acks.push(ack));
    ws.fail(ws.lastRequest('files.session.directory').id, {code: 'rate_limited', message: 'slow'});
    await tick();
    assert.deepEqual(plain(seen), [
        {session_id: 's', request_id: 'r1', success: true, available: true},
        {session_id: 's', request_id: 'r2', success: false, available: false, reason: 'resource_shortage'},
    ]);
    assert.deepEqual(plain(acks), [
        {success: true, directory: {path: '/srv', shell: 'bash'}, reason: null},
        {success: false, directory: null, reason: 'busy'},
    ]);
    socket.disconnect();
});

test('a large editor answer is fetched once over HTTP and then pushed as edit_data', async () => {
    const fetched = [];
    const window = loadShim({fetch: (url, init) => {
        fetched.push([url, init.credentials, init.cache]);
        if (url.endsWith('/gone')) return Promise.resolve({ok: false, json: () => Promise.resolve({code: 'SOURCE_UNAVAILABLE', error: 'expired'})});
        return Promise.resolve({ok: true, json: () => Promise.resolve({source_id: 's:a', request_id: 'r1', path: '/big', content: 'x'.repeat(10), revision: 'v'})});
    }});
    const {socket, ws} = await connected(window, {path: '/root/socket.io'});
    const seen = [];
    socket.on('edit_data', data => seen.push(['data', data]));
    socket.on('edit_error', data => seen.push(['error', data.code, data.error]));
    socket.emit('open_file_for_edit', {source_id: 's:a', request_id: 'r1', path: '/big'});
    ws.reply(ws.lastRequest('files.edit.open').id, {source_id: 's:a', request_id: 'r1', path: '/big', size: 10, handoff: 'tok'});
    await tick(5);
    socket.emit('open_file_for_edit', {source_id: 's:a', request_id: 'r2', path: '/big'});
    ws.reply(ws.lastRequest('files.edit.open').id, {source_id: 's:a', request_id: 'r2', path: '/big', size: 10, handoff: 'gone'});
    await tick(5);
    assert.deepEqual(plain(fetched), [['/root/api/files/handoff/tok', 'same-origin', 'no-store'], ['/root/api/files/handoff/gone', 'same-origin', 'no-store']]);
    assert.deepEqual(plain(seen), [
        ['data', {source_id: 's:a', request_id: 'r1', path: '/big', content: 'xxxxxxxxxx', revision: 'v'}],
        ['error', 'SOURCE_UNAVAILABLE', 'expired'],
    ]);
    socket.disconnect();
});
