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
