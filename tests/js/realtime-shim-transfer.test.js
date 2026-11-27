const assert = require('node:assert/strict');
const test = require('node:test');
const {loadShim, connected, tick} = require('./support/realtime-harness.js');

const plain = value => JSON.parse(JSON.stringify(value));

test('prepare_transfer sends transfer.prepare and acknowledges like Python', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.emit('prepare_transfer', {direction: 'download', source_id: 's:a', remote_path: '/d', request_id: 'r1', archive: true, extra: 1},
        ack => seen.push(ack));
    let request = ws.lastRequest('transfer.prepare');
    assert.deepEqual(request.p, {source_id: 's:a', request_id: 'r1', direction: 'download', remote_path: '/d', archive: true});
    ws.reply(request.id, {source_id: 's:a', request_id: 'r1', transfer_id: 't1', url: '/api/transfers/x/folder-download', expires_at: 1, direction: 'download'});
    socket.emit('prepare_transfer', {direction: 'upload', source_id: 's:a', remote_path: '/u', request_id: 'r2', conflict_policy: 'replace'},
        ack => seen.push(ack));
    request = ws.lastRequest('transfer.prepare');
    assert.equal(request.p.conflict_policy, 'replace');
    assert.equal(request.p.archive, undefined);
    ws.fail(request.id, {code: 'busy', message: 'transfer quota exceeded (per_user limit 2)'});
    await tick();
    assert.deepEqual(plain(seen), [
        {success: true, source_id: 's:a', request_id: 'r1', transfer_id: 't1', url: '/api/transfers/x/folder-download', expires_at: 1, direction: 'download'},
        {success: false, error: 'Transfer unavailable', source_id: 's:a', request_id: 'r2'},
    ]);
    socket.disconnect();
});

test('cancel_transfer reports the state and unavailable as a failure', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.emit('cancel_transfer', {transfer_id: 't1'}, ack => seen.push(ack));
    ws.reply(ws.lastRequest('transfer.cancel').id, {state: 'cancelling'});
    socket.emit('cancel_transfer', {transfer_id: 7}, ack => seen.push(ack));
    assert.deepEqual(ws.lastRequest('transfer.cancel').p, {transfer_id: ''});
    ws.reply(ws.lastRequest('transfer.cancel').id, {state: 'unavailable'});
    socket.emit('cancel_transfer', {transfer_id: 't3'}, ack => seen.push(ack));
    ws.fail(ws.lastRequest('transfer.cancel').id, {code: 'rate_limited', message: 'slow'});
    await tick();
    assert.deepEqual(plain(seen), [
        {success: true, state: 'cancelling'},
        {success: false, state: 'unavailable'},
        {success: false, state: 'unavailable'},
    ]);
    socket.disconnect();
});

test('a refused copy answers and pushes s2s_transfer_error with the public failure', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    socket.on('s2s_transfer_error', data => seen.push(['push', data]));
    const data = {source_id: 's:a', request_id: 'r1', source_path: '/a', destination_source_id: 's:b', dest_path: '/b', is_dir: false, conflict_policy: 'error'};
    socket.emit('transfer_server_to_server', data, ack => seen.push(['ack', ack]));
    const request = ws.lastRequest('transfer.copy');
    assert.deepEqual(request.p, {source_id: 's:a', request_id: 'r1', source_path: '/a', destination_source_id: 's:b', dest_path: '/b', conflict_policy: 'error'});
    ws.fail(request.id, {code: 'SOURCE_UNAVAILABLE', message: 'The file source is no longer available. Reconnect and try again.', details: {retryable: true}});
    socket.emit('transfer_server_to_server', {...data, request_id: 'r2'}, ack => seen.push(['ack', ack]));
    ws.fail(ws.lastRequest('transfer.copy').id, {code: 'invalid_request', message: 'invalid payload'});
    socket.emit('transfer_server_to_server', {...data, request_id: 'r3'}, ack => seen.push(['ack', ack]));
    ws.reply(ws.lastRequest('transfer.copy').id, {source_id: 's:a', request_id: 'r3', transfer_id: 't3', destination_source_id: 's:b'});
    await tick();
    const unavailable = {source_id: 's:a', request_id: 'r1', destination_source_id: 's:b', retryable: true,
        error_code: 'SOURCE_UNAVAILABLE', error: 'The file source is no longer available. Reconnect and try again.'};
    assert.deepEqual(plain(seen), [
        ['push', {...unavailable, transfer_id: null}],
        ['ack', {success: false, ...unavailable}],
        ['push', {source_id: 's:a', request_id: 'r2', destination_source_id: 's:b', error: 'Missing required fields', transfer_id: null}],
        ['ack', {success: false, source_id: 's:a', request_id: 'r2', destination_source_id: 's:b', error: 'Missing required fields'}],
        ['ack', {success: true, transfer_id: 't3', source_id: 's:a', request_id: 'r3', destination_source_id: 's:b'}],
    ]);
    socket.disconnect();
});

test('progress and finished events become the push events of today', async () => {
    const window = loadShim();
    const {socket, ws} = await connected(window);
    const seen = [];
    for (const name of ['transfer_progress', 'transfer_finished', 's2s_transfer_progress', 's2s_transfer_complete', 's2s_transfer_error']) {
        socket.on(name, data => seen.push([name, plain(data)]));
    }
    const copy = {source_id: 's:a', request_id: 'r1', destination_source_id: 's:b'};
    ws.serverSend('transfer.progress', {transfer_id: 'h', direction: 'upload', transferred: 5, total: 10});
    ws.serverSend('transfer.finished', {transfer_id: 'h', direction: 'download', status: 'failed', error_code: 'LIMIT_EXCEEDED',
        error: 'The transfer exceeds the configured limit.', retryable: false, limit_kind: 'download', limit_bytes: 10, actual_bytes: 11});
    ws.serverSend('transfer.finished', {transfer_id: 'p', status: 'cancelled'});
    ws.serverSend('transfer.progress', {transfer_id: 'c', direction: 'server_to_server', transferred: 3, total: 4, filename: 'f', copy});
    ws.serverSend('transfer.finished', {transfer_id: 'c', direction: 'server_to_server', status: 'completed', filename: 'f', source_path: '/a/f', dest_path: '/b/f', copy});
    ws.serverSend('transfer.finished', {transfer_id: 'd', direction: 'server_to_server', status: 'cancelled', error_code: 'CANCELLED',
        error: 'The transfer was cancelled.', retryable: false, copy});
    await tick();
    assert.deepEqual(seen, [
        ['transfer_progress', {transfer_id: 'h', direction: 'upload', transferred: 5, total: 10}],
        ['transfer_finished', {transfer_id: 'h', status: 'failed', error_code: 'LIMIT_EXCEEDED', error: 'The transfer exceeds the configured limit.',
            retryable: false, limit_kind: 'download', limit_bytes: 10, actual_bytes: 11, direction: 'download'}],
        ['transfer_finished', {transfer_id: 'p', status: 'cancelled'}],
        ['s2s_transfer_progress', {...copy, transfer_id: 'c', filename: 'f', transferred: 3, total: 4, percent: 75, status: 'transferring'}],
        ['s2s_transfer_complete', {...copy, transfer_id: 'c', filename: 'f', source_path: '/a/f', dest_path: '/b/f'}],
        ['s2s_transfer_error', {...copy, transfer_id: 'd', error_code: 'CANCELLED', error: 'The transfer was cancelled.', retryable: false}],
    ]);
    socket.disconnect();
});
