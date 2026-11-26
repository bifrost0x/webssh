const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
test('connection errors are bounded, sanitized and reset after connection', () => {
    const events = {};
    const notices = [];
    let mismatch = 0;
    const start = source.indexOf("    socket.on('connect_error'");
    const noticeStart = source.indexOf('    let connectionErrorNotice');
    const end = source.indexOf('    window.ModalManager', start);
    vm.runInNewContext(source.slice(noticeStart < 0 ? start : noticeStart, end), {
        socket: {on(event, handler) { events[event] = handler; }},
        showNotification(value) { notices.push(value); return () => {}; },
        socketProtocolMismatch: {handleMismatch() { mismatch++; }},
    });
    events.connect_error({message: 'secret-cookie', description: 'private-path'});
    events.connect_error({message: 'secret-cookie'});
    assert.equal(notices.length, 1);
    assert.doesNotMatch(JSON.stringify(notices), /secret-cookie|private-path/);
    assert.match(notices[0].message, /proxy|session/i);
    events.connect();
    events.connect_error({message: 'another failure'});
    assert.equal(notices.length, 2);
    events.connect_error({data: {code: 'socket_protocol_mismatch'}});
    assert.equal(mismatch, 1);
    assert.equal(notices.length, 2);
});

test('a connection limit shows the readable reason of the server', () => {
    const events = {};
    const notices = [];
    const start = source.indexOf('    let connectionErrorNotice');
    const end = source.indexOf('    window.ModalManager', start);
    vm.runInNewContext(source.slice(start, end), {
        socket: {on(event, handler) { events[event] = handler; }},
        showNotification(value) { notices.push(value); return () => {}; },
        socketProtocolMismatch: {handleMismatch() {}},
    });
    events.connect_error({data: {code: 'connection_limit', scope: 'user', message: 'at most 32 realtime connections per user are open'}});
    assert.equal(notices.length, 1);
    assert.equal(notices[0].message, 'Cannot connect to WebSSH: at most 32 realtime connections per user are open');
});
