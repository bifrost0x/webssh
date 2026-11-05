const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(session) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const notices = [], cleaned = [];
    let handler;
    const manager = {
        getSession: () => session,
        updateSessionStatus(_id, status) { if (session) session.connected = status !== 'disconnected'; },
    };
    vm.runInNewContext(source.slice(source.indexOf("    socket.on('ssh_disconnected'"), source.indexOf("    socket.on('session_timeout_warning'")), {
        socket: {on(_name, fn) {handler = fn;}},
        cancelledSessionIds: new Set(), SessionManager: manager,
        showNotification: (...args) => notices.push(args),
        window: {sftpFileManager: {handleSessionDisconnected: id => cleaned.push(id)}},
    });
    return {handler, notices, cleaned};
}

test('disconnect acknowledgements do not warn after the user has closed a session', () => {
    const {handler, notices, cleaned} = setup(null);
    handler({session_id: 'closed', reason: 'Connection closed'});
    handler({session_id: 'closed', reason: 'User requested disconnect'});
    assert.equal(notices.length, 0);
    assert.equal(cleaned.length, 2);
});

test('unexpected disconnect warns once while still updating session and file state', () => {
    const session = {connected: true};
    const {handler, notices, cleaned} = setup(session);
    handler({session_id: 'live', reason: 'Connection closed'});
    handler({session_id: 'live', reason: 'Connection closed'});
    assert.equal(notices.length, 1);
    assert.equal(session.connected, false);
    assert.equal(cleaned.length, 2);
});
