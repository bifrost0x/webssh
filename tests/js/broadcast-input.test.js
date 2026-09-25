const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('broadcast submits multiline text through the text input path for each connected session', () => {
    const delivered = [];
    const context = {
        window: {
            socket: {connected: true},
            SSHInput: {sendText: (id, value) => delivered.push([id, value])},
        },
        SessionManager: {getAllSessions: () => [
            {id: 'one', connected: true},
            {id: 'offline', connected: false},
            {id: 'two', connected: true},
        ]},
        document: {addEventListener() {}},
    };
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/broadcast-input.js'), 'utf8');
    vm.runInNewContext(source, context);

    assert.equal(context.window.BroadcastInput.sendAll('first\nsecond'), 2);
    assert.deepEqual(delivered, [
        ['one', 'first\nsecond\r'],
        ['two', 'first\nsecond\r'],
    ]);
});
