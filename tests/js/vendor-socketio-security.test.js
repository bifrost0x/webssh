const assert = require('node:assert/strict');
const test = require('node:test');

const io = require('../../static/vendor/socketio/socket.io.min.js');


function decoder() {
    return new io.Manager('http://127.0.0.1', { autoConnect: false }).decoder;
}


test('vendored Socket.IO rejects binary packets with zero attachments', () => {
    assert.throws(
        () => decoder().add('50-["event"]'),
        /Illegal attachments/,
    );
});


test('vendored Socket.IO bounds the number of pending binary attachments', () => {
    assert.throws(
        () => decoder().add('511-["event"]'),
        /too many attachments/,
    );
});
