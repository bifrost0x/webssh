const assert = require('node:assert/strict');
const test = require('node:test');
const {create} = require('../../static/js/notepad-controller');

function harness() {
    const timers = new Map();
    const handlers = {};
    const requests = [];
    const state = {text: '', status: ''};
    let next = 0;
    const socket = {connected: true, on: (name, handler) => { handlers[name] = handler; },
        emit: (name, payload, ack) => requests.push({name, payload, ack})};
    const controller = create({socket, read: () => state.text,
        write: value => { state.text = value; }, status: value => { state.status = value; },
        setTimeout: (fn, ms) => { const id = ++next; timers.set(id, {fn, ms}); return id; },
        clearTimeout: id => timers.delete(id)});
    return {controller, state, socket, requests,
        edit(text) { state.text = text; controller.changed(); },
        disconnect() { socket.connected = false; handlers.disconnect(); },
        tick(ms) { for (const [id, timer] of [...timers]) if (timer.ms === ms) {timers.delete(id); timer.fn();} },
    };
}

test('waits for successful persistence acknowledgement before saying saved', () => {
    const h = harness();
    h.edit('note'); h.tick(300);
    assert.equal(h.state.status, 'saving');
    assert.equal(h.controller.hasUnsaved(), true);
    h.requests[0].ack({success: false});
    assert.equal(h.state.status, 'failed');
    assert.equal(h.controller.hasUnsaved(), true);
    h.edit('retry'); h.tick(300); h.requests[1].ack({success: true});
    assert.equal(h.state.status, 'saved');
    assert.equal(h.controller.hasUnsaved(), false);
});

test('keeps offline edits through reconnect reads and ignores stale acknowledgements', () => {
    const h = harness();
    h.edit('first'); h.tick(300); h.disconnect();
    h.edit('offline'); h.tick(300);
    assert.equal(h.requests.length, 1);
    assert.equal(h.state.status, 'offline');
    h.controller.receive('old server note');
    assert.equal(h.state.text, 'offline');
    h.socket.connected = true; h.controller.reconnect();
    h.requests[0].ack({success: true});
    assert.equal(h.controller.hasUnsaved(), true);
    assert.equal(h.requests[1].payload.text, 'offline');
    h.requests[1].ack({success: true});
    h.controller.receive('late old read');
    assert.equal(h.state.text, 'offline');
    assert.equal(h.state.status, 'saved');
});

test('serializes edits made while a save is pending', () => {
    const h = harness();
    h.edit('one'); h.tick(300); h.edit('two'); h.tick(300);
    assert.equal(h.requests.length, 1);
    h.requests[0].ack({success: true});
    assert.equal(h.requests.length, 2);
    assert.equal(h.requests[1].payload.text, 'two');
    assert.equal(h.state.status, 'saving');
    h.requests[1].ack({success: true});
    assert.equal(h.state.status, 'saved');
});

test('timeout leaves the note dirty and late acknowledgement cannot clear newer edits', () => {
    const h = harness();
    h.edit('one'); h.tick(300); h.tick(10000);
    assert.equal(h.state.status, 'failed');
    h.edit('two'); h.tick(300); h.requests[0].ack({success: true});
    assert.equal(h.controller.hasUnsaved(), true);
    assert.equal(h.state.status, 'saving');
});

test('checks the server character limit without rejecting valid non-BMP text', () => {
    const h = harness();
    h.edit('😀'.repeat(100001)); h.tick(300);
    assert.equal(h.requests.length, 0);
    assert.equal(h.state.status, 'tooLarge');
    h.edit('😀'.repeat(100000)); h.tick(300);
    assert.equal(h.requests.length, 1);
});
