const test = require('node:test');
const assert = require('node:assert/strict');

const SocketReconnectPolicy = require(
    '../../static/js/socket-reconnect-policy.js'
);

function createHarness() {
    const scheduled = [];
    const cancelled = [];
    const socket = {
        connectCalls: 0,
        connect() {
            this.connectCalls += 1;
        },
    };
    const policy = SocketReconnectPolicy.create(socket, {
        schedule(callback) {
            scheduled.push(callback);
            return scheduled.length;
        },
        cancel(timer) {
            cancelled.push(timer);
        },
    });
    return { cancelled, policy, scheduled, socket };
}

test('reconnects after a marked server eviction for SSH output resync', () => {
    const { policy, socket } = createHarness();

    policy.expectOutputResync();

    assert.equal(policy.handleDisconnect('io server disconnect'), true);
    assert.equal(socket.connectCalls, 1);
});

test('does not reconnect other server disconnects or transport failures', () => {
    const first = createHarness();
    assert.equal(first.policy.handleDisconnect('io server disconnect'), false);
    assert.equal(first.socket.connectCalls, 0);

    const second = createHarness();
    second.policy.expectOutputResync();
    assert.equal(second.policy.handleDisconnect('transport close'), false);
    assert.equal(second.socket.connectCalls, 0);
});

test('expires a resync marker if the matching disconnect never arrives', () => {
    const { policy, scheduled, socket } = createHarness();
    policy.expectOutputResync();

    scheduled[0]();

    assert.equal(policy.handleDisconnect('io server disconnect'), false);
    assert.equal(socket.connectCalls, 0);
});
