const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createRestoreStatusFlow
} = require('../../static/js/restore-status-flow.js');

function memoryStorage() {
    const values = new Map();
    return {
        getItem: key => values.has(key) ? values.get(key) : null,
        setItem: (key, value) => values.set(key, String(value)),
        removeItem: key => values.delete(key)
    };
}

test('restore status survives idle race, restart, and reauthentication reload', async () => {
    const storage = memoryStorage();
    const scheduled = [];
    const presented = [];
    let statusAttempt = 0;
    let readyAttempt = 0;
    let reloads = 0;

    const flow = createRestoreStatusFlow({
        storage,
        schedule: callback => scheduled.push(callback),
        fetchStatus: async () => {
            statusAttempt += 1;
            if (statusAttempt === 1) {
                return { state: 'idle', message: null };
            }
            if (statusAttempt === 2) {
                return { state: 'preparing', message: 'Preparing restore' };
            }
            throw new TypeError('fetch failed');
        },
        checkReady: async () => {
            readyAttempt += 1;
            return readyAttempt === 2;
        },
        present: status => presented.push(status.state),
        presentRestarting: () => presented.push('restarting'),
        reload: () => { reloads += 1; }
    });

    flow.markPending();
    await flow.poll();
    assert.deepEqual(presented, []);
    assert.equal(scheduled.length, 1);

    await scheduled.shift()();
    assert.deepEqual(presented, ['preparing']);
    assert.equal(scheduled.length, 1);

    await scheduled.shift()();
    assert.deepEqual(presented, ['preparing', 'restarting']);
    assert.equal(scheduled.length, 1);

    await scheduled.shift()();
    assert.equal(reloads, 0);
    assert.equal(scheduled.length, 1);
    await scheduled.shift()();
    assert.equal(reloads, 1);
    assert.equal(flow.isPending(), true);

    const afterLogin = createRestoreStatusFlow({
        storage,
        schedule: callback => scheduled.push(callback),
        fetchStatus: async () => ({
            state: 'succeeded',
            message: 'Restore completed'
        }),
        checkReady: async () => true,
        present: status => presented.push(status.state),
        presentRestarting: () => presented.push('restarting'),
        reload: () => { reloads += 1; }
    });

    assert.equal(afterLogin.isPending(), true);
    await afterLogin.resume();
    assert.equal(afterLogin.isPending(), false);
    assert.deepEqual(presented, ['preparing', 'restarting', 'succeeded']);
});

test('restore polling continues when session storage is unavailable', async () => {
    const scheduled = [];
    const storage = {
        getItem: () => { throw new Error('storage blocked'); },
        setItem: () => { throw new Error('storage blocked'); },
        removeItem: () => { throw new Error('storage blocked'); }
    };
    const flow = createRestoreStatusFlow({
        storage,
        schedule: callback => scheduled.push(callback),
        fetchStatus: async () => ({ state: 'idle', message: null }),
        checkReady: async () => false,
        present: () => {},
        presentRestarting: () => {},
        reload: () => {}
    });

    assert.doesNotThrow(() => flow.markPending());
    assert.equal(flow.isPending(), true);
    await flow.poll();
    assert.equal(scheduled.length, 1);
});
