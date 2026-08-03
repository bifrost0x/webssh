const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createConnectionLauncher,
} = require('../../static/js/connection-launcher.js');

function profile(overrides = {}) {
    return {
        id: 'profile-1',
        host: 'server.example',
        port: 22,
        username: 'alice',
        auth_type: 'key',
        key_id: 'target-key',
        ...overrides,
    };
}

function dependencies(overrides = {}) {
    const profiles = new Map([['profile-1', profile()]]);
    return {
        getProfile: id => profiles.get(id),
        getContext: () => ({
            keys: [{ id: 'target-key', usable: true }],
            jumpHosts: [],
        }),
        getDefaultPaneIndex: () => 4,
        isBusy: () => false,
        startConnection: () => true,
        openReview: () => {},
        notify: () => {},
        refreshProfiles: () => {},
        ...overrides,
    };
}

test('launches a complete profile directly without opening review', () => {
    const calls = [];
    const launcher = createConnectionLauncher(dependencies({
        startConnection: (data, pane) => {
            calls.push(['connect', data, pane]);
            return true;
        },
        openReview: (...args) => calls.push(['review', ...args]),
    }));

    assert.equal(launcher.launch('profile-1', 2), 'connect');
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], 'connect');
    assert.equal(calls[0][2], 2);
    assert.equal(calls[0][1].key_id, 'target-key');
});

test('uses the default pane and opens review for interactive profiles', () => {
    const calls = [];
    const launcher = createConnectionLauncher(dependencies({
        getProfile: () => profile({ auth_type: 'password', key_id: null }),
        startConnection: (...args) => calls.push(['connect', ...args]),
        openReview: (...args) => calls.push(['review', ...args]),
    }));

    assert.equal(launcher.launch('profile-1'), 'review');
    assert.deepEqual(calls, [['review', 'profile-1', 4, 'password']]);
});

test('rejects busy and missing profiles without starting a connection', () => {
    const busyCalls = [];
    const busy = createConnectionLauncher(dependencies({
        isBusy: () => true,
        startConnection: (...args) => busyCalls.push(['connect', ...args]),
        openReview: (...args) => busyCalls.push(['review', ...args]),
        notify: (...args) => busyCalls.push(['notify', ...args]),
    }));
    assert.equal(busy.launch('profile-1'), 'rejected');
    assert.deepEqual(busyCalls.map(call => call[0]), ['notify']);

    const missingCalls = [];
    const missing = createConnectionLauncher(dependencies({
        getProfile: () => null,
        startConnection: (...args) => missingCalls.push(['connect', ...args]),
        openReview: (...args) => missingCalls.push(['review', ...args]),
        notify: (...args) => missingCalls.push(['notify', ...args]),
        refreshProfiles: () => missingCalls.push(['refresh']),
    }));
    assert.equal(missing.launch('missing'), 'rejected');
    assert.deepEqual(
        missingCalls.map(call => call[0]),
        ['notify', 'refresh'],
    );
});

test('falls back to review when strict request construction rejects data', () => {
    const calls = [];
    const launcher = createConnectionLauncher(dependencies({
        getProfile: () => profile({ host: '   ' }),
        startConnection: (...args) => calls.push(['connect', ...args]),
        openReview: (...args) => calls.push(['review', ...args]),
    }));

    assert.equal(launcher.launch('profile-1', 1), 'review');
    assert.deepEqual(calls, [['review', 'profile-1', 1, 'review']]);
});

test('validates every required dependency', () => {
    for (const name of [
        'getProfile',
        'getContext',
        'getDefaultPaneIndex',
        'isBusy',
        'startConnection',
        'openReview',
        'notify',
        'refreshProfiles',
    ]) {
        const deps = dependencies();
        delete deps[name];
        assert.throws(
            () => createConnectionLauncher(deps),
            new RegExp(`requires ${name}\\(\\)`),
        );
    }
});
