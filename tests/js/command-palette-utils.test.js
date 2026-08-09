const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildItems,
} = require('../../static/js/command-palette-utils.js');

const labels = {
    activeSession: 'Active session',
    savedHost: 'Saved host',
};

const actions = [
    {
        id: 'quick-connect',
        label: 'Quick Connect',
        description: '',
        hint: 'Ctrl+Shift+N',
    },
];

const profiles = [
    {
        id: 'favorite-host',
        name: 'Production API',
        host: 'api.example.com',
        port: 2222,
        username: 'deploy',
        group: 'Customer systems',
        favorite: true,
        auth_type: 'key',
        key_id: 'secret-key-reference',
        password: 'never-project-this',
        key_content: 'private material',
        private_key: 'private material',
    },
    {
        id: 'ordinary-host',
        name: 'Backup NAS',
        host: 'nas.lan',
        port: 22,
        username: 'backup',
        group: 'Homelab',
        favorite: false,
    },
];

const sessions = [
    {
        id: 'connected-session',
        displayName: 'Live production shell',
        host: 'api.example.com',
        port: 2222,
        username: 'deploy',
        connected: true,
        authType: 'key',
        keyId: 'session-key-reference',
    },
    {
        id: 'disconnected-session',
        displayName: 'Dormant shell',
        host: 'old.example.com',
        port: 22,
        username: 'root',
        connected: false,
    },
];

function build(overrides = {}) {
    return buildItems({
        actions,
        profiles,
        sessions,
        query: '',
        labels,
        formatEndpoint: profile => `${profile.username}@${profile.host}:${profile.port}`,
        sessionLabel: session => session.displayName || `${session.username}@${session.host}`,
        ...overrides,
    });
}

test('empty query returns active sessions, favorite hosts, and actions only', () => {
    assert.deepEqual(build(), [
        {
            kind: 'session',
            id: 'connected-session',
            label: 'Live production shell',
            description: 'deploy@api.example.com:2222',
            hint: 'Active session',
        },
        {
            kind: 'profile',
            id: 'favorite-host',
            label: 'Production API',
            description: 'deploy@api.example.com:2222',
            hint: 'Saved host',
        },
        {
            kind: 'action',
            id: 'quick-connect',
            label: 'Quick Connect',
            description: '',
            hint: 'Ctrl+Shift+N',
        },
    ]);
});
test('search matches host metadata and translated action labels', () => {
    assert.deepEqual(build({ query: 'homelab' }).map(item => item.id), [
        'ordinary-host',
    ]);
    assert.deepEqual(build({ query: 'backup@nas' }).map(item => item.id), [
        'ordinary-host',
    ]);
    assert.deepEqual(build({ query: 'quick' }).map(item => item.id), [
        'quick-connect',
    ]);
    assert.deepEqual(build({ query: 'live production' }).map(item => item.id), [
        'connected-session',
    ]);
    assert.deepEqual(build({ query: 'dormant' }), []);
});

test('descriptors exclude authentication data and source references', () => {
    const result = build({ query: 'production' });
    const serialized = JSON.stringify(result);

    for (const forbidden of [
        'auth_type',
        'authType',
        'key_id',
        'keyId',
        'password',
        'key_content',
        'private_key',
        'secret-key-reference',
        'session-key-reference',
        'never-project-this',
        'private material',
    ]) {
        assert.equal(serialized.includes(forbidden), false, forbidden);
    }

    result[0].label = 'changed';
    assert.equal(sessions[0].displayName, 'Live production shell');
    assert.equal(profiles[0].name, 'Production API');
});

test('deduplicates descriptors and enforces a hard 50 item cap', () => {
    const manyActions = Array.from({ length: 70 }, (_, index) => ({
        id: `action-${index}`,
        label: `Action ${index}`,
        description: '',
        hint: '',
    }));

    const result = build({
        actions: [manyActions[0], manyActions[0], ...manyActions.slice(1)],
        profiles: [],
        sessions: [],
        limit: 500,
    });

    assert.equal(result.length, 50);
    assert.equal(new Set(result.map(item => `${item.kind}:${item.id}`)).size, 50);
});
