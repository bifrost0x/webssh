const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildDirectConnectionData,
    buildProfileSections,
    determineLaunchMode,
    filterAndSortProfiles,
    formatEndpoint,
    resolveProfileDrop,
    usesAdvancedConnectionSettings,
} = require('../../static/js/profile-launcher-utils.js');

test('detects only saved settings that belong in the advanced connection section', () => {
    assert.equal(usesAdvancedConnectionSettings({}), false);
    assert.equal(usesAdvancedConnectionSettings({startup_mode: 'none'}), false);
    assert.equal(usesAdvancedConnectionSettings({jump_host_id: 'jump-1'}), true);
    assert.equal(usesAdvancedConnectionSettings({startup_mode: 'command_set'}), true);
    assert.equal(usesAdvancedConnectionSettings({command_id: 'command-1'}), true);
    assert.equal(usesAdvancedConnectionSettings({startup_commands: 'uptime'}), true);
    assert.equal(usesAdvancedConnectionSettings({use_tmux: true}), true);
});

test('filters profiles across name endpoint user and group', () => {
    const profiles = [
        {
            id: 'a',
            name: 'API',
            host: 'api.example.com',
            username: 'deploy',
            group: 'Production',
        },
        {
            id: 'b',
            name: 'NAS',
            host: 'nas.lan',
            username: 'backup',
            group: 'Homelab',
        },
    ];

    assert.deepEqual(
        filterAndSortProfiles(profiles, 'backup').map(item => item.id),
        ['b'],
    );
    assert.deepEqual(
        filterAndSortProfiles(profiles, 'production').map(item => item.id),
        ['a'],
    );
    assert.deepEqual(
        filterAndSortProfiles(profiles, 'API.EXAMPLE').map(item => item.id),
        ['a'],
    );
});

test('builds favorites first then named groups without duplicates', () => {
    const sections = buildProfileSections([
        { id: 'b', name: 'NAS', group: 'Homelab' },
        { id: 'a', name: 'API', group: 'Production', favorite: true },
        { id: 'c', name: 'Worker', group: 'production' },
        { id: 'd', name: 'Loose host' },
    ], '', { favorites: 'Favorites', ungrouped: 'Ungrouped' });

    assert.deepEqual(
        sections.map(section => [
            section.label,
            section.profiles.map(item => item.id),
        ]),
        [
            ['Favorites', ['a']],
            ['Homelab', ['b']],
            ['Production', ['c']],
            ['Ungrouped', ['d']],
        ],
    );
    assert.deepEqual(
        sections.flatMap(section => section.profiles).map(item => item.id),
        ['a', 'b', 'c', 'd'],
    );
});

test('uses persisted order only after a whole group has positions', () => {
    const sections = buildProfileSections([
        { id: 'legacy-2', name: 'Legacy second', group: 'Ops' },
        { id: 'ordered-2', name: 'Ordered second', group: 'Ops', sort_order: 1 },
        { id: 'legacy-1', name: 'Legacy first', group: 'Ops' },
        { id: 'ordered-1', name: 'Ordered first', group: 'Ops', sort_order: 0 },
    ]);

    assert.deepEqual(
        sections[0].profiles.map(item => item.id),
        ['legacy-2', 'ordered-2', 'legacy-1', 'ordered-1'],
    );
});

test('resolves same-group insertion boundaries after removing the dragged item', () => {
    const profiles = [
        { id: 'a', group: 'Ops', sort_order: 0 },
        { id: 'b', group: 'Ops', sort_order: 1 },
        { id: 'c', group: 'Ops', sort_order: 2 },
    ];

    assert.deepEqual(resolveProfileDrop(profiles, 'a', 'Ops', 2), {
        profileId: 'a',
        expectedSourceGroup: 'Ops',
        targetGroup: 'Ops',
        targetIndex: 1,
    });
    assert.equal(resolveProfileDrop(profiles, 'b', 'Ops', 2), null);
    assert.deepEqual(resolveProfileDrop(profiles, 'c', 'Ops', 0), {
        profileId: 'c',
        expectedSourceGroup: 'Ops',
        targetGroup: 'Ops',
        targetIndex: 0,
    });
});

test('resolves cross-group and ungrouped drops with clamped target positions', () => {
    const profiles = [
        { id: 'a', group: 'Ops', sort_order: 0 },
        { id: 'b', group: 'Apps', sort_order: 0 },
        { id: 'c', group: 'Apps', sort_order: 1 },
    ];

    assert.deepEqual(resolveProfileDrop(profiles, 'a', 'Apps', 99), {
        profileId: 'a',
        expectedSourceGroup: 'Ops',
        targetGroup: 'Apps',
        targetIndex: 2,
    });
    assert.deepEqual(resolveProfileDrop(profiles, 'b', '', 0), {
        profileId: 'b',
        expectedSourceGroup: 'Apps',
        targetGroup: '',
        targetIndex: 0,
    });
    assert.equal(resolveProfileDrop(profiles, 'missing', 'Apps', 0), null);
    assert.equal(resolveProfileDrop(profiles, 'a', 'Apps', -1), null);
});

test('maps visible drop boundaries around derived favorites to full group order', () => {
    const profiles = [
        { id: 'favorite', group: 'Ops', favorite: true, sort_order: 0 },
        { id: 'a', group: 'Ops', sort_order: 1 },
        { id: 'b', group: 'Ops', sort_order: 2 },
        { id: 'target-favorite', group: 'Apps', favorite: true, sort_order: 0 },
        { id: 'target', group: 'Apps', sort_order: 1 },
    ];

    assert.deepEqual(resolveProfileDrop(profiles, 'a', 'Ops', 2), {
        profileId: 'a',
        expectedSourceGroup: 'Ops',
        targetGroup: 'Ops',
        targetIndex: 2,
    });
    assert.deepEqual(resolveProfileDrop(profiles, 'b', 'Apps', 0), {
        profileId: 'b',
        expectedSourceGroup: 'Ops',
        targetGroup: 'Apps',
        targetIndex: 1,
    });
});

const keys = [
    { id: 'target-key', usable: true },
    { id: 'jump-key', usable: true },
];
const jumpHosts = [
    {
        id: 'jump-with-key',
        host: 'jump.example',
        port: 2222,
        username: 'jumper',
        auth_type: 'key',
        key_id: 'jump-key',
    },
    {
        id: 'jump-with-password',
        host: 'jump.example',
        port: 22,
        username: 'jumper',
        auth_type: 'password',
        key_id: null,
    },
];

function profile(overrides = {}) {
    return {
        id: 'profile-1',
        name: 'Production',
        host: 'server.example',
        port: 22,
        username: 'deploy',
        auth_type: 'key',
        key_id: 'target-key',
        ...overrides,
    };
}

test('builds a complete key profile request without mutating inputs', () => {
    const candidate = profile({
        username: ' alice ',
        use_tmux: true,
        startup_mode: 'command',
        command_id: 'command-1',
        parameters_override: '',
    });
    const before = structuredClone(candidate);

    assert.deepEqual(
        buildDirectConnectionData(candidate, { keys, jumpHosts }),
        {
            host: 'server.example',
            port: 22,
            username: 'alice',
            auth_type: 'key',
            key_id: 'target-key',
            use_tmux: true,
            startup_mode: 'command',
            command_id: 'command-1',
            parameters_override: '',
        },
    );
    assert.deepEqual(candidate, before);
});

test('builds Tailscale, jump-host, and legacy post-connect payloads', () => {
    assert.deepEqual(buildDirectConnectionData(profile({
        auth_type: 'tailscale',
        key_id: null,
        tailscale_authorized: true,
    }), { keys, jumpHosts }), {
        host: 'server.example',
        port: 22,
        username: 'deploy',
        auth_type: 'tailscale',
        startup_mode: 'none',
    });

    assert.deepEqual(buildDirectConnectionData(profile({
        jump_host_id: 'jump-with-key',
        startup_mode: 'free_text',
        startup_commands: 'uptime\nwhoami',
    }), { keys, jumpHosts }), {
        host: 'server.example',
        port: 22,
        username: 'deploy',
        auth_type: 'key',
        key_id: 'target-key',
        startup_mode: 'free_text',
        startup_commands: 'uptime\nwhoami',
        proxy_jump: {
            jump_host_id: 'jump-with-key',
            host: 'jump.example',
            port: 2222,
            username: 'jumper',
            auth_type: 'key',
            key_id: 'jump-key',
        },
    });

    assert.deepEqual(buildDirectConnectionData(profile({
        command_set_id: 'set-1',
    }), { keys, jumpHosts }), {
        host: 'server.example',
        port: 22,
        username: 'deploy',
        auth_type: 'key',
        key_id: 'target-key',
        startup_mode: 'command_set',
        command_set_id: 'set-1',
    });
});

test('direct request construction fails closed for incomplete data', () => {
    const invalidProfiles = [
        profile({ auth_type: 'password', key_id: null }),
        profile({ key_id: 'missing' }),
        profile({ jump_host_id: 'jump-with-password' }),
        profile({ jump_host_id: 'missing' }),
        profile({ host: '   ' }),
        profile({ username: '' }),
        profile({ port: 0 }),
        profile({ port: 65536 }),
        profile({ startup_mode: 'command', command_id: null }),
        profile({ startup_mode: 'command_set', command_set_id: null }),
        profile({ startup_mode: 'unknown' }),
        profile({
            auth_type: 'tailscale',
            key_id: null,
            tailscale_authorized: false,
        }),
    ];

    for (const candidate of invalidProfiles) {
        assert.equal(
            buildDirectConnectionData(candidate, { keys, jumpHosts }),
            null,
        );
    }

    const unusableJumpContext = {
        keys,
        jumpHosts: [{
            ...jumpHosts[0],
            key_id: 'missing',
        }],
    };
    assert.equal(buildDirectConnectionData(profile({
        jump_host_id: 'jump-with-key',
    }), unusableJumpContext), null);
});

test('key and Tailscale profiles connect when every reference is available', () => {
    assert.equal(determineLaunchMode(profile(), { keys, jumpHosts }), 'connect');
    assert.equal(determineLaunchMode(profile({
        auth_type: 'tailscale',
        key_id: null,
        tailscale_authorized: true,
    }), { keys, jumpHosts }), 'connect');
    assert.equal(determineLaunchMode(profile({
        jump_host_id: 'jump-with-key',
    }), { keys, jumpHosts }), 'connect');
});

test('target and jump-host passwords always require the dialog', () => {
    assert.equal(determineLaunchMode(profile({
        auth_type: 'password',
        key_id: null,
    }), { keys, jumpHosts }), 'password');
    assert.equal(determineLaunchMode(profile({
        jump_host_id: 'jump-with-password',
    }), { keys, jumpHosts }), 'jump-host-password');
    assert.equal(determineLaunchMode(profile({
        auth_type: 'password',
        key_id: null,
        jump_host_id: 'jump-with-key',
    }), { keys, jumpHosts }), 'password');
});

test('missing or malformed references fall back to review', () => {
    assert.equal(determineLaunchMode(profile({ key_id: 'missing' }), {
        keys,
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(profile({ jump_host_id: 'missing' }), {
        keys,
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(profile({ jump_host_id: 'jump-with-key' }), {
        keys: [{ id: 'target-key' }],
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(profile({ auth_type: 'agent' }), {
        keys,
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(profile({
        auth_type: 'password',
        key_id: null,
        jump_host_id: 'missing',
    }), { keys, jumpHosts }), 'review');
    assert.equal(determineLaunchMode(profile({
        auth_type: 'tailscale',
        key_id: null,
    }), {
        keys,
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(profile(), {
        keys: [{ id: 'target-key' }, { id: 'jump-key', usable: true }],
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(null, { keys, jumpHosts }), 'review');
});

test('revoked saved references remain review-only without credential expansion', () => {
    const revokedKeyProfile = profile({ key_id: 'revoked-key' });
    const revokedJumpProfile = profile({ jump_host_id: 'revoked-jump' });

    assert.equal(determineLaunchMode(revokedKeyProfile, {
        keys,
        jumpHosts,
    }), 'review');
    assert.equal(determineLaunchMode(revokedJumpProfile, {
        keys,
        jumpHosts,
    }), 'review');
    assert.deepEqual(revokedKeyProfile, profile({ key_id: 'revoked-key' }));
    assert.deepEqual(
        revokedJumpProfile,
        profile({ jump_host_id: 'revoked-jump' }),
    );
    assert.equal('password' in revokedKeyProfile, false);
    assert.equal('proxy_jump' in revokedJumpProfile, false);
});

test('formatEndpoint normalizes missing values without injecting markup', () => {
    assert.equal(formatEndpoint(profile()), 'deploy@server.example:22');
    assert.equal(formatEndpoint({
        username: '<admin>',
        host: '<server>',
        port: null,
    }), '<admin>@<server>:22');
});
