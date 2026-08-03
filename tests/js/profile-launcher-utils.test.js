const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildDirectConnectionData,
    determineLaunchMode,
    formatEndpoint,
} = require('../../static/js/profile-launcher-utils.js');

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
