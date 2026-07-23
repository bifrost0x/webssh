const test = require('node:test');
const assert = require('node:assert/strict');

const {
    determineLaunchMode,
    formatEndpoint,
} = require('../../static/js/profile-launcher-utils.js');

const keys = [
    { id: 'target-key', usable: true },
    { id: 'jump-key', usable: true },
];
const jumpHosts = [
    { id: 'jump-with-key', auth_type: 'key', key_id: 'jump-key' },
    { id: 'jump-with-password', auth_type: 'password', key_id: null },
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

test('formatEndpoint normalizes missing values without injecting markup', () => {
    assert.equal(formatEndpoint(profile()), 'deploy@server.example:22');
    assert.equal(formatEndpoint({
        username: '<admin>',
        host: '<server>',
        port: null,
    }), '<admin>@<server>:22');
});
