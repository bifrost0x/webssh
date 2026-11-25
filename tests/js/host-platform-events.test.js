const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(sessions = {}) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const start = source.indexOf("    socket.on('host_platform'");
    const end = source.indexOf("    // The login recheck found the restart marker gone");
    assert.ok(start > 0 && end > start);
    const calls = {loads: 0, refreshes: 0};
    let handler;
    vm.runInNewContext(source.slice(start, end), {
        socket: {on(_name, fn) {handler = fn;}},
        SessionManager: {sessions},
        ProfileManager: {profiles: [], loadProfiles() { calls.loads += 1; }},
        Object,
        Array,
        window: {HostPlatform: {labels: {debian: 'Debian'}, refreshSessionIcons() { calls.refreshes += 1; }}},
    });
    return {handler, calls};
}

test('a profile-only event reloads the saved hosts', () => {
    const {handler, calls} = setup();
    handler({profile_id: 'p1'});
    assert.equal(calls.loads, 1);
});

test('a profile-only event without a valid id changes nothing', () => {
    const {handler, calls} = setup();
    for (const data of [null, {}, {profile_id: ''}, {profile_id: 7}, {profile_id: ['p1']}, {platform: 'unknown'}]) {
        handler(data);
    }
    assert.deepEqual(calls, {loads: 0, refreshes: 0});
});

test('a detection event updates the session and reloads the profile', () => {
    const session = {};
    const {handler, calls} = setup({s1: session});
    handler({session_id: 's1', profile_id: 'p1', platform: 'debian', services: []});
    assert.equal(session.detectedPlatform, 'debian');
    assert.deepEqual(calls, {loads: 1, refreshes: 1});
});
