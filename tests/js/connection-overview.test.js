const test = require('node:test');
const assert = require('node:assert/strict');
const {buildAccessModel, groupTone} = require('../../static/js/connection-overview');

test('access routes require an exact authorized jump ID, never groups or addresses', () => {
    const profiles = [
        {id: 'target', name: 'Target', group: 'Production', jump_host_id: 'bastion'},
        {id: 'direct', group: 'Production', host: 'same-address'},
        {id: 'missing', jump_host_id: 'other-user-jump', host: 'same-address'},
    ];
    const model = buildAccessModel(profiles, [{id: 'bastion', name: 'Jump', host: 'same-address'}], true);
    assert.deepEqual(model.find(host => host.id === 'target').jump, {id: 'bastion', name: 'Jump'});
    assert.equal(model.find(host => host.id === 'direct').route, 'none');
    assert.equal(model.find(host => host.id === 'missing').route, 'unavailable');
    assert.equal(model.filter(host => host.jump).length, 1);
});

test('loading and empty stores do not claim missing routes or reachability', () => {
    assert.deepEqual(buildAccessModel(), []);
    const model = buildAccessModel([{id: 'one', jump_host_id: 'jump'}], [{id: 'jump'}]);
    assert.equal(model[0].route, 'loading');
    assert.equal(model[0].jump, null);
});

test('display model excludes credentials, usernames, addresses and arbitrary metadata', () => {
    const model = buildAccessModel([{
        id: 'target', name: '<img onerror=alert(1)>', group: 'Operations', jump_host_id: 'jump',
        username: 'secret-user', password: 'secret-password', host: 'private-address',
        startup_commands: 'secret-command', favorite: true,
    }], [{id: 'jump', name: 'Jump', password: 'jump-secret', host: 'private-jump'}], true);
    assert.equal(model[0].name, '<img onerror=alert(1)>');
    assert.equal(model[0].favorite, true);
    assert.doesNotMatch(JSON.stringify(model), /secret|private-/);
});

test('large stores, duplicate IDs and cyclic-looking records remain finite and unique', () => {
    const profiles = Array.from({length: 500}, (_, index) => ({
        id: String(index), name: 'Long name '.repeat(30), group: `Group ${index % 5}`,
        jump_host_id: String(index), sort_order: index,
    }));
    const jumps = profiles.map(profile => ({id: profile.id, jump_host_id: profile.id}));
    const result = buildAccessModel([...profiles, profiles[0], null], jumps, true);
    assert.equal(result.length, 500);
    assert.equal(result.filter(host => host.jump).length, 500);
    assert.ok(result.every(host => !('jump_host_id' in host.jump)));
});

// Color must remain tied to labels when filters reorder the visible records.
test('group accents are stable for arbitrary Unicode labels and independent of state', () => {
    const groups = ['Production', 'Database', 'Homelab', '', '🛰️ 系统', '<img src=x>'];
    const before = new Map(groups.map(group => [group, groupTone(group)]));
    for (const group of [...groups].reverse()) {
        assert.equal(groupTone(group), before.get(group));
        assert.match(groupTone(group), /^[0-4]$/);
    }
});

const {orderedGroups, readGroupOrder} = require('../../static/js/connection-overview');
test('manual group order handles new, missing, duplicate and hostile labels without changing membership', () => {
    const current = ['Beta', '', 'Alpha', 'Beta', '__proto__', '<img>'];
    const saved = ['Beta', 'deleted', 'Beta', 'Alpha'];
    assert.deepEqual(orderedGroups(current, saved), ['Beta', 'Alpha', ...['', '__proto__', '<img>'].sort((a,b) => a.localeCompare(b))]);
    assert.deepEqual(saved, ['Beta', 'deleted', 'Beta', 'Alpha']);
});
test('optional group ordering rejects malformed storage and reads only the account key', () => {
    const calls = [];
    const store = {getItem(key) { calls.push(key); return '["B","A","B"]'; }};
    assert.deepEqual(readGroupOrder(store, 'account-one'), ['B','A']);
    assert.deepEqual(readGroupOrder(store, null), []);
    assert.deepEqual(calls, ['account-one']);
    for (const raw of ['{}','null','[3]','broken', JSON.stringify(['a'.repeat(513)]), JSON.stringify(Array(5001).fill('A'))]) {
        assert.deepEqual(readGroupOrder({getItem: () => raw}, 'key'), []);
    }
    assert.deepEqual(readGroupOrder({getItem() { throw Error('blocked'); }}, 'key'), []);
});

const Overview = require('../../static/js/connection-overview');
const HostPlatform = require('../../static/js/host-platform');
const HostIdentity = require('../../static/js/host-identity');

test('host rows carry only the role and catalog service ids besides the existing display fields', () => {
    globalThis.HostPlatform = HostPlatform;
    globalThis.HostIdentity = HostIdentity;
    try {
        const model = Overview.buildAccessModel([{
            id: 'one', name: 'Shelf', group: 'Lab', host: 'private-address', username: 'secret-user', password: 'secret-password',
            detected_services: ['immich', 'not-a-service', 'docker'], role_override: 'media', detected_guests: 4,
        }, {id: 'two', name: 'Plain', group: 'Lab'}]);
        const one = model.find(host => host.id === 'one');
        const two = model.find(host => host.id === 'two');
        assert.deepEqual(one.role, {id: 'media', source: 'manual'});
        assert.deepEqual(one.services, HostIdentity.facts({detected_services: ['immich', 'docker']}).services);
        assert.ok(one.services.every(id => Object.hasOwn(HostPlatform.serviceLabels, id)));
        assert.deepEqual(two.role, {id: 'server', source: 'default'});
        assert.deepEqual(two.services, []);
        assert.deepEqual(Object.keys(one).sort(), ['favorite', 'group', 'id', 'jump', 'name', 'order', 'platform', 'role', 'route', 'routeRef', 'services']);
        assert.doesNotMatch(JSON.stringify(model), /secret|private-/);
    } finally {
        delete globalThis.HostPlatform;
        delete globalThis.HostIdentity;
    }
});

test('rows still build when the identity catalog is not loaded', () => {
    const [host] = Overview.buildAccessModel([{id: 'one', name: 'One', detected_services: ['docker']}]);
    assert.deepEqual(host.role, {id: 'server', source: 'pending'});
    assert.deepEqual(host.services, []);
});

test('the grouping preference defaults to group and accepts only the two known values', () => {
    const store = value => ({getItem(key) { assert.equal(key, 'webssh.hostRailGrouping'); return value; }});
    assert.equal(Overview.readGrouping(store(null)), 'group');
    assert.equal(Overview.readGrouping(store('role')), 'role');
    assert.equal(Overview.readGrouping(store('group')), 'group');
    for (const raw of ['', 'Role', 'roles', '__proto__', '1', 'role ']) assert.equal(Overview.readGrouping(store(raw)), 'group');
    assert.equal(Overview.readGrouping({getItem() { throw Error('blocked'); }}), 'group');
    assert.equal(Overview.readGrouping(null), 'group');
});

test('role grouping follows the catalog order, skips empty roles and ignores unknown ids', () => {
    const hosts = [
        {id: 'a', role: {id: 'server'}}, {id: 'b', role: {id: 'hypervisor'}}, {id: 'c', role: {id: 'server'}},
        {id: 'd', role: {id: 'media'}}, {id: 'e', role: {id: 'bogus'}}, {id: 'f'},
    ];
    const groups = Overview.groupByRole(hosts, HostIdentity.ROLES);
    assert.deepEqual(groups.map(([role, items]) => [role, items.map(host => host.id)]),
        [['hypervisor', ['b']], ['media', ['d']], ['server', ['a', 'c']]]);
});

const Classic = require('../../static/js/connection-overview-classic');

test('classic rows carry only platform, role, virtualization label and catalog service ids', () => {
    globalThis.HostPlatform = HostPlatform;
    globalThis.HostIdentity = HostIdentity;
    try {
        const model = Classic.buildAccessModel([{
            id: 'one', name: 'Shelf', group: 'Lab', host: 'private-address', username: 'secret-user', password: 'secret-password',
            detected_platform: 'proxmox', detected_virt: 'bare-metal', detected_services: ['immich', 'not-a-service', 'docker'],
        }, {id: 'two', name: 'Plain', group: 'Lab'}]);
        const one = model.find(host => host.id === 'one');
        const two = model.find(host => host.id === 'two');
        assert.equal(one.platform.id, 'proxmox');
        assert.deepEqual(one.role, {id: 'hypervisor', source: 'derived'});
        assert.equal(one.virt, 'Bare Metal');
        assert.deepEqual(one.services, HostIdentity.facts({detected_services: ['immich', 'docker']}).services);
        assert.deepEqual(two.role, {id: 'server', source: 'default'});
        assert.equal(two.platform.id, 'server');
        assert.equal(two.virt, '');
        assert.deepEqual(two.services, []);
        assert.deepEqual(Object.keys(one).sort(), ['favorite', 'group', 'id', 'jump', 'name', 'order', 'platform', 'role', 'route', 'services', 'virt']);
        assert.doesNotMatch(JSON.stringify(model), /secret|private-/);
    } finally {
        delete globalThis.HostPlatform;
        delete globalThis.HostIdentity;
    }
});

test('classic rows still build when the identity catalog is not loaded', () => {
    const [host] = Classic.buildAccessModel([{id: 'one', name: 'One', detected_services: ['docker']}]);
    assert.deepEqual(host.role, {id: 'server', source: 'pending'});
    assert.deepEqual(host.services, []);
    assert.equal(host.virt, '');
});
