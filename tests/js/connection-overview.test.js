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

const {orderedGroups, moveGroupOrder, readGroupOrder} = require('../../static/js/connection-overview');
test('manual group order handles new, missing, duplicate and hostile labels without changing membership', () => {
    const current = ['Beta', '', 'Alpha', 'Beta', '__proto__', '<img>'];
    const saved = ['Beta', 'deleted', 'Beta', 'Alpha'];
    assert.deepEqual(orderedGroups(current, saved), ['Beta', 'Alpha', ...['', '__proto__', '<img>'].sort((a,b) => a.localeCompare(b))]);
    assert.deepEqual(saved, ['Beta', 'deleted', 'Beta', 'Alpha']);
    assert.deepEqual(moveGroupOrder(['A','B','C'], 'A', 2), ['B','C','A']);
    assert.deepEqual(moveGroupOrder(['A','B','C'], 'C', 0), ['C','A','B']);
    for (const index of [-1, 3, NaN, 1.5]) assert.deepEqual(moveGroupOrder(['A','B','C'], 'B', index), ['A','B','C']);
    assert.deepEqual(moveGroupOrder(['A'], 'missing', 0), ['A']);
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
