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

const {aggregateRoutes, pageItems} = require('../../static/js/connection-overview');
test('inventory groups by both saved group and actual route without duplicate targets', () => {
    const model = buildAccessModel([
        {id: 'a', name: 'API', group: 'Production', jump_host_id: 'jump-a'},
        {id: 'b', name: 'DB', group: 'Production', jump_host_id: 'jump-b'},
        {id: 'c', name: 'Local', group: 'Production'},
        {id: 'missing-a', group: 'Production', jump_host_id: 'missing-a'},
        {id: 'missing-b', group: 'Production', jump_host_id: 'missing-b'},
        {id: 'a', name: 'duplicate'},
    ], [{id: 'jump-a', name: 'Gateway A'}, {id: 'jump-b', name: 'Gateway B'}], true);
    const result = aggregateRoutes(model);
    assert.equal(result.totalHosts, 5);
    assert.equal(result.totalBundles, 5);
    assert.equal(result.bundles.reduce((sum, bundle) => sum + bundle.count, 0), 5);
    assert.deepEqual(result.bundles.filter(bundle => bundle.route === 'configured').map(bundle => bundle.jump.name), ['Gateway A', 'Gateway B']);
});
test('large inventory search reaches hidden targets while retaining full bundle counts', () => {
    const model = buildAccessModel(Array.from({length: 150}, (_, index) => ({
        id: String(index), name: `Target ${index}`, group: `Group ${index % 12}`, jump_host_id: `jump-${index % 3}`,
    })), [], false);
    const result = aggregateRoutes(model, {query: 'Target 149'});
    assert.equal(result.totalHosts, 150);
    assert.equal(result.matches, 1);
    assert.equal(result.bundles.length, 1);
    assert.equal(result.bundles[0].hosts[0].id, '149');
    assert.equal(result.bundles[0].count, 13);
    assert.equal(result.bundles[0].route, 'loading');
    assert.equal(result.bundles[0].jump, null);
});
test('pagination clamps stale pages and bounds visible nodes for many routes and targets', () => {
    const records = Array.from({length: 105}, (_, id) => ({id}));
    assert.deepEqual(pageItems(records, 2, 8).items.map(item => item.id), [16,17,18,19,20,21,22,23]);
    assert.equal(pageItems(records, 500, 8).page, 13);
    assert.equal(pageItems([], 500, 8).page, 0);
    assert.equal(pageItems(records, -1, 8).page, 0);
    assert.ok(pageItems(records, 0, 500).items.length <= 20);
});

const {summarizeResources} = require('../../static/js/connection-overview');
test('resource summary counts only loaded owned records and named groups', () => {
    assert.deepEqual(summarizeResources({}), {hosts: null, groups: null, jumps: null, keys: null, commandSets: null});
    const result = summarizeResources({
        profilesLoaded: true,
        profiles: [{id:'a', group:'Production'}, {id:'b', group:'Production'}, {id:'c', group:''}, {id:'a', group:'duplicate'}, {id:'d', group:'Home'}, null],
        jumpsLoaded: true, jumps: [{id:'j'}, {id:'j'}],
        keysLoaded: true, keys: [],
        commandSetsLoaded: false, commandSets: [],
    });
    assert.deepEqual(result, {hosts:4, groups:2, jumps:1, keys:0, commandSets:null});
    assert.equal(summarizeResources({commandSetsLoaded:true, commandSets:[]}).commandSets, 0);
    assert.equal(summarizeResources({keysLoaded:true}).keys, null);
});

const {atlasConnections} = require('../../static/js/connection-overview');
test('route atlas uses orthogonal paths with noncrossing ordered fan-out', () => {
    const connections = atlasConnections({right:140, y:160}, [40,120,200,280].map(y => ({left:240, right:380, y, targetLeft:430})));
    assert.equal(connections.length, 4);
    const lines = [];
    connections.forEach(connection => {
        for (const points of [connection.root, connection.target]) {
            points.slice(1).forEach((point, index) => {
                const start = points[index];
                assert.ok(start[0] === point[0] || start[1] === point[1]);
                lines.push([start, point]);
            });
        }
    });
    for (let i=0; i<lines.length; i++) for (let j=i+1; j<lines.length; j++) {
        const [a,b] = lines[i], [c,d] = lines[j];
        if (a[0] === b[0] && c[1] === d[1]) {
            assert.ok(!(a[0] > Math.min(c[0],d[0]) && a[0] < Math.max(c[0],d[0]) && c[1] > Math.min(a[1],b[1]) && c[1] < Math.max(a[1],b[1])));
        }
    }
});

const {selectRouteTarget} = require('../../static/js/connection-overview');
test('single-route mode retains a valid target and falls back only within an authorized bundle', () => {
    const bundles = [{key:'A', hosts:[{id:'a1'}, {id:'a2'}]}, {key:'B', hosts:[{id:'b1'}]}];
    assert.deepEqual(selectRouteTarget(bundles, 'A', 'a2', 'B'), {route:'A', host:'a2'});
    assert.deepEqual(selectRouteTarget(bundles, null, 'other-user-host', 'B'), {route:'B', host:'b1'});
    assert.deepEqual(selectRouteTarget(bundles, 'deleted', 'a2', 'missing'), {route:'A', host:'a2'});
    assert.deepEqual(selectRouteTarget([], null, null, null), {route:null, host:null});
});
