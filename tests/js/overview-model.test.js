const test = require('node:test');
const assert = require('node:assert/strict');
const Model = require('../../static/js/overview-model.js');

const profiles = [
    {id: 'web', name: 'web-01', host: '10.0.0.1', port: 22, username: 'root', group: 'Prod'},
    {id: 'db', name: 'db-01', host: '10.0.0.2', port: 2222, username: 'pg', group: 'Prod', jump_host_id: 'j1', favorite: true},
    {id: 'nas', name: 'nas', host: '192.168.1.5', username: 'admin', jump_host_id: 'gone'},
];
const jumps = [{id: 'j1', name: 'bastion'}];

test('host states combine readiness, routes, reachability and open sessions', () => {
    const readiness = [{id: 'web', state: 'ready', host_key: 'trusted'}, {id: 'db', state: 'action', host_key: 'unknown'}, {id: 'nas', state: 'ready'}];
    const hosts = Model.hosts({profiles, jumps, jumpsLoaded: true, readiness, reachability: {web: {state: 'unreachable'}},
        sessions: [{id: 's1', connected: true, host: '10.0.0.2', port: 2222, username: 'pg'}]});
    const byId = Object.fromEntries(hosts.map(host => [host.id, host]));
    assert.equal(byId.web.state, 'unreachable');
    assert.equal(byId.db.state, 'live');
    assert.equal(byId.db.sessionId, 's1');
    assert.equal(byId.nas.state, 'broken');
    assert.equal(byId.db.destination, 'pg@10.0.0.2:2222');
    assert.equal(hosts[0].id, 'db', 'favorites sort first');
    assert.deepEqual(byId.db.route, {kind: 'jump', name: 'bastion', id: 'j1'});
});

test('unknown readiness stays unknown until the server answers', () => {
    const [host] = Model.hosts({profiles: [profiles[0]], jumpsLoaded: true});
    assert.equal(host.state, 'unknown');
    const metrics = Model.metrics({hostList: [host]});
    assert.equal(metrics.hosts.loaded, false);
});

test('filter matches name, destination, group and route', () => {
    const hosts = Model.hosts({profiles, jumps, jumpsLoaded: true});
    assert.deepEqual(Model.filter(hosts, 'bastion').map(host => host.id), ['db']);
    assert.deepEqual(Model.filter(hosts, '192.168').map(host => host.id), ['nas']);
    assert.equal(Model.filter(hosts, '  ').length, 3);
});

test('automation bins count fourteen local days and ignore older runs', () => {
    const now = new Date(2026, 10, 7, 12).getTime();
    const runs = [
        {created_at: new Date(2026, 10, 7, 9).toISOString(), outcome: 'succeeded'},
        {created_at: new Date(2026, 10, 7, 10).toISOString(), outcome: 'failed'},
        {created_at: new Date(2026, 10, 1, 10).toISOString(), outcome: 'unknown'},
        {created_at: new Date(2026, 9, 1, 10).toISOString(), outcome: 'succeeded'},
        {created_at: 'not a date', outcome: 'succeeded'},
    ];
    const bins = Model.automationBins(runs, now);
    assert.equal(bins.length, 14);
    assert.deepEqual([bins[13].succeeded, bins[13].failed], [1, 1]);
    assert.equal(bins.reduce((sum, bin) => sum + bin.other, 0), 1);
    const metrics = Model.metrics({runs, now});
    assert.equal(metrics.automation.runs, 3);
    assert.equal(metrics.automation.rate, 33);
});

test('next run is the earliest enabled future schedule', () => {
    const now = Date.parse('2026-11-07T10:00:00Z');
    const metrics = Model.metrics({now, schedules: [
        {name: 'later', enabled: true, next_due: '2026-11-08T09:00:00Z'},
        {name: 'paused', enabled: false, next_due: '2026-11-07T11:00:00Z'},
        {name: 'soon', enabled: true, next_due: '2026-11-07T12:00:00Z'},
    ]});
    assert.equal(metrics.nextRun.name, 'soon');
});

test('headline picks the most severe condition', () => {
    const ready = Model.hosts({profiles: [profiles[0]], readiness: [{id: 'web', state: 'ready'}]});
    assert.equal(Model.headline({hostList: ready}).key, 'ready');
    assert.equal(Model.headline({hostList: []}).key, 'empty');
    assert.equal(Model.headline({hostList: ready, attentionItems: [{}]}).tone, 'warning');
    assert.equal(Model.headline({connected: false, hostList: ready}).key, 'disconnected');
});

test('attention lists actionable items only', () => {
    const now = Date.parse('2026-11-07T10:00:00Z');
    const hosts = Model.hosts({profiles, jumps, jumpsLoaded: true, readiness: [
        {id: 'web', state: 'action', host_key: 'unknown', auth: 'prompt'},
        {id: 'db', state: 'action', host_key: 'trusted', auth: 'password_changed'},
        {id: 'nas', state: 'ready', host_key: 'trusted'},
    ]});
    const items = Model.attention({hostList: hosts, now,
        runs: [{id: 'r1', name: 'Backup', outcome: 'failed', created_at: '2026-11-07T08:00:00Z'},
            {id: 'r0', name: 'Old', outcome: 'failed', created_at: '2026-11-01T08:00:00Z'}],
        schedules: [{name: 'Nightly', last_status: 'needs_review'}, {name: 'Fine', last_status: 'succeeded'}]});
    assert.deepEqual(items.map(item => item.kind), ['host-keys', 'jump-missing', 'credentials', 'run-failed', 'schedule-review']);
    assert.equal(items[0].count, 1);
});

test('activity merges sessions, saved-host connections and runs, newest first', () => {
    const now = Date.parse('2026-11-07T10:00:00Z');
    const hosts = Model.hosts({profiles, jumps, jumpsLoaded: true,
        sessions: [{id: 's1', connected: true, host: '10.0.0.1', port: 22, username: 'root'}]});
    const events = Model.activity({hostList: hosts, now, sessions: [{id: 's1', connected: true, host: '10.0.0.1', port: 22, username: 'root'}],
        history: [{host: '192.168.1.5', port: 22, username: 'admin', timestamp: now - 3600000}, {host: 'unknown', port: 22, username: 'x', timestamp: now}],
        runs: [{id: 'r', name: 'Updates', outcome: 'succeeded', created_at: '2026-11-07T09:30:00Z'}]});
    assert.deepEqual(events.map(event => event.kind), ['session', 'run-succeeded', 'connection']);
});

test('platforms are counted and sorted by frequency', () => {
    const hosts = Model.hosts({profiles});
    const resolve = profile => ({id: profile.id === 'nas' ? 'truenas' : 'ubuntu'});
    assert.deepEqual(Model.platforms(hosts, resolve).map(entry => [entry.platform.id, entry.count]), [['ubuntu', 2], ['truenas', 1]]);
});

test('topology keeps labels away from the center and summarises large hubs', () => {
    const many = Array.from({length: 20}, (_, index) => ({id: `h${index}`, name: `host-${index}`, host: `10.1.0.${index}`, username: 'u',
        jump_host_id: index < 5 ? 'j1' : undefined}));
    const layout = Model.topology(Model.hosts({profiles: many, jumps, jumpsLoaded: true}), {perHub: 12});
    const direct = layout.hubs.find(hub => hub.kind === 'direct');
    assert.equal(direct.hidden, 3);
    for (const node of layout.nodes) {
        assert.ok(node.x >= 0 && node.x <= layout.width && node.y >= 0 && node.y <= layout.height);
        assert.equal(node.anchor, node.x < layout.center.x ? 'end' : 'start');
    }
    const directYs = layout.nodes.filter(node => node.hub === 'direct').map(node => node.y).sort((a, b) => a - b);
    assert.ok(directYs.every((y, index) => index === 0 || y - directYs[index - 1] >= 20), 'labels do not overlap vertically');
});

test('greeting follows the time of day', () => {
    assert.equal(Model.greetingKey(7), 'greetingMorning');
    assert.equal(Model.greetingKey(14), 'greetingDay');
    assert.equal(Model.greetingKey(21), 'greetingEvening');
});
