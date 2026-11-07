const test = require('node:test');
const assert = require('node:assert/strict');
const Layout = require('../../static/js/overview-layout.js');
const Model = require('../../static/js/overview-model.js');

const ids = layout => layout.filter(item => !item.hidden).map(item => item.id);

test('a missing or foreign layout falls back to the default and keeps known values', () => {
    assert.deepEqual(Layout.normalize(null), Layout.defaults());
    const layout = Layout.normalize([{id: 'hosts', w: 40, h: 2}, {id: 'news', w: 6}, {id: 'hosts', w: 4}, null]);
    assert.equal(layout[0].id, 'hosts');
    assert.equal(layout[0].w, 12, 'width is clamped to the grid');
    assert.equal(layout[0].h, 8, 'height is clamped to the minimum');
    assert.equal(layout.length, Layout.PANELS.length, 'unknown and duplicate panels are dropped, new panels appended');
    assert.ok(Layout.isDefault(Layout.defaults()));
});

test('moving skips hidden panels and stops at the ends', () => {
    let layout = Layout.setHidden(Layout.defaults(), 'attention', true);
    layout = Layout.move(layout, 'automation', -1);
    assert.deepEqual(ids(layout).slice(0, 3), ['kpis', 'automation', 'topology']);
    assert.deepEqual(ids(Layout.move(layout, 'kpis', -1)), ids(layout));
    const last = Layout.move(Layout.defaults(), 'platforms', 5);
    assert.equal(ids(last).at(-1), 'platforms');
    assert.deepEqual(ids(Layout.moveBefore(Layout.defaults(), 'activity', 'kpis'))[0], 'activity');
});

test('resizing clamps to the grid and an explicit null restores the content height', () => {
    let layout = Layout.resize(Layout.defaults(), 'hosts', {w: 1, h: 500});
    const hosts = () => layout.find(item => item.id === 'hosts');
    assert.deepEqual([hosts().w, hosts().h], [3, 160]);
    layout = Layout.resize(layout, 'hosts', {h: null});
    assert.equal(hosts().h, null);
    assert.equal(hosts().w, 3, 'width is untouched when only the height changes');
});

test('pointer positions snap to columns and rows', () => {
    // 12 columns of 80px with 20px gaps: 1180px.
    assert.equal(Layout.widthFromPointer(380, 1180, 20), 4);
    assert.equal(Layout.widthFromPointer(5000, 1180, 20), 12);
    assert.equal(Layout.widthFromPointer(10, 1180, 20), 3);
    assert.equal(Layout.heightFromPointer(300, 20), 40);
    assert.equal(Layout.rowsFor(100, 20), 15);
});

test('attention keys change with the situation they describe', () => {
    const a = Model.attentionKey({kind: 'host-keys', hostIds: ['b', 'a']});
    assert.equal(a, Model.attentionKey({kind: 'host-keys', hostIds: ['a', 'b']}), 'order does not matter');
    assert.notEqual(a, Model.attentionKey({kind: 'host-keys', hostIds: ['a', 'b', 'c']}), 'a new host shows the item again');
    assert.equal(Model.attentionKey({kind: 'run-failed', runId: 'r-1'}), 'run-failed:r-1');
    assert.match(Model.attentionKey({kind: 'schedule-review', name: 'Nightly <b>', status: 'unknown'}), /^schedule-review:[a-z0-9]+$/);
    for (const key of [a, Model.attentionKey({kind: 'unreachable', hostIds: ['x'.repeat(80)]})]) {
        assert.match(key, /^[a-z-]+:[A-Za-z0-9_.-]{1,64}$/, 'keys stay within what the server accepts');
    }
});
