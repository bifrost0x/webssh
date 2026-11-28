const test = require('node:test');
const assert = require('node:assert/strict');
const Order = require('../../static/js/overview-host-order.js');
const Model = require('../../static/js/overview-model.js');

const profiles = [
    {id: 'web', name: 'web', group: 'Prod'},
    {id: 'db', name: 'db', group: 'Prod', favorite: true},
    {id: 'nas', name: 'nas', group: 'Home'},
    {id: 'pi', name: 'pi', group: 'Home', favorite: true},
    {id: 'lab', name: 'lab'},
];
const hosts = () => Model.hosts({profiles});
const ids = list => list.map(host => host.id);

test('without a saved order the default order stays', () => {
    assert.deepEqual(ids(Order.arranged(hosts(), null)), ['pi', 'db', 'lab', 'nas', 'web']);
    assert.deepEqual(ids(Order.arranged(hosts(), undefined)), ids(hosts()));
});

test('the saved order is flat across groups and favourites stay first', () => {
    // A saved order that puts a non-favourite first still shows favourites first.
    assert.deepEqual(ids(Order.arranged(hosts(), ['web', 'pi', 'nas', 'db', 'lab'])), ['pi', 'db', 'web', 'nas', 'lab']);
});

test('hosts the order does not name follow in their default order; unknown ids are ignored', () => {
    assert.deepEqual(ids(Order.arranged(hosts(), ['gone', 'web', 'db'])), ['db', 'pi', 'web', 'lab', 'nas']);
    assert.deepEqual(ids(Order.arranged(hosts(), [])), ids(hosts()));
});

test('moving stays inside the favourites or inside the other hosts', () => {
    const shown = Order.arranged(hosts(), ['web', 'nas', 'lab', 'db', 'pi']);
    assert.deepEqual(ids(shown), ['db', 'pi', 'web', 'nas', 'lab']);
    assert.deepEqual(Order.moveTo(shown, 'lab', 0), ['db', 'pi', 'lab', 'web', 'nas']);
    assert.deepEqual(Order.moveTo(shown, 'web', 99), ['db', 'pi', 'nas', 'lab', 'web']);
    assert.deepEqual(Order.moveTo(shown, 'pi', 0), ['pi', 'db', 'web', 'nas', 'lab']);
    assert.equal(Order.moveTo(shown, 'web', 0), null, 'already first of its section');
    assert.equal(Order.moveTo(shown, 'db', -1), null);
    assert.equal(Order.moveTo(shown, 'missing', 0), null);
    assert.deepEqual(Order.position(shown, 'nas'), {index: 1, count: 3});
    assert.deepEqual(Order.position(shown, 'pi'), {index: 1, count: 2});
});

test('placing before or after a card of the same section', () => {
    const shown = Order.arranged(hosts(), ['web', 'nas', 'lab']);
    assert.deepEqual(ids(shown), ['pi', 'db', 'web', 'nas', 'lab']);
    assert.deepEqual(Order.place(shown, 'lab', 'web', false), ['pi', 'db', 'lab', 'web', 'nas']);
    assert.deepEqual(Order.place(shown, 'web', 'lab', true), ['pi', 'db', 'nas', 'lab', 'web']);
    assert.deepEqual(Order.place(shown, 'web', 'lab', false), ['pi', 'db', 'nas', 'web', 'lab']);
    assert.deepEqual(Order.place(shown, 'db', 'pi', false), ['db', 'pi', 'web', 'nas', 'lab']);
    assert.equal(Order.place(shown, 'web', 'nas', false), null, 'same place');
    assert.equal(Order.place(shown, 'web', 'db', false), null, 'a favourite is no target for other hosts');
    assert.equal(Order.place(shown, 'web', 'web', true), null);
});
