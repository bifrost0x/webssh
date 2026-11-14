const test = require('node:test');
const assert = require('node:assert/strict');
const helpers = require('../../static/js/customer-workflows.js');
test('preset layout preserves existing assigned sessions and never connects', () => {
    assert.deepEqual(helpers.layoutAssignments(1, ['a', 'b'], 2), {layout: 2, assignments: ['a', 'b']});
    assert.deepEqual(helpers.layoutAssignments(4, ['a', null], 2), {layout: 4, assignments: ['a', null, null, null]});
});
test('single-pane presets shrink an empty quad layout', () => {
    assert.deepEqual(helpers.layoutAssignments(1, [null, null, null, null], 4), {
        layout: 1, assignments: [null]
    });
});
test('smaller presets compact occupied later panes without losing sessions', () => {
    assert.deepEqual(helpers.layoutAssignments(1, [null, null, null, 'a'], 4), {
        layout: 1, assignments: ['a']
    });
    assert.deepEqual(helpers.layoutAssignments(1, [null, 'a', null, 'b'], 4), {
        layout: 2, assignments: ['a', 'b']
    });
    assert.deepEqual(helpers.layoutAssignments(2, ['a', null, 'b', 'c'], 4), {
        layout: 4, assignments: ['a', null, 'b', 'c']
    });
});
test('failure advice never recommends retry for ambiguous or permission failures', () => {
    assert.equal(helpers.adviceKey('PERMISSION_DENIED'), 'permission');
    assert.equal(helpers.adviceKey('OUTCOME_UNKNOWN'), 'unknown');
    assert.equal(helpers.adviceKey('CONFLICT'), 'conflict');
    assert.equal(helpers.adviceKey('SOURCE_UNAVAILABLE'), 'source');
});
test('metadata preset identifiers also work on HTTP homelab origins without randomUUID',()=>{
 assert.match(helpers.presetId({}),/^preset_[a-z0-9]+_[a-z0-9]+$/);
 assert.equal(helpers.presetId({randomUUID:()=> 'provided-uuid'}),'provided-uuid');
});
