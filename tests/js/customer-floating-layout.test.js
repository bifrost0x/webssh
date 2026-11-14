const test = require('node:test');
const assert = require('node:assert/strict');
const {layoutAssignments} = require('../../static/js/customer-workflows.js');
test('floating layouts compact holes and preserve all assigned sessions',()=>{
 assert.deepEqual(layoutAssignments(1,[null,'a',null,null,'b'],'windows'),{layout:2,assignments:['a','b']});
 assert.deepEqual(layoutAssignments(1,['a','b'],'windows'),{layout:2,assignments:['a','b']});
 assert.throws(()=>layoutAssignments(4,['a','b','c','d','e'],'windows'),RangeError);
});
