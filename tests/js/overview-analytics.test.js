const test=require('node:test');const assert=require('node:assert/strict');
const {summarize,dayKey}=require('../../static/js/overview-analytics.js');
const now=new Date(2026,10,4,12);
const make=(id,day,outcome)=>({id,created_at:new Date(2026,10,day,11).toISOString(),outcome});
test('counts retained local-day runs without inventing older history',()=>{
 const model=summarize([make('a',4,'succeeded'),make('b',4,'failed'),make('c',3,'unknown'),make('d',2,'other'),make('old',-10,'failed'),{created_at:'invalid',outcome:'failed'}],7,now);
 assert.equal(model.bins.length,7);assert.equal(model.available,5);assert.equal(model.total,4);assert.equal(model.maximum,2);
 assert.deepEqual(model.bins.at(-1).counts,{succeeded:1,failed:1,unknown:0,other:0});assert.equal(model.bins[0].runs.length,0);
});
test('14-day boundary uses calendar days and unknown outcomes remain unconfirmed',()=>{
 const start=new Date(2026,10,4-13,0);const before=new Date(start.getTime()-1);
 const model=summarize([{created_at:start.toISOString(),outcome:'unexpected'},{created_at:before.toISOString(),outcome:'failed'}],14,now);
 assert.equal(model.total,1);assert.equal(model.bins[0].counts.unknown,1);assert.equal(model.bins[0].key,dayKey(start));
});
test('empty history has zero data and stable nonzero chart denominator',()=>{
 const model=summarize([],7,now);assert.equal(model.maximum,1);assert.equal(model.total,0);assert.equal(model.available,0);
 assert.ok(model.bins.every(bin=>Object.values(bin.counts).every(count=>count===0)));
});
