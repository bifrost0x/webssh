const {test}=require('node:test');const assert=require('node:assert/strict');
const {hasOpenSession}=require('../../static/js/connection-overview');
test('activity requires a connected session matching saved identity, endpoint and jump route',()=>{
 const p={id:'p',host:'server',port:22,username:'user',jump_host_id:'jump'};
 const s={connected:true,profileId:'p',host:'server',port:22,username:'user',jumpHostId:'jump'};
 assert.equal(hasOpenSession(p,[s]),true);
 for(const patch of [{connected:false},{profileId:'other'},{host:'edited'},{port:2222},{username:'another'},{jumpHostId:null}])assert.equal(hasOpenSession(p,[{...s,...patch}]),false);
 assert.equal(hasOpenSession(null,[s]),false);
});
