const test = require('node:test');
const assert = require('node:assert/strict');
const Model = require('../../static/js/overview-model.js');

test('work-first shortcuts keep live sessions, deduplicate favorites and sort saved recent hosts', () => {
    const profiles = [
        {id:'a',name:'A',host:'a',username:'u',favorite:true},
        {id:'b',name:'B',host:'b',username:'u',favorite:true},
        {id:'c',name:'C',host:'c',username:'u'},
    ];
    const hosts = Model.hosts({profiles, sessions:[{id:'s',connected:true,profileId:'a'}]});
    const result = Model.workFirst({hostList:hosts,history:[
        {host:'gone',username:'u',timestamp:999},
        {host:'c',username:'u',timestamp:200},
        {host:'b',username:'u',timestamp:300},
        {host:'c',username:'u',timestamp:100},
    ]});
    assert.deepEqual(result.resume.map(x=>x.id),['a']);
    assert.deepEqual(result.favorites.map(x=>x.id),['b']);
    assert.deepEqual(result.recent.map(x=>x.id),['c']);
});

test('setup never infers authentication, trust or file access from TCP reachability', () => {
    const [host] = Model.hosts({profiles:[{id:'a',host:'a',username:'u'}],reachability:{a:{state:'reachable'}}});
    assert.deepEqual(Model.setupProgress(host), {host:true,auth:false,trust:false,terminal:false,files:false});
    host.status = {auth:'saved_password',host_key:'trusted'};
    assert.equal(Model.setupProgress(host).auth,false,'stored credentials are not verified login');
    host.sessionId = 's';
    assert.deepEqual(Model.setupProgress(host,new Set(['s'])), {host:true,auth:true,trust:true,terminal:true,files:true});
    host.sessionId = null;
    assert.equal(Model.setupProgress(host,new Set(['s'])).files,false,'disconnected files are not presented as available');
});
test('configuration readiness stays separate from an unreachable TCP result', () => {
    const hosts = Model.hosts({profiles:[{id:'a',host:'a',username:'u'}],
        readiness:[{id:'a',state:'ready',auth:'prompt',host_key:'trusted'}],reachability:{a:{state:'unreachable'}}});
    assert.equal(hosts[0].state,'unreachable');
    assert.deepEqual(Model.metrics({hostList:hosts}).hosts,{total:1,ready:1,needsAttention:0,loaded:true});
});
test('resume includes connected ad-hoc sessions without inventing saved hosts', () => {
    const result = Model.workFirst({sessions:[{id:'ad-hoc',connected:true,host:'192.0.2.3',username:'u'}, {id:'closed',connected:false,host:'192.0.2.4'}]});
    assert.equal(result.resume.length,1);
    assert.equal(result.resume[0].sessionId,'ad-hoc');
    assert.equal(result.resume[0].destination,'u@192.0.2.3');
    assert.equal(result.resume[0].profile,undefined);
});
test('saved hosts remain quick actions when no resume, favorites or history exist', () => {
    const hostList = Model.hosts({profiles:Array.from({length:9},(_,index)=>({id:`host-${index}`,host:`192.0.2.${index}`,username:'u'}))});
    const result = Model.workFirst({hostList});
    assert.deepEqual(result.saved.map(host=>host.id),hostList.slice(0,6).map(host=>host.id));
    assert.equal(Model.workFirst({hostList:[{...hostList[0],favorite:true}]}).saved.length,0,'fallback appears only when primary shortcuts are empty');
    assert.deepEqual(Model.workFirst({hostList:Model.filter(hostList,'192.0.2.8')}).saved.map(host=>host.id),['host-8'],'fallback uses the filtered inventory');
});
