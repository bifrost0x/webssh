const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

global.window = {};
global.document = {getElementById: () => null};
require('../../static/js/file-directory-requests.js');
require('../../static/js/sftp-file-manager.js');
const Manager = window.SFTPFileManager;

test('transfer pagination prioritizes old actionable jobs and retains all history', () => {
    const manager = Object.create(Manager.prototype);
    manager.transferQueue = [
        {id:'active',status:'active'}, {id:'failure',status:'error'},
        ...Array.from({length:95}, (_, id) => ({id, status:'complete'}))
    ];
    const page = manager.getTransferQueuePage();
    assert.equal(page.entries.length, 20);
    assert.deepEqual(page.entries.slice(0,2).map(item => item.id), ['active','failure']);
    assert.equal(page.total,97);
    manager.transferQueueFilter = 'error';
    assert.deepEqual(manager.getTransferQueuePage().entries.map(item => item.id), ['failure']);
    manager.transferQueueFilter = 'history';
    manager.transferQueuePage = 4;
    assert.equal(manager.getTransferQueuePage().entries.length,15);
    assert.equal(manager.transferQueue.length,97);
});

test('transfer endpoint snapshot distinguishes browser and remote sources after tab closure', () => {
    const manager = Object.create(Manager.prototype);
    manager.t = (_key, fallback) => fallback;
    manager.findPaneStateEntry = () => ({state:{source:{label:'Archive',endpoint:'operator@archive:22'}}});
    const upload = {type:'upload',filename:'<upload>.txt',targetPath:'/tmp/<upload>.txt',sourceId:'remote'};
    const endpoints = manager.describeTransferEndpoints(upload);
    assert.match(endpoints.source,/This browser/);
    assert.match(endpoints.destination,/operator@archive:22.*\/tmp\/</);
    Object.assign(upload,{endpoints});
    manager.findPaneStateEntry = () => null;
    assert.deepEqual(manager.describeTransferEndpoints(upload),endpoints);
    assert.match(manager.describeTransferEndpoints({type:'download',filename:'out',sourcePath:'/in',sourceId:'gone'}).destination,/This browser/);
});

test('credential assignment validity is explicit and fails closed for invalid uses', () => {
    const context = {window:{},document:{addEventListener(){}}};
    vm.runInNewContext(fs.readFileSync('static/js/native-credentials.js','utf8'),context);
    const client = context.window.NativeCredentials;
    assert.equal(client.assignmentReady({valid:false},{credential_status:'ready'}),false);
    assert.equal(client.assignmentReady({valid:true},{credential_status:'needs_confirmation'}),false);
    assert.equal(client.assignmentReady({valid:true},{credential_status:'ready'}),true);
    assert.equal(client.assignmentReady({},{}),false);
});

test('opening a long queue starts at prioritized actionable jobs instead of completed tail', () => {
    const manager = Object.create(Manager.prototype);
    const list = {scrollTop:500, scrollHeight:1000};
    const previous = global.document;
    global.document = {getElementById:id => id === 'fmQueueList' ? list : null};
    manager.transferQueue = [{status:'active'}, ...Array.from({length:30}, () => ({status:'complete'}))];
    try {
        manager.scrollTransferQueueToEnd();
        assert.equal(list.scrollTop,0);
    } finally { global.document = previous; }
});

for (const scenario of ['reassigned', 'deleted', 'closed']) {
    test(`credential review stops before an intent when the destination was ${scenario}`, async () => {
        const requests = [];
        const context = {window:{}, document:{addEventListener(){},querySelector(){return null;}}, DOMException,
            fetch:async path => {
                requests.push(path);
                return {ok:true,json:async()=>({enabled:true,profiles:scenario === 'deleted' ? [] : [{id:'target',credential_id:scenario === 'reassigned' ? 'different' : 'original'}]})};
            }};
        vm.runInNewContext(fs.readFileSync('static/js/native-credentials.js','utf8'),context);
        await assert.rejects(context.window.NativeCredentials.reviewAssignment('target','original',()=>scenario !== 'closed'),
            scenario === 'closed' ? {name:'AbortError'} : /destination or its password assignment changed/i);
        assert.deepEqual(requests,['/api/credentials/state']);
    });
}
