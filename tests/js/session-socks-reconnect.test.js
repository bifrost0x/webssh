const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(route, persistent) {
    const sent = [];
    const context = {document:{body:{dataset:{}}}, window:{
        socket:{emit:(event,payload)=>sent.push({event,payload})},
        showNotification() {}, prepareSessionReconnectJump:()=>route,
    }, confirm:()=>true, setTimeout:fn=>fn()};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../static/js/session-manager.js'),'utf8')+'\nglobalThis.manager = SessionManager;', context);
    const manager=context.manager;
    manager.getDisplayLabel=()=> 'test';
    manager.closeSession=()=> {};
    manager.removeSessionUI=()=> {};
    manager.sessions.test={host:'private.example',port:22,username:'test',keyId:'key',authType:'key',
        viaSocks:true,socksProxyId:'proxy',connected:true,useTmux:true,tmuxSessionName:'test',isPersistentCandidate:persistent};
    return {manager,sent};
}

for (const persistent of [false,true]) {
    test(`SOCKS reconnect preserves route and tmux (persistent=${persistent})`,()=>{
        const {manager,sent}=setup({socksProxy:{socks_proxy_id:'proxy'}},persistent);
        manager.requestReconnect('test');
        assert.equal(sent.length,1);
        assert.equal(sent[0].payload.socks_proxy.socks_proxy_id,'proxy');
        assert.equal(sent[0].payload.use_tmux,true);
        assert.equal(sent[0].payload.proxy_jump,undefined);
    });
    test(`unresolved SOCKS reconnect cannot remove the session or dial directly (persistent=${persistent})`,()=>{
        const {manager,sent}=setup({requiresForm:true},persistent);
        let form=false;
        manager.prefillConnectionForm=(_id,force)=>{form=force;};
        manager.closeSession=manager.removeSessionUI=()=>assert.fail('removed before resolving route');
        manager.requestReconnect('test');
        assert.equal(form,true);
        assert.equal(sent.length,0);
    });
}

test('SOCKS reconnect without a route helper requires review',()=>{
    const {manager}=setup({},false);
    const context={document:{body:{dataset:{}}},window:{}};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../static/js/session-manager.js'),'utf8')+'\nglobalThis.manager = SessionManager;',context);
    assert.equal(context.manager.reconnectRoute(manager.sessions.test).requiresForm,true);
});
