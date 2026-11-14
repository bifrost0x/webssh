const test = require('node:test');
const assert = require('node:assert/strict');
const launcher = require('../../static/js/profile-launcher-utils.js');
const overview = require('../../static/js/overview-model.js');
const {describeSSHError} = require('../../static/js/ssh-error-ui.js');
const profile = {id:'host', host:'internal.example', username:'user', auth_type:'key', key_id:'key', socks_proxy_id:'proxy'};
const context = {keys:[{id:'key',usable:true}], socksProxies:[{id:'proxy',host:'proxy.example',port:1080,auth_type:'none',name:'Office'}], socksProxiesLoaded:true};

test('SOCKS launch retains only the saved proxy reference', () => {
    assert.equal(launcher.determineLaunchMode(profile, context), 'connect');
    assert.deepEqual(launcher.buildDirectConnectionData(profile, context).socks_proxy, {socks_proxy_id:'proxy'});
    assert.equal(launcher.usesAdvancedConnectionSettings(profile), true);
});
test('missing, conflicting and Tailscale SOCKS routes never launch directly', () => {
    assert.equal(launcher.buildDirectConnectionData(profile, {...context,socksProxies:[]}), null);
    assert.equal(launcher.getProfileReadiness(profile, {...context,socksProxies:[]}).state, 'socks-missing');
    assert.equal(launcher.getProfileReadiness(profile, {...context,socksProxiesLoaded:false}).state, 'loading');
    assert.equal(launcher.determineLaunchMode({...profile,jump_host_id:'jump'}, context), 'review');
    assert.equal(launcher.determineLaunchMode({...profile,auth_type:'tailscale',tailscale_authorized:true}, context), 'review');
});
test('SOCKS password launch asks for the proxy password', () => {
    const passwordContext = {...context,socksProxies:[{...context.socksProxies[0],auth_type:'password'}]};
    assert.equal(launcher.determineLaunchMode(profile,passwordContext), 'socks-proxy-password');
    assert.equal(launcher.getProfileReadiness(profile,passwordContext).state,'password-needed');
    assert.equal(launcher.determineLaunchMode({...profile,auth_type:'password'},passwordContext),'password');
});
test('overview represents SOCKS routes and missing proxies without guessing direct', () => {
    const hosts = overview.hosts({profiles:[profile],socks:context.socksProxies,socksLoaded:true});
    assert.deepEqual(hosts[0].route,{kind:'socks',id:'proxy',name:'Office'});
    const missing = overview.hosts({profiles:[profile],socksLoaded:true});
    assert.equal(missing[0].state,'broken');
    assert.equal(overview.attention({hostList:missing})[0].kind,'socks-missing');
});
test('every SOCKS error has a localized safe message and proxy review action', () => {
    for (const code of ['proxy_failure','not_allowed','network_unreachable','host_unreachable','connection_refused','ttl_expired','unsupported','protocol_error','proxy_unreachable','timeout','auth_required','auth_rejected','auth_failed']) {
        const result=describeSSHError({code:'socks_'+code,error:'raw private proxy response'}, key=>'translated:'+key);
        assert.match(result.message,/^translated:sshErrors\.socks/);
        assert.equal(result.action.asset,'socks-proxies');
        assert.equal(result.message.includes('raw private'),false);
    }
});

test('a direct session does not mark a SOCKS host connected at the same address', () => {
    const [host] = overview.hosts({profiles:[profile],socks:context.socksProxies,socksLoaded:true,
        sessions:[{id:'direct',connected:true,host:profile.host,username:profile.username,port:22}]});
    assert.equal(host.sessionId,null);
});

for (const filename of ['connection-overview.js','connection-overview-classic.js']) {
    test(`${filename} whitelists SOCKS display metadata and does not expose endpoint credentials`, () => {
        const {buildAccessModel}=require('../../static/js/'+filename);
        const [host]=buildAccessModel([profile],[],true,[{...context.socksProxies[0],username:'private',password:'secret'}],true);
        assert.equal(host.route,'configured');
        assert.equal(host.routeKind,'socks');
        assert.deepEqual(host.socks,{id:'proxy',name:'Office'});
        assert.equal(JSON.stringify(host).includes('secret'),false);
        assert.equal(JSON.stringify(host).includes('proxy.example'),false);
    });
}
