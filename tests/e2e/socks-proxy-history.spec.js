const {test, expect}=require('playwright/test');
const {login, openWorkspace, installSshConnectTrap}=require('./helpers');

async function rememberProxyConnection(page,authType='none') {
    const proxy=await page.evaluate(async authType=>{
        const result=await new Promise(resolve=>window.socket.emit('save_socks_proxy',{
            name:'History proxy '+authType,host:'history-proxy.example',port:1080,
            auth_type:authType,username:authType==='password'?'proxy-user':'',remote_dns:true,
        },resolve));
        if (!result.success) throw new Error(result.error);
        const originalEmit=window.socket.emit.bind(window.socket);
        window.socket.emit=(event,...args)=>{
            if (event!=='ssh_connect') return originalEmit(event,...args);
            const payload=args[0];
            window.__initialHistoryConnect=structuredClone(payload);
            queueMicrotask(()=>window.socket.listeners('ssh_connected').forEach(listener=>listener({
                session_id:'history-socks-'+authType,host:payload.host,port:payload.port,username:payload.username,
                client_request_id:payload.client_request_id,auth_type:payload.auth_type,
                via_socks:true,socks_proxy_id:payload.socks_proxy?.socks_proxy_id,reconnect_route_known:true,
                password:'never-save-target-password',credential_id:'never-save-credential',
                credential_target_token:'never-save-token',
                socks_proxy:{password:'never-save-proxy-password',host:'never-save-proxy-address',username:'never-save-proxy-username'},
            })));
            return window.socket;
        };
        return result.socks_proxy;
    },authType);
    await page.locator('#workspaceRecentBtn').click();
    await page.locator('#hostInput').fill('history-target.example');
    await page.locator('#portInput').fill('2222');
    await page.locator('#usernameInput').fill('history-user');
    await page.locator('#authTypeSelect').selectOption('password');
    await page.locator('#passwordInput').fill('never-save-target-password');
    await page.locator('#connectionAdvancedSettings').evaluate(element=>{element.open=true;});
    await page.locator('#socksProxySelect').selectOption(proxy.id);
    if (authType==='password') await page.locator('#socksProxyPasswordInput').fill('never-save-proxy-password');
    await page.locator('#connectBtn').click();
    await expect.poll(()=>page.evaluate(()=>window.ConnectionHistory.getHistory().length)).toBe(1);
    expect(await page.evaluate(()=>window.__initialHistoryConnect.socks_proxy.socks_proxy_id)).toBe(proxy.id);
    return proxy;
}

async function reopenHistory(page) {
    await openWorkspace(page);
    await page.locator('#workspaceRecentBtn').click();
    await page.locator('#recentConnectionsCard').evaluate(element=>{element.open=true;});
    await page.locator('#recentConnectionsList .recent-connection-item').filter({hasText:'history-target.example'}).click();
    await page.locator('#authTypeSelect').selectOption('password');
    await page.locator('#passwordInput').fill('target-runtime-password');
}

for (const authType of ['none','password']) {
    test(`recent SOCKS connection retains its route after reload (${authType})`,async({page})=>{
        await login(page);
        const proxy=await rememberProxyConnection(page,authType);
        const history=await page.evaluate(()=>window.ConnectionHistory.getHistory());
        expect(history).toHaveLength(1);
        expect(history[0]).toMatchObject({host:'history-target.example',port:2222,username:'history-user',socks_proxy_id:proxy.id});
        const stored=await page.evaluate(()=>localStorage.getItem(window.ConnectionHistory.storageKey));
        expect(stored).not.toContain('never-save');
        expect(stored).not.toContain('credential');
        await page.reload();
        await expect.poll(()=>page.evaluate(()=>SocksProxyManager.loaded)).toBe(true);
        await installSshConnectTrap(page);
        await reopenHistory(page);
        await expect(page.locator('#socksProxySelect')).toHaveValue(proxy.id);
        if (authType==='password') await page.locator('#socksProxyPasswordInput').fill('proxy-runtime-password');
        await page.locator('#connectBtn').click();
        await expect.poll(()=>page.evaluate(()=>window.__sshConnectAttempts.length)).toBe(1);
        const payload=await page.evaluate(()=>window.__sshConnectAttempts[0].payload);
        expect(payload.socks_proxy).toEqual({socks_proxy_id:proxy.id,...(authType==='password'?{password:'proxy-runtime-password'}:{})});
        expect(payload.host).toBe('history-target.example');
        expect(payload.profile_id).toBeUndefined();
        expect(await page.evaluate(()=>localStorage.getItem(window.ConnectionHistory.storageKey))).not.toContain('runtime-password');
    });
}

test('recent connection with a deleted SOCKS proxy cannot emit a direct request',async({page})=>{
    await login(page);
    const proxy=await rememberProxyConnection(page);
    const deleted=await page.evaluate(id=>new Promise(resolve=>window.socket.emit('delete_socks_proxy',{socks_proxy_id:id},resolve)),proxy.id);
    expect(deleted.success).toBe(true);
    await page.reload();
    await expect.poll(()=>page.evaluate(()=>SocksProxyManager.loaded)).toBe(true);
    await installSshConnectTrap(page);
    await reopenHistory(page);
    await expect(page.locator('#socksProxySelect')).toHaveValue(proxy.id);
    await expect(page.locator('#socksProxySelect option:checked')).toHaveText('SOCKS5 proxy missing');
    await page.locator('#connectBtn').click();
    expect(await page.evaluate(()=>window.__sshConnectAttempts)).toEqual([]);
    await page.locator('#socksProxySelect').selectOption('');
    await page.locator('#connectBtn').click();
    expect(await page.evaluate(()=>window.__sshConnectAttempts)).toEqual([]);
});
