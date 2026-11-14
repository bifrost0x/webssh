const {test, expect} = require('playwright/test');
const {login, openProfileManagement, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');

async function openProxies(page) {
    await openProfileManagement(page);
    await page.locator('#profileManagementModal .connection-asset-nav [data-connection-asset="socks-proxies"]').click();
    await expect.poll(() => page.evaluate(() => SocksProxyManager.loaded)).toBe(true);
}

for (const width of [390, 1536]) {
    test(`SOCKS CRUD, validation and checkbox drafts at ${width}`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await openProxies(page);
        await page.locator('#socksResourceNew').click();
        await expect(page.locator('#spPortInput')).toHaveValue('1080');
        await expect(page.locator('#spRemoteDns')).toBeChecked();
        const name = `Office proxy ${width}`;
        await page.locator('#spNameInput').fill(name);
        await page.locator('#spHostInput').fill('office.example');
        await page.locator('#spPortInput').fill('0');
        await page.locator('#saveSocksProxyBtn').click();
        expect(await page.locator('#spPortInput').evaluate(input => input.validity.rangeUnderflow)).toBe(true);
        await page.locator('#spPortInput').fill('1080');
        await page.locator('#saveSocksProxyBtn').click();
        const row = page.locator('#socksProxiesList .key-item').filter({hasText:name});
        await expect(row).toContainText('office.example:1080');
        const id = await page.evaluate(name => SocksProxyManager.socksProxies.find(proxy => proxy.name === name).id, name);
        await row.getByRole('button', {name:'Edit', exact:true}).click();
        await page.locator('#spRemoteDns').uncheck();
        expect(await page.evaluate(() => SocksProxyManager.isDirty())).toBe(true);
        page.once('dialog', dialog => dialog.dismiss());
        await page.locator('#cancelSocksProxyEdit').click();
        await expect(page.locator('#spRemoteDns')).not.toBeChecked();
        await page.locator('[name="spAuthType"][value="password"]').check();
        await expect(page.locator('#spUsernameInput')).toBeVisible();
        await expect(page.locator('[data-i18n="socksproxies.passwordWarning"]')).toBeVisible();
        await page.locator('#spUsernameInput').fill('proxyuser');
        await page.locator('#spHostInput').fill('edited.example');
        await page.locator('#saveSocksProxyBtn').click();
        await expect(row).toContainText('edited.example:1080');
        expect(await page.evaluate(id => SocksProxyManager.getById(id).remote_dns, id)).toBe(false);
        await page.reload();
        await openProxies(page);
        await expect(row).toContainText('edited.example:1080');
        expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)).toBe(false);
        await page.screenshot({path:`plans/socks-ui-review/proxies-${width}.png`,fullPage:true});
        page.once('dialog', dialog => dialog.accept());
        await row.getByRole('button', {name:'Delete',exact:true}).click();
        await expect(row).toHaveCount(0);
        await assertNoExternalRequests(page);
    });
}

test('SOCKS route selector excludes Jump and Tailscale and saves the reference', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.evaluate(() => ProfileManager.openEditor('socks-key-host'));
    const proxyId = await page.evaluate(() => ProfileManager.profiles.find(item => item.id === 'socks-key-host').socks_proxy_id);
    await page.locator('#profileAdvancedSettingsCard').evaluate(element => { element.open = true; });
    await expect(page.locator('#profileEditorSocksProxySelect')).toHaveValue(proxyId);
    await expect(page.locator('#profileEditorJumpHostSelect')).toBeDisabled();
    await page.locator('#profileEditorSocksProxySelect').selectOption('');
    await expect(page.locator('#profileEditorJumpHostSelect')).toBeEnabled();
    const jumpId = await page.evaluate(() => JumpHostManager.jumpHosts[0].id);
    await page.locator('#profileEditorJumpHostSelect').selectOption(jumpId);
    await expect(page.locator('#profileEditorSocksProxySelect')).toBeDisabled();
    await page.locator('#profileEditorJumpHostSelect').selectOption('');
    await page.locator('#profileEditorSocksProxySelect').selectOption(proxyId);
    await page.locator('#profileEditorAuthType').selectOption('tailscale');
    await expect(page.locator('#profileEditorSocksProxySelect')).toBeDisabled();
    await expect(page.locator('#profileEditorJumpHostSelect')).toBeDisabled();
    await expect(page.locator('#profileEditorRouteHint')).toHaveText('Tailscale SSH connects directly.');
    await page.locator('#profileEditorAuthType').selectOption('key');
    await page.locator('#profileEditorForm button[type="submit"][data-i18n="common.save"]').click();
    await expect(page.locator('#profileManagementModal')).not.toHaveClass(/has-profile-editor/);
    await page.reload();
    await openProfileManagement(page);
    await page.evaluate(() => ProfileManager.openEditor('socks-key-host'));
    await expect(page.locator('#profileEditorSocksProxySelect')).toHaveValue(proxyId);
});

test('SOCKS key launch keeps the route and missing references cannot silently become direct', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(() => window.launchProfileForPane('socks-key-host'));
    await expect.poll(() => page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    const payload = await page.evaluate(() => window.__sshConnectAttempts[0].payload);
    const proxyId = await page.evaluate(() => ProfileManager.profiles.find(item => item.id === 'socks-key-host').socks_proxy_id);
    expect(payload.socks_proxy).toEqual({socks_proxy_id:proxyId});
    await page.evaluate(() => window.launchProfileForPane('missing-socks-host'));
    await expect(page.locator('#socksProxySelect')).toHaveValue('missing-socks-proxy');
    await page.evaluate(() => {
        SocksProxyManager.setSocksProxies([...SocksProxyManager.socksProxies]);
        document.getElementById('connectionForm').requestSubmit();
    });
    await expect(page.locator('#socksProxySelect')).toHaveValue('missing-socks-proxy');
    expect(await page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    await page.locator('#socksProxySelect').selectOption('');
    await page.locator('#connectBtn').click();
    expect(await page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
});

test('manual SOCKS password is included only in the connection and then cleared', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(() => window.launchProfileForPane('socks-password-host'));
    await expect(page.locator('#socksProxyPasswordInput')).toBeVisible();
    await page.locator('#socksProxyPasswordInput').fill('runtime-proxy-secret');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    const payload = await page.evaluate(() => window.__sshConnectAttempts[0].payload);
    expect(payload.socks_proxy.password).toBe('runtime-proxy-secret');
    expect(Object.keys(payload.socks_proxy).sort()).toEqual(['password','socks_proxy_id']);
    await expect(page.locator('#socksProxyPasswordInput')).toHaveValue('');
});

test('saved SOCKS password launches automatically and reconnect retains the reference', async ({page}) => {
    await login(page);
    const proxy = await page.evaluate(() => SocksProxyManager.socksProxies.find(item => item.auth_type === 'password'));
    const resourceId = `socks:${proxy.id}`;
    await page.route('**/api/credentials/state', route => route.fulfill({json:{enabled:true,
        profiles:[{...proxy,id:resourceId,kind:'socks'}],credentials:[{id:'proxy-password',name:'Proxy password',uses:[{resource_id:resourceId,valid:true}]}]}}));
    await installSshConnectTrap(page);
    await page.evaluate(() => window.launchProfileForPane('socks-password-host'));
    await expect.poll(() => page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    const payload = await page.evaluate(() => window.__sshConnectAttempts[0].payload);
    expect(payload.socks_proxy).toEqual({socks_proxy_id:proxy.id,credential_id:resourceId});
    await page.evaluate(proxyId => {
        SessionManager.sessions['socks-reconnect'] = {id:'socks-reconnect',host:'routed.example',port:22,username:'deploy',
            connected:false,authType:'password',socksProxyId:proxyId,viaSocks:true,reconnectRouteKnown:true};
        SessionManager.requestReconnect('socks-reconnect');
    },proxy.id);
    await expect(page.locator('#socksProxySelect')).toHaveValue(proxy.id);
    await expect.poll(() => page.evaluate(() => CredentialPicker.get('socksProxyPasswordInput'))).toBe(resourceId);
});

test('SOCKS save timeout keeps checkbox draft and locks duplicate submission', async ({page}) => {
    await login(page);
    await openProxies(page);
    await page.locator('#socksResourceNew').click();
    await page.locator('#spNameInput').fill('Uncertain proxy');
    await page.locator('#spHostInput').fill('uncertain.example');
    await page.locator('#spRemoteDns').uncheck();
    await page.evaluate(() => { window.socket.timeout = () => ({emit:(event,payload,callback) => {window.socksSaveCallback=callback;}}); });
    await page.locator('#saveSocksProxyBtn').click();
    await expect(page.locator('#saveSocksProxyBtn')).toBeDisabled();
    await page.evaluate(() => window.socksSaveCallback(new Error('timeout')));
    await expect(page.locator('#spNameInput')).toHaveValue('Uncertain proxy');
    await expect(page.locator('#spRemoteDns')).not.toBeChecked();
    await expect(page.locator('#spSaveStatus')).toContainText('Check the saved list');
    await expect(page.locator('#saveSocksProxyBtn')).toBeDisabled();
});

test('SOCKS hosts are blocked at all Quick SFTP entry points', async ({page}) => {
    await login(page);
    const result = await page.evaluate(() => {
        const manager = window.sftpFileManager;
        const profile = ProfileManager.profiles.find(item => item.id === 'socks-key-host');
        manager.qcProfiles = [profile];
        const source = manager.buildSourceCatalog().flatMap(group => group.items).find(item => item.profileId === profile.id);
        manager.onProfileSelect(profile.id);
        const emitted = [];
        const original = manager.socket.emit;
        manager.socket.emit = (event,payload) => emitted.push({event,payload});
        try { manager.submitQuickConnect(); } finally { manager.socket.emit=original; }
        return {disabled:source.disabled,status:source.status,emitted};
    });
    expect(result.disabled).toBe(true);
    expect(result.status).toContain('Connect a terminal first');
    expect(result.emitted).toEqual([]);
});

test('deletion of a referenced SOCKS proxy reports its hosts', async ({page}) => {
    await login(page);
    await openProxies(page);
    const row = page.locator('#socksProxiesList .key-item').filter({hasText:'E2E none SOCKS proxy'});
    page.once('dialog', dialog => dialog.accept());
    await row.getByRole('button',{name:'Delete',exact:true}).click();
    await expect(page.locator('.notification').filter({hasText:'This SOCKS5 proxy is used by'})).toContainText('SOCKS key host');
    await expect(row).toBeVisible();
    await expect(page.locator('.notification').filter({hasText:/SOCKS.*used by/})).toHaveCount(1);
});

test('managing proxies from the connection dialog leaves the dialog', async ({page}) => {
    await login(page);
    await page.locator('#workspaceRecentBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/\bshow\b/);
    await page.locator('#connectionAdvancedSettings').evaluate(element => { element.open = true; });
    await page.locator('#connectionModal [data-connection-asset="socks-proxies"]').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/\bshow\b/);
    await expect(page.locator('#socksProxyManagementModal')).toBeVisible();
    await expect(page.locator('#socksProxiesList .key-item').first()).toBeVisible();
});

test('programmatic jump and SOCKS routes replace each other in the connection form', async ({page}) => {
    await login(page);
    await page.locator('#workspaceRecentBtn').click();
    await page.locator('#connectionAdvancedSettings').evaluate(element => { element.open = true; });
    await expect.poll(() => page.evaluate(() => JumpHostManager.loaded && SocksProxyManager.loaded)).toBe(true);
    const ids = await page.evaluate(() => ({
        jump: JumpHostManager.jumpHosts[0].id,
        socks: SocksProxyManager.socksProxies.find(proxy => proxy.auth_type === 'none').id,
    }));
    await page.locator('#socksProxySelect').selectOption(ids.socks);
    await page.evaluate(id => window.prepareSessionReconnectJump({jumpHostId: id, reconnectRouteKnown: true}, {applyToForm: true}), ids.jump);
    await expect(page.locator('#jumpHostSelect')).toHaveValue(ids.jump);
    await expect(page.locator('#socksProxySelect')).toHaveValue('');
    await expect(page.locator('#socksProxySelect')).toBeDisabled();
    await expect(page.locator('#connectionRouteHint')).toBeVisible();
    await page.evaluate(id => window.prepareSessionReconnectJump({socksProxyId: id, viaSocks: true, reconnectRouteKnown: true}, {applyToForm: true}), ids.socks);
    await expect(page.locator('#socksProxySelect')).toHaveValue(ids.socks);
    await expect(page.locator('#jumpHostSelect')).toHaveValue('');
    await expect(page.locator('#jumpHostSelect')).toBeDisabled();
});

test('SOCKS overview and route map identify the proxy and missing references', async ({page}) => {
    const errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    await login(page,'e2e_admin',{workspace:false});
    const host=page.locator('#overviewHostList [data-host-id="socks-key-host"]');
    await expect(host.locator('[data-route="socks"]')).toContainText('E2E none SOCKS proxy');
    await expect(host.locator('[data-route="socks"] .material-icons')).toHaveText('lan');
    await expect(page.locator('#overviewHostList [data-host-id="missing-socks-host"]')).toContainText('SOCKS5 proxy missing');
    await expect(page.locator('#odTopology')).toHaveAttribute('aria-label',/2 SOCKS5 proxies/);
    await page.locator('#overviewOpenMap').click();
    const proxy=page.locator('.ssh-route-source').filter({hasText:'E2E none SOCKS proxy'});
    await expect(proxy).toContainText('SOCKS5 Proxy');
    await expect(proxy.locator(':scope > .material-icons')).toHaveText('lan');
    await page.screenshot({path:'plans/socks-ui-review/route-map.png',fullPage:true});
    expect(errors).toEqual([]);
});

test('SOCKS errors offer proxy review without exposing the server response', async ({page}) => {
    await login(page);
    await page.evaluate(() => window.socket.listeners('ssh_error').forEach(listener=>listener({code:'socks_auth_failed',error:'secret proxy response'})));
    await expect(page.locator('.notification').filter({hasText:'SOCKS5 proxy login failed'})).not.toContainText('secret proxy response');
    await page.getByRole('button',{name:'Review SOCKS5 proxy',exact:true}).click();
    await expect(page.locator('#socksProxyManagementModal')).toBeVisible();
});

test('host export warns that SOCKS routes are omitted', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#exportProfilesBtn').locator('xpath=ancestor::details').locator('summary').click();
    const download=page.waitForEvent('download');
    await page.locator('#exportProfilesBtn').click();
    await download;
    await expect(page.locator('.notification').filter({hasText:'SOCKS5 route not exported'})).toBeVisible();
});
