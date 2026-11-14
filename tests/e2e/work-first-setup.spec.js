const path = require('node:path');
const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

for (const width of [390, 1440]) {
    test(`work-first access and observed setup preserve explicit connection at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await installSshConnectTrap(page);
        await page.evaluate(() => {
            ProfileManager.setProfiles([
                {id:'wf-favorite',name:'Favorite task host',host:'192.0.2.11',username:'operator',favorite:true},
                {id:'wf-recent',name:'Recent task host',host:'192.0.2.12',username:'operator'},
            ]);
            const original = ConnectionHistory.getHistory;
            window.__wfRestoreHistory = () => { ConnectionHistory.getHistory = original; };
            ConnectionHistory.getHistory = () => [{host:'192.0.2.12',username:'operator',timestamp:Date.now()}];
            window.dispatchEvent(new Event('session-workspace-change'));
        });
        const first = page.locator('#overviewWorkFirst');
        await expect(first.getByRole('button', {name:'Favorite task host',exact:true})).toBeVisible();
        await expect(first.getByRole('button', {name:'Recent task host',exact:true})).toBeVisible();
        expect(await first.boundingBox().then(box => box.y)).toBeLessThan(await page.locator('#odBoard').boundingBox().then(box => box.y));
        await expect(page.locator('#overviewSetupCount')).toHaveText('1 / 5');
        await page.screenshot({path:path.join(process.env.WEBSSH_E2E_OUTPUT_DIR || 'test-results', `home-${width}-collapsed.png`)});
        await first.locator('summary').click();
        await page.locator('#overviewSetupHost').selectOption('wf-favorite');
        await expect(page.locator('[data-step="host"]')).toHaveAttribute('data-complete','true');
        for (const step of ['auth','trust','terminal','files']) await expect(page.locator(`[data-step="${step}"]`)).toHaveAttribute('data-complete','false');
        await page.screenshot({path:path.join(process.env.WEBSSH_E2E_OUTPUT_DIR || 'test-results', `home-${width}-guide.png`)});
        // Merely opening the guide, changing its target, or searching never connects.
        await page.locator('#overviewSetupHost').selectOption('wf-recent');
        await page.locator('#overviewSearch').fill('Recent task host');
        await expect(first.getByRole('button', {name:'Favorite task host',exact:true})).toHaveCount(0);
        await expect(first.getByRole('button', {name:'Recent task host',exact:true})).toBeVisible();
        expect(await sshAttempts(page)).toEqual([]);
        expect(await first.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
        await first.getByRole('link', {name:'Choose your start page'}).click();
        await expect(page.locator('#settingsStartPage')).toBeVisible();
        await assertNoExternalRequests(page);
    });
}

test('setup marks authentication and files only after observed session and directory response', async ({page}) => {
    await login(page, 'e2e_admin', {workspace:false});
    await page.evaluate(() => {
        const session = {id:'wf-session',profileId:'wf-host',connected:true,host:'192.0.2.21',username:'operator'};
        ProfileManager.setProfiles([{id:'wf-host',name:'Observed host',host:session.host,username:session.username}]);
        SessionManager.getAllSessions = () => [session];
        SessionManager.getSession = id => id === session.id ? session : null;
        window.dispatchEvent(new Event('session-workspace-change'));
    });
    await page.locator('#overviewFirstConnection summary').click();
    for (const step of ['auth','trust','terminal']) await expect(page.locator(`[data-step="${step}"]`)).toHaveAttribute('data-complete','true');
    await expect(page.locator('[data-step="files"]')).toHaveAttribute('data-complete','false');
    await page.evaluate(() => {
        socket.listeners('directory_listing').forEach(listener => listener({source_id:'sftp-session:wf-session',files:[],path:'/home/operator'}));
    });
    await expect(page.locator('[data-step="files"]')).toHaveAttribute('data-complete','true');
    await page.evaluate(() => {
        SessionManager.getAllSessions = () => [];
        window.dispatchEvent(new Event('session-workspace-change'));
    });
    await expect(page.locator('[data-step="terminal"]')).toHaveAttribute('data-complete','false');
    await expect(page.locator('[data-step="files"]')).toHaveAttribute('data-complete','false');
});
test('mobile saved-host fallback offers existing destinations before metrics and retains explicit launch', async ({page}) => {
    await page.setViewportSize({width:390,height:900});
    await login(page,'e2e_admin',{workspace:false});
    await installSshConnectTrap(page);
    await page.evaluate(() => {
        ConnectionHistory.getHistory = () => [];
        ProfileManager.setProfiles(Array.from({length:9},(_,index)=>({id:`fallback-${index}`,name:`Saved target ${index}`,host:`192.0.2.${index+1}`,username:'operator',favorite:false})));
        window.__fallbackLaunches = [];
        window.launchProfileForPane = id => window.__fallbackLaunches.push(id);
        window.dispatchEvent(new Event('session-workspace-change'));
    });
    const first = page.locator('#overviewWorkFirst');
    await expect(first.getByRole('heading',{name:'Saved hosts',exact:true})).toBeVisible();
    await expect(first.locator('.od-shortcut')).toHaveCount(6);
    expect(await sshAttempts(page)).toEqual([]);
    expect(await page.evaluate(()=>window.__fallbackLaunches)).toEqual([]);
    await first.getByRole('button',{name:'Saved target 0',exact:true}).click();
    expect(await page.evaluate(()=>window.__fallbackLaunches)).toEqual(['fallback-0']);
    await page.locator('#overviewNavBtn').evaluate(el=>el.click());
    await page.locator('#overviewSearch').fill('Saved target 8');
    await expect(first.locator('.od-shortcut')).toHaveCount(1);
    await expect(first.getByRole('button',{name:'Saved target 8',exact:true})).toBeVisible();
    for (const theme of ['glass','paper','werkbank','arctic-ice']) {
        await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
        const colors = await first.evaluate(el=>{
            const probe=document.createElement('span');
            probe.style.background='var(--ws2-panel)';probe.style.color='var(--ws2-accent)';el.append(probe);
            const expected=getComputedStyle(probe);const link=getComputedStyle(el.querySelector('a'));
            const value={panel:getComputedStyle(el).backgroundColor,expectedPanel:expected.backgroundColor,link:link.color,expectedLink:expected.color};probe.remove();return value;
        });
        expect(colors.panel).toBe(colors.expectedPanel);
        expect(colors.link).toBe(colors.expectedLink);
        expect(await first.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
    }
    const link = first.getByRole('link',{name:'Choose your start page'});
    await link.focus();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Shift+Tab');
    await expect(link).toBeFocused();
    expect(await link.evaluate(el=>getComputedStyle(el).outlineStyle)).not.toBe('none');
});


test('host context keeps disclosure and keyboard focus after profile updates', async ({page}) => {
    await login(page, 'e2e_admin', {workspace:false});
    await page.evaluate(() => {
        ProfileManager.setProfiles([{id:'context-host', name:'Context host', host:'192.0.2.31', username:'operator'}]);
    });
    const summary = page.locator('[data-key="context:context-host"]');
    const details = page.locator('.od-host-context[data-host-id="context-host"]');
    await summary.click();
    await expect(details).toHaveAttribute('open', '');
    await summary.focus();
    await page.evaluate(() => {
        ProfileManager.setProfiles([{id:'context-host', name:'Renamed context host', host:'192.0.2.31', username:'operator'}]);
    });
    await expect(page.locator('#overviewHostList')).toContainText('Renamed context host');
    await expect(details).toHaveAttribute('open', '');
    await expect(summary).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(details).not.toHaveAttribute('open');
    await page.evaluate(() => {
        ProfileManager.setProfiles([{id:'context-host', name:'Updated context host', host:'192.0.2.31', username:'operator'}]);
    });
    await expect(page.locator('#overviewHostList')).toContainText('Updated context host');
    await expect(details).not.toHaveAttribute('open');
    await expect(summary).toBeFocused();
});

test('mobile setup exposes completion status to assistive technology', async ({page}) => {
    await page.setViewportSize({width:390, height:900});
    await login(page, 'e2e_admin', {workspace:false});
    await page.evaluate(() => ProfileManager.setProfiles([{id:'accessible-host', name:'Accessible host', host:'192.0.2.32', username:'operator'}]));
    await page.locator('#overviewFirstConnection summary').click();
    await expect(page.locator('#overviewSetupSteps [data-step="host"]')).toHaveAttribute('data-complete', 'true');
    expect(await page.locator('#overviewSetupSteps [data-step="host"]').ariaSnapshot()).toContain('Observed');
    expect(await page.locator('#overviewSetupSteps [data-step="auth"]').ariaSnapshot()).toContain('Pending');
});
