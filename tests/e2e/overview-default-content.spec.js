const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests, openWorkspace} = require('./helpers');

test('normal login opens Overview and instance identity is the actual browser host', async ({page}) => {
    await page.goto('/login');
    await expect(page.locator('#authInstanceAddress')).toHaveText(new URL(page.url()).host);
    await expect(page.locator('.auth-status-dot')).toHaveCount(0);
    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('#overviewNavBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#connectionOverview')).toBeVisible();
    await expect(page.locator('.main-content')).toBeHidden();
    await expect(page.locator('#overviewHosts .overview-compact-row [data-host-id]').first()).toBeVisible();
    await page.locator('#overviewHostSearch').fill('Usable key');
    await expect(page.locator('#overviewHosts')).toContainText('Usable key');
    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('.main-content')).toBeVisible();
    await expect(page.locator('#workspaceStatusState')).toHaveText('No active session');
    await expect(page.locator('#workspaceStatusUserField')).toBeHidden();
    await expect(page.locator('#workspaceStatusTarget')).toBeHidden();
    await expect(page.locator('#workspaceStatusTransferCount')).toHaveText('0');
    await page.locator('#workspaceStatusTransfers').click();
    await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'files');
    await assertNoExternalRequests(page);
});

for (const view of ['overview', 'workspaces', 'hosts', 'commands']) {
    test(`reauthentication handles saved ${view} view with Overview as the empty workspace default`, async ({page}) => {
        await login(page, 'e2e_admin', {workspace: false});
        await page.evaluate(view => {
            const ids = {overview: 'overviewNavBtn', workspaces: 'workspaceNavBtn', hosts: 'manageProfilesBtn', commands: 'commandLibraryBtn'};
            document.getElementById(ids[view]).click();
            window.AuthSessionGuard.saveRestore(window, document, sessionStorage);
        }, view);
        await page.reload();
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', view === 'workspaces' ? 'overview' : view);
        expect(await page.evaluate(() => Object.keys(sessionStorage)
            .filter(key => key.startsWith('webssh:auth-session-return:')))).toEqual([]);
    });
}

for (const width of [1440, 390]) {
    test(`route guidance explains setup and opens jump-host management at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await expect.poll(() => page.evaluate(() => JumpHostManager.loaded)).toBe(true);
        await page.evaluate(() => {
            JumpHostManager.setJumpHosts([]);
            ProfileManager.setProfiles([{id:'route-guide', name:'Route target', group:'Test'}]);
        });
        await page.locator('#overviewHosts [data-host-id]').first().click();
        const help = page.locator('.overview-access-inspector');
        await expect(help).toBeVisible();
        await expect(help.getByRole('button', {name:'Edit access',exact:true})).toBeVisible();
        const stops = page.locator('#overviewHosts .overview-path-stops > li');
        await expect(stops).toHaveCount(2);
        await expect(stops.last()).toContainText('Route target');
        // A jump host alone is not a route: the saved host must select it.
        await page.evaluate(() => JumpHostManager.setJumpHosts([{id:'route-jump', name:'Route bastion'}]));
        await expect(stops).toHaveCount(2);
        await page.evaluate(() => ProfileManager.setProfiles([
            {...ProfileManager.profiles[0], jump_host_id:'route-jump'},
        ]));
        await expect(stops).toHaveCount(3);
        await expect(stops.nth(1)).toContainText('Route bastion');
        await help.getByRole('button', {name:'Manage jump hosts',exact:true}).click();
        await expect(page.locator('#jumpHostManagementModal')).toBeVisible();
        await expect(page.locator('#jumpResourceNew')).toBeVisible();
        await page.locator('#jumpResourceNew').click();
        await expect(page.locator('#jumpHostForm')).toBeVisible();
        if (!await page.locator('#overviewNavBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
        await page.locator('#overviewNavBtn').click();
        await page.locator('#overviewHosts [data-host-id]').first().click();
        await expect(help).toBeVisible();
        expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
        await help.getByRole('button', {name:'Manage jump hosts',exact:true}).focus();
        await page.keyboard.press('Enter');
        await expect(page.locator('#jumpHostManagementModal')).toBeVisible();
        await assertNoExternalRequests(page);
    });
}

for (const width of [390, 1440]) {
    test(`login after empty workspace expiry opens Overview at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 844});
        await login(page, 'e2e_admin', {workspace: false});
        await openWorkspace(page);
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'workspaces');
        // Simulate expired authentication while retaining this tab's restore storage.
        await page.context().clearCookies();
        await page.evaluate(() => window.AuthSessionGuard.create().expire());
        await expect(page).toHaveURL(/\/login\?next=/);
        await page.locator('#username').fill('e2e_admin');
        await page.locator('#password').fill('browser-password');
        await page.locator('form button[type="submit"]').click();
        await expect(page).toHaveURL(/\/$/);
        await expect(page.locator('#connectionOverview')).toBeVisible();
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'overview');
        await expect(page.locator('.main-content')).toBeHidden();
        expect(await page.evaluate(() => Object.keys(sessionStorage).filter(key => key.startsWith('webssh:auth-session-return:')))).toEqual([]);
        await assertNoExternalRequests(page);
    });
}
