const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test('normal login opens Overview and instance identity is the actual browser host', async ({page}) => {
    await page.goto('/login');
    await expect(page.locator('#authInstanceAddress')).toHaveText(new URL(page.url()).host);
    await expect(page.locator('.auth-status-dot')).toHaveCount(0);
    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('#overviewNavBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#connectionOverview')).toBeVisible();
    await expect(page.locator('.main-content')).toBeHidden();
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
    test(`reauthentication keeps the saved ${view} view instead of overriding it with the login default`, async ({page}) => {
        await login(page, 'e2e_admin', {workspace: false});
        await page.evaluate(view => {
            const ids = {overview: 'overviewNavBtn', workspaces: 'workspaceNavBtn', hosts: 'manageProfilesBtn', commands: 'commandLibraryBtn'};
            document.getElementById(ids[view]).click();
            window.AuthSessionGuard.saveRestore(window, document, sessionStorage);
        }, view);
        await page.reload();
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', view);
        expect(await page.evaluate(() => Object.keys(sessionStorage)
            .filter(key => key.startsWith('webssh:auth-session-return:')))).toEqual([]);
    });
}
