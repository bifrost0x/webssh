const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
const fs = require('node:fs');
const path = require('node:path');

for (const width of [1536, 390]) {
    test(`login inventory revokes another browser and preserves this login at ${width}px`, async ({page, browser}) => {
        await page.setViewportSize({width, height:960});
        await login(page);
        const otherContext = await browser.newContext({baseURL:test.info().project.use.baseURL});
        try {
            const other = await otherContext.newPage();
            await login(other);
            const selected = (await (await other.request.get('/api/account/sessions')).json()).sessions.find(row => row.current);
            await page.goto('/settings#security-overview');
            const list = page.locator('#accountLoginList');
            await expect(list.getByText('This login', {exact:false})).toHaveCount(1);
            await expect(page.locator('#accountRevokeOthers')).toBeEnabled();
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
            const directory = path.join('plans', 'account-controls');
            fs.mkdirSync(directory, {recursive:true});
            if (width < 600) await list.scrollIntoViewIfNeeded();
            await page.screenshot({path:path.join(directory, `logins-${width}.png`)});
            page.once('dialog', dialog => dialog.accept());
            await page.locator('#accountRevokeOthers').click();
            await expect(page.locator('#accountLoginStatus')).toHaveText('Selected login access revoked.');
            await expect(list.locator('li')).toHaveCount(1);
            const after = await other.request.get('/api/account/sessions', {maxRedirects:0});
            expect(after.status()).toBe(302);
            const current = await page.request.get('/api/account/sessions');
            expect(current.ok()).toBe(true);
            expect((await current.json()).sessions.some(row => row.handle === selected.handle)).toBe(false);
        } finally { await otherContext.close(); }
    });

    test(`feature impact appears before authentication and cancels with Escape at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:960});
        await login(page);
        const feature = {name:'passkey', deployment_allowed:true, ready:true, active:true, admin_enabled:true};
        await page.route('**/admin/api/security-features', route => route.fulfill({json:{features:[feature]}}));
        await page.route('**/admin/api/security-features/passkey/impact', route => route.fulfill({json:{approval:'synthetic-approval', impact:{
            affected_accounts:4, affected_admins:2, locked_affected_accounts:0, remaining_primary:{password:4},
            remaining_factors:{totp:2}, accounts_without_primary:0, admins_without_primary:0,
            mfa_required_without_local_factor:1, admins_without_local_factor:1, tested:false,
            accounts:[{username:'synthetic_admin_long_account_name', admin:true, locked:false, mfa_required:true, remaining_primary:['password'], remaining_factors:[]}],
        }}}));
        const writes = [];
        page.on('request', request => {
            if (request.method() === 'POST' && (request.url().includes('/api/step-up/') || request.url().includes('/api/security-features/'))) writes.push(request.url());
        });
        await page.goto('/settings#authentication');
        const toggle = page.locator('input[data-security-feature="passkey"]');
        await expect(toggle).toBeChecked();
        await toggle.uncheck();
        const dialog = page.locator('.account-impact-dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('Affected accounts: 4; administrators: 2');
        await expect(dialog).toContainText('Configured, not tested');
        await expect(dialog.locator('.account-impact-warning')).toBeVisible();
        await expect(dialog.getByRole('button', {name:'Cancel', exact:true})).toBeFocused();
        const directory = path.join('plans', 'account-controls');
        fs.mkdirSync(directory, {recursive:true});
        await page.screenshot({path:path.join(directory, `impact-${width}.png`)});
        await dialog.locator('summary').click();
        await expect(dialog).toContainText('synthetic_admin_long_account_name');
        const footer = await dialog.getByRole('button', {name:'Continue to authentication'}).boundingBox();
        expect(footer.y + footer.height).toBeLessThan(960);
        await page.screenshot({path:path.join(directory, `impact-details-${width}.png`)});
        expect(writes).toEqual([]);
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(toggle).toBeChecked();
        await expect(toggle).toBeFocused();
        expect(writes).toEqual([]);
    });
}

test('account deletion names the account and explains quarantined files before authentication', async ({page}) => {
    await login(page);
    await page.goto('/settings#users');
    const row = page.locator('#adminUsersBody tr[data-username="e2e_user"]');
    await row.locator('summary').click();
    await Promise.all([
        page.waitForEvent('dialog').then(async dialog => {
            expect(dialog.message()).toContain('e2e_user');
            expect(dialog.message()).toContain('access will be revoked');
            expect(dialog.message()).toContain('files are retained in quarantine');
            await dialog.dismiss();
        }),
        row.locator('[data-act="delete"]').click(),
    ]);
    await expect(row).toHaveCount(1);
    await expect(page.locator('#stepUpModal')).not.toBeVisible();
});
