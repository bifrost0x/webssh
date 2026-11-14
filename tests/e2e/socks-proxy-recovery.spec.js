const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');

test('recovery check identifies missing SOCKS routes without connecting', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.route('**/api/account/recovery-check', route => route.fulfill({json: {
        needs_review: false, schedules: [], hosts: [{
            id: 'socks-key-host', name: 'Restored proxy target', credential: 'ready',
            route: 'missing_socks', host_key: 'trusted',
        }],
    }}));
    await page.evaluate(() => document.querySelector('[data-recovery-check]').click());
    const row = page.getByRole('dialog').locator('.customer-row').filter({hasText: 'Restored proxy target'});
    await expect(row).toContainText('Referenced SOCKS5 proxy is missing');
    await expect(row).not.toContainText('Configuration present');
    expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
    await assertNoExternalRequests(page);
});
