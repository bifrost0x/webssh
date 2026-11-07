const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

for (const method of ['password', 'totp', 'recent']) {
    test(`cancelled recovery action does not dispatch after late ${method} verification`, async ({page}) => {
        await login(page);
        await page.goto('/admin');
        let release;
        let entered;
        let mutations = 0;
        const gate = new Promise(resolve => { release = resolve; });
        const started = new Promise(resolve => { entered = resolve; });
        await page.route('**/api/step-up/intents', async route => {
            if (method === 'recent') {
                entered();
                await gate;
                await route.fulfill({json: {grant: 'fixture-grant'}});
            } else await route.fulfill({json: {methods: [method]}});
        });
        if (method !== 'recent') await page.route(`**/api/step-up/${method}`, async route => {
            entered();
            await gate;
            await route.fulfill({json: {grant: 'fixture-grant'}});
        });
        await page.route('**/admin/api/users/*/recovery', async route => {
            mutations += 1;
            await route.fulfill({json: {codes: ['must-not-be-generated']}});
        });
        const row = page.locator('#adminUsersBody tr').filter({hasText: 'e2e_user'});
        const open = async () => {
            await row.locator('.admin-action-menu > summary').click();
            await row.locator('button[data-act="recovery"]').click();
        };
        await open();
        await page.locator('#securityActionConfirmation').fill('e2e_user');
        await page.locator('#submitSecurityAction').click();
        if (method !== 'recent') {
            await page.locator(method === 'password' ? '#stepUpPassword' : '#stepUpTotp').fill(method === 'password' ? 'fixture' : '123456');
            await page.locator('#stepUpSubmit').click();
        }
        await started;
        await page.locator('#closeSecurityAction').click();
        await open();
        await expect(page.locator('#submitSecurityAction')).toBeDisabled();
        release();
        await expect(page.locator('#submitSecurityAction')).toBeEnabled();
        expect(mutations).toBe(0);
        await expect(page.locator('#securityActionResult')).toHaveValue('');
    });
}
