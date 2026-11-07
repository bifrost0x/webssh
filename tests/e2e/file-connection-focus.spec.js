const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

for (const width of [390, 1440]) {
    test(`cancelling a host file connection returns keyboard focus to Files at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 800});
        await login(page, 'e2e_admin', {workspace: false});
        await page.locator('#overviewHostSearch').fill('Password review');
        await page.getByRole('button', {name: 'Connection details: Password review', exact: true}).click();
        await page.getByRole('button', {name: 'Open files', exact: true}).click();
        await expect(page.locator('#fmQcHost')).toHaveValue('password.local');
        await page.locator('#fmQcCancel').click();
        const choose = page.locator('#fmLeftList .fm-empty-source-cta');
        await expect(choose).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(page.locator('#fmSourceLauncher')).toBeVisible();
        await expect(page.locator('#fmSourceSearch')).toBeFocused();
        await assertNoExternalRequests(page);
    });
}
