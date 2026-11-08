const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

for (const width of [390, 1440]) {
    test(`cancelling a host file connection returns keyboard focus to Files at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 800});
        await login(page, 'e2e_admin', {workspace: false});
        if (!await page.locator('#fileTransferBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
        await page.locator('#fileTransferBtn').click();
        await page.locator('#fmLeftList .fm-empty-source-cta').click();
        await expect(page.locator('#fmSourceLauncher')).toBeVisible();
        await page.locator('#fmSourceSearch').fill('Password review');
        await page.locator('#fmSourceGroups .fm-source-row').filter({hasText: 'Password review'}).first().click();
        await expect(page.locator('#fmQcHost')).toHaveValue('password.local');
        await page.locator('#fmQcCancel').click();
        // Cancelling returns to the chooser on the host that was picked.
        await expect(page.locator('#fmSourceLauncher')).toBeVisible();
        await expect(page.locator('#fmSourceGroups [data-source-key="profile:password-review"]')).toBeFocused();
        await page.keyboard.press('Escape');
        await expect(page.locator('#fmSourceLauncher')).toBeHidden();
        const choose = page.locator('#fmLeftList .fm-empty-source-cta');
        await expect(choose).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(page.locator('#fmSourceLauncher')).toBeVisible();
        await expect(page.locator('#fmSourceSearch')).toBeFocused();
        await assertNoExternalRequests(page);
    });
}
