const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

test('SOCKS management and its editor work from the keyboard', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    const entry = page.locator('#profileManagementModal .connection-asset-nav [data-connection-asset="socks-proxies"]');
    await entry.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#socksProxyManagementModal')).toBeVisible();
    await page.locator('#socksResourceNew').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#spNameInput')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#spHostInput')).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#spNameInput')).toBeFocused();
    await assertNoExternalRequests(page);
});
