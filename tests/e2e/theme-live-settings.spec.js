const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('settings theme changes reach an open workspace without losing its current search', async ({page, context}) => {
    await login(page);
    await page.locator('#commandLibraryBtn').click();
    await page.locator('#commandSearchInput').fill('pwd');
    const settings = await context.newPage();
    await settings.goto('/settings#preferences');
    for (const theme of ['paper', 'noir', 'glass', 'werkbank', 'arctic-ice']) {
        await settings.locator('#settingsThemeSelect').selectOption(theme);
        await expect(settings.locator('#settingsThemeSelect')).toBeEnabled();
        await expect(page.locator('body')).toHaveAttribute('data-theme', theme);
        await expect(page.locator('#commandSearchInput')).toHaveValue('pwd');
        await expect(page.locator('#commandWorkspaceModal')).toBeVisible();
    }
    await settings.close();
});
