const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

for (const width of [390, 1536]) {
    test(`admin authentication supports keyboard cancellation and focus containment at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await login(page);
        await page.goto('/settings#backup');
        await page.locator('#backupCreateBtn').click();
        const modal = page.locator('#stepUpModal');
        await expect(page.locator('#stepUpPassword')).toBeFocused();
        await page.locator('#stepUpSubmit').focus();
        await page.keyboard.press('Tab');
        await expect(page.locator('#stepUpCancel')).toBeFocused();
        await page.keyboard.press('Shift+Tab');
        await expect(page.locator('#stepUpSubmit')).toBeFocused();
        await page.keyboard.press('Escape');
        await expect(modal).not.toBeVisible();
        await expect(page.locator('#backupCreateBtn')).toBeEnabled();
        await expect(page.locator('#backupCreateBtn')).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(modal).toBeVisible();
        await expect(page.locator('#stepUpPassword')).toHaveValue('');
        await page.keyboard.press('Escape');
    });
}

// Successful Enter submission is covered in admin-functional-flows.spec.js,
// including the real archive download, verification and restore cancellation.
