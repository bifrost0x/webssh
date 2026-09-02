const { test, expect } = require('playwright/test');
const { assertNoExternalRequests } = require('./helpers');

test('login load does not wait for the decorative theme background', async ({ page }) => {
    assertNoExternalRequests(page);
    let releaseBackground;
    let backgroundRequested = false;
    const backgroundGate = new Promise(resolve => {
        releaseBackground = resolve;
    });
    await page.route('**/theme-backgrounds/**', async route => {
        backgroundRequested = true;
        await backgroundGate;
        await route.continue();
    });

    const navigation = page.goto('/login', { waitUntil: 'load' });
    const loadedWithoutBackground = await Promise.race([
        navigation.then(() => true),
        new Promise(resolve => setTimeout(() => resolve(false), 1500)),
    ]);

    releaseBackground();
    await navigation;

    expect(loadedWithoutBackground).toBe(true);
    await expect(page.getByRole('heading', { name: 'Access your SSH workspace' }))
        .toBeVisible();
    await expect.poll(() => backgroundRequested).toBe(true);
    await expect(page.locator('body')).toHaveAttribute(
        'data-theme-background-ready',
        '',
    );
});
