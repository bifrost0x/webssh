const { test, expect } = require('playwright/test');
const { assertNoExternalRequests } = require('./helpers');

for (const theme of ['glass', 'paper']) {
    test(`login requests its ${theme} background before unrelated assets finish`, async ({ page }) => {
        assertNoExternalRequests(page);
        await page.addInitScript(value => localStorage.setItem('websshTheme', value), theme);
        let releaseLogo;
        const logoGate = new Promise(resolve => { releaseLogo = resolve; });
        const backgrounds = [];
        page.on('request', request => {
            if (request.url().includes('/theme-backgrounds/')) backgrounds.push(request.url());
        });
        await page.route('**/webssh-logo.svg*', async route => {
            await logoGate;
            await route.continue();
        });
        try {
            await page.goto('/login', { waitUntil: 'domcontentloaded' });
            await expect.poll(() => backgrounds.length, { timeout: 1500 }).toBe(1);
            expect(backgrounds[0]).toContain(theme === 'paper' ? 'paper-blueprint.' : 'carbon-glass.');
            await expect(page.locator('body')).toHaveAttribute('data-theme', theme);
        } finally {
            releaseLogo();
            await page.waitForLoadState('load');
        }
    });
}

test('login remains usable while its background is still downloading', async ({ page }) => {
    assertNoExternalRequests(page);
    let releaseBackground;
    const gate = new Promise(resolve => { releaseBackground = resolve; });
    await page.route('**/theme-backgrounds/**', async route => {
        await gate;
        await route.continue();
    });
    try {
        await page.goto('/login', { waitUntil: 'domcontentloaded' });
        await expect(page.getByRole('heading', { name: 'Access your SSH workspace' })).toBeVisible();
        await page.locator('input[name="username"]').fill('still-responsive');
        await expect(page.locator('input[name="username"]')).toHaveValue('still-responsive');
    } finally {
        releaseBackground();
        await page.waitForLoadState('load');
    }
});
