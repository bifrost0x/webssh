const { test, expect } = require('playwright/test');
const { assertNoExternalRequests, installExternalRequestGuard } = require('./helpers');

for (const theme of ['glass', 'paper']) {
    test(`login requests its ${theme} background before unrelated assets finish`, async ({ page }) => {
        installExternalRequestGuard(page);
        await page.addInitScript(value => localStorage.setItem('websshTheme', value), theme);
        let releaseLogo;
        const logoGate = new Promise(resolve => { releaseLogo = resolve; });
        const backgrounds = [];
        page.on('request', request => {
            if (/\/(?:theme-backgrounds\/|redesign\/midnight-lodge\.)/.test(request.url())) backgrounds.push(request.url());
        });
        await page.route('**/redesign/webssh-mark.png*', async route => {
            await logoGate;
            await route.continue();
        });
        try {
            await page.goto('/login', { waitUntil: 'domcontentloaded' });
            await expect.poll(() => backgrounds.length, { timeout: 1500 }).toBe(1);
            expect(backgrounds[0]).toContain(theme === 'paper' ? 'paper-blueprint.' : 'midnight-lodge.');
            await expect(page.locator('body')).toHaveAttribute('data-theme', theme);
        } finally {
            releaseLogo();
            await page.waitForLoadState('load');
            await assertNoExternalRequests(page);
        }
    });
}

test('login remains usable while its background is still downloading', async ({ page }) => {
    installExternalRequestGuard(page);
    let releaseBackground;
    let backgroundRequested = false;
    const gate = new Promise(resolve => { releaseBackground = resolve; });
    await page.route('**/redesign/midnight-lodge.webp*', async route => {
        backgroundRequested = true;
        await gate;
        await route.continue();
    });
    try {
        await page.goto('/login', { waitUntil: 'domcontentloaded' });
        await expect.poll(() => backgroundRequested).toBe(true);
        await expect(page.getByRole('heading', { name: 'Access your SSH workspace' })).toBeVisible();
        await page.locator('input[name="username"]').fill('still-responsive');
        await expect(page.locator('input[name="username"]')).toHaveValue('still-responsive');
    } finally {
        releaseBackground();
        await page.waitForLoadState('load');
        await assertNoExternalRequests(page);
    }
});
