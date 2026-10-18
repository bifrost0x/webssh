const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.describe('touch landscape navigation', () => {
    test.use({ hasTouch: true, viewport: { width: 844, height: 390 } });

    for (const width of [844, 1280]) {
        test(`mobile shell keeps the full workspace width at ${width}px`, async ({ page }) => {
            await page.setViewportSize({ width, height: 390 });
            await login(page);
            await page.evaluate(() => SessionManager.createSession({
                session_id: 'landscape-fixture', host: 'landscape.example.invalid', username: 'fixture', port: 22,
            }));
            await expect.poll(() => page.evaluate(() => TerminalManager.terminalReady['landscape-fixture'])).toBe(true);
            await page.evaluate(() => { window.__landscapeTerminal = TerminalManager.terminals['landscape-fixture']; });
            expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
            await expect(page.locator('body')).toHaveCSS('padding-left', '0px');
            await expect(page.locator('.header-buttons')).toBeHidden();
            expect(await page.locator('body').evaluate(body => getComputedStyle(body, '::after').content)).toBe('none');
            await page.locator('#mobileMoreBtn').click();
            await expect(page.locator('#overviewNavBtn')).toBeVisible();
            await expect(page.locator('.global-navigation')).toHaveCSS('position', 'static');
            await page.locator('#overviewNavBtn').click();
            await expect(page.locator('#connectionOverview')).toBeVisible();
            await expect(page.locator('.header-buttons')).toBeHidden();
            await page.locator('[data-mobile-view="workspaces"]').click();
            await expect(page.locator('#connectionOverview')).toBeHidden();
            await expect(page.locator('.main-content')).toBeVisible();

            for (const viewport of [{ width: 390, height: 844 }, { width, height: 390 }]) {
                await page.setViewportSize(viewport);
                await expect(page.locator('body')).toHaveCSS('padding-left', '0px');
                const geometry = await page.locator('.main-content').boundingBox();
                expect(geometry.x).toBeLessThanOrEqual(1);
                expect(geometry.width).toBeGreaterThanOrEqual(viewport.width - 2);
                expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
                expect(await page.evaluate(() => TerminalManager.terminals['landscape-fixture'] === window.__landscapeTerminal)).toBe(true);
            }
            await assertNoExternalRequests(page);
        });
    }

    test('touch tablet above the phone height breakpoint keeps the rail', async ({ page }) => {
        await page.setViewportSize({ width: 844, height: 521 });
        await login(page);
        await expect(page.locator('body')).toHaveCSS('padding-left', '72px');
        await expect(page.locator('.global-navigation')).toHaveCSS('position', 'fixed');
        await expect(page.locator('#overviewNavBtn')).toBeVisible();
        await assertNoExternalRequests(page);
    });
});

test('short desktop windows keep the rail with a fine pointer', async ({ page }) => {
    await page.setViewportSize({ width: 844, height: 390 });
    await login(page);
    expect(await page.evaluate(() => matchMedia('(pointer: fine)').matches)).toBe(true);
    await expect(page.locator('body')).toHaveCSS('padding-left', '72px');
    await expect(page.locator('.global-navigation')).toHaveCSS('position', 'fixed');
    await assertNoExternalRequests(page);
});
