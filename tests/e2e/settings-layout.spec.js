const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('settings sections share their content track and user actions remain reachable', async ({page}, testInfo) => {
    test.setTimeout(120000);
    await login(page, 'e2e_admin', {workspace: false});
    await page.goto('/settings');
    for (const width of [390, 1440, 3440]) {
        await page.setViewportSize({width, height: 900});
        let reference;
        for (const section of ['preferences', 'factors', 'password', 'users', 'authentication', 'backup']) {
            const mobile = page.locator('#settingsMobileSection');
            if (await mobile.isVisible()) await mobile.selectOption(section);
            else await page.locator(`[data-account-section="${section}"],.admin-tab[data-settings-section="${section}"],.admin-tab[data-tab="${section}"]`).first().click();
            const panel = page.locator('.settings-center-content > .admin-panel:visible');
            await expect(panel).toHaveCount(1);
            const box = await panel.boundingBox();
            reference ||= box;
            expect(Math.abs(box.x - reference.x)).toBeLessThan(1);
            expect(Math.abs(box.width - reference.width)).toBeLessThan(1);
            expect(box.x).toBeGreaterThanOrEqual(0);
            expect(box.x + box.width).toBeLessThanOrEqual(width);
            if (width === 3440) expect(box.width).toBeGreaterThan(2200);
            if (section === 'users') {
                const menu = page.locator('.admin-action-menu').first();
                await menu.locator('summary').click();
                const actions = menu.locator('.admin-actions');
                await expect(actions).toBeVisible();
                await actions.scrollIntoViewIfNeeded();
                expect(await actions.evaluate(el => {
                    const a = el.getBoundingClientRect();
                    const hit = document.elementFromPoint(a.left + a.width / 2, a.bottom - 10);
                    return a.bottom <= innerHeight && el.contains(hit);
                })).toBe(true);
                await page.screenshot({path: testInfo.outputPath(`users-${width}.png`)});
                await menu.locator('summary').click();
            }
        }
    }
});
