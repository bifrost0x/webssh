const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

const themes = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];
test.afterEach(async ({page}) => assertNoExternalRequests(page));

for (const width of [360, 768, 1366, 3440]) {
    test(`automation navigation and controls remain usable at ${width}px in every theme`, async ({page}, testInfo) => {
        test.setTimeout(90000);
        await page.setViewportSize({width, height: 900});
        await login(page, 'e2e_admin', {workspace: false});
        if (width < 768) await page.locator('#mobileMoreBtn').click();
        await page.locator('#automationNavBtn').click();
        await expect(page.locator('#automationNativeView')).toBeVisible();
        await expect(page.locator('#newRunbook')).toBeVisible();
        for (const theme of themes) {
            await page.evaluate(value => { document.body.dataset.theme = value; }, theme);
            for (const tab of ['library', 'runbooks', 'schedules', 'runs']) {
                await page.locator(`[data-auto-tab="${tab}"]`).click();
                await expect(page.locator(`#auto-${tab}`)).toBeVisible();
                const fits = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
                expect(fits, `${theme}: ${tab}`).toBe(true);
                await expect(page.locator(`[data-auto-tab="${tab}"]`)).toHaveAttribute('aria-current', 'page');
            }
        }
        await page.locator('[data-auto-tab="runbooks"]').click();
        await page.locator('.automation-main').evaluate(element => { element.scrollTop = 0; });
        await page.screenshot({path: testInfo.outputPath(`automation-${width}.png`), animations: 'disabled'});
        await page.goto('/credentials');
        await expect(page).toHaveURL(/#passwords/);
        await expect(page.locator('#credentialManagementView')).toBeVisible();
    });
}
