const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.use({deviceScaleFactor: 1});
test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('theme switching keeps the welcome heading clear of the status and command bar', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace: false});
    const themes = ['glass', 'noir', 'solar', 'paper', 'arctic-ice', 'rose-gold', 'obsidian'];
    for (const width of [2240, 1280, 1024, 390]) {
        await page.setViewportSize({width, height: 900});
        for (const theme of themes) {
            await page.evaluate(value => {document.body.dataset.theme = value;}, theme);
            await expect(page.locator('.od-hero')).toBeVisible();
            const geometry = await page.evaluate(() => {
                const rect = selector => {
                    const box = document.querySelector(selector).getBoundingClientRect();
                    return {left: box.left, right: box.right, top: box.top, bottom: box.bottom};
                };
                return {heading: rect('#overviewTitle'), hero: rect('.od-hero'), others: [rect('#overviewStatus'), rect('.od-command')],
                    contained: document.documentElement.scrollWidth <= innerWidth};
            });
            const {heading, hero, others} = geometry;
            for (const other of others) {
                expect(heading.left >= other.right - 1 || heading.right <= other.left + 1
                    || heading.top >= other.bottom - 1 || heading.bottom <= other.top + 1,
                `${theme} at ${width}px overlaps the hero controls`).toBe(true);
            }
            expect(heading.left >= hero.left && heading.right <= hero.right, `${theme} at ${width}px leaves the hero`).toBe(true);
            expect(geometry.contained, `${theme} at ${width}px overflows`).toBe(true);
            if (width === 2240 || (width === 390 && theme === 'noir')) {
                await page.screenshot({path: testInfo.outputPath(`${theme}-${width}.png`), animations: 'disabled'});
            }
        }
    }
});
