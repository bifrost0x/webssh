const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
for (const width of [390, 768, 1024, 1440]) {
    test(`host cards, group labels and workspace controls fit at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await page.evaluate(() => {
            const profile = window.ProfileManager.profiles[0];
            window.ProfileManager.setProfiles([
                {...profile, id:'long-a', name:'long-host-'.repeat(30), group:'long-group-'.repeat(30)},
                {...profile, id:'long-b', name:'second-host', group:'other'},
            ]);
        });
        for (const graph of [false, true]) {
            await page.locator(graph ? '#overviewGraphBtn' : '#overviewListBtn').click();
            const escaped = await page.locator('#overviewHosts').evaluate(container => {
                const bounds = container.getBoundingClientRect();
                return [...container.querySelectorAll('.overview-host-group, .overview-row, .overview-group-heading')].filter(element => {
                    const rect = element.getBoundingClientRect();
                    return rect.right > bounds.right + 1 || rect.left < bounds.left - 1;
                }).map(element => element.className);
            });
            expect(escaped).toEqual([]);
        }
        await page.screenshot({path:test.info().outputPath(`overview-${width}.png`)});
        await (width < 768 ? page.locator('[data-mobile-view="workspaces"]') : page.locator('#workspaceNavBtn')).click();
        if (width >= 768) await page.locator('[data-layout="windows"]').click();
        const escaped = await page.locator('.session-tabs-row').evaluate(row => {
            const r = row.getBoundingClientRect();
            return [...row.querySelectorAll('button')].filter(button => {
                const b = button.getBoundingClientRect();
                return b.width > 0 && (b.left < r.left - 1 || b.right > r.right + 1);
            }).map(button => button.id || button.className);
        });
        expect(escaped).toEqual([]);
        await page.screenshot({path:test.info().outputPath(`workspace-${width}.png`)});
    });
}
