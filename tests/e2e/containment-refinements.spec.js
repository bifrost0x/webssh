const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
for (const width of [390, 768, 1024, 1440]) {
    test(`host cards, group labels and workspace controls fit at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await page.evaluate(() => {
            const profile = window.ProfileManager.profiles[0];
            window.JumpHostManager.setJumpHosts([{id:'long-jump', name:'long-jump-'.repeat(30)}]);
            window.ProfileManager.setProfiles([
                {...profile, id:'long-a', name:'long-host-'.repeat(30), group:'long-group-'.repeat(30), jump_host_id:'long-jump'},
                {...profile, id:'long-b', name:'second-host', group:'other', jump_host_id:null},
            ]);
        });
        const escapedFrom = (selector, children) => page.locator(selector).evaluate((container, children) => {
            const bounds = container.getBoundingClientRect();
            return [...container.querySelectorAll(children)].filter(element => {
                if (!element.getClientRects().length) return false;
                const rect = element.getBoundingClientRect();
                return rect.right > bounds.right + 1 || rect.left < bounds.left - 1;
            }).map(element => element.className);
        }, children);
        for (const query of ['', 'long-group-'.repeat(30)]) {
            await page.locator('#overviewSearch').fill(query);
            await expect(page.locator('#overviewHostList .od-host')).toHaveCount(query ? 1 : 2);
            expect(await escapedFrom('#overviewHostList', '.od-host, .od-host-name, .od-host-destination, .od-state, .od-connect')).toEqual([]);
            expect(await escapedFrom('#odTopology', '.od-route-item, .od-topology-svg')).toEqual([]);
            expect(await page.locator('#connectionOverview').evaluate(e => e.scrollWidth <= e.clientWidth + 1)).toBe(true);
        }
        await expect(page.locator('#overviewHostList [data-host-id="long-a"] .od-host-name')).toContainText('long-host-');
        await page.screenshot({path:test.info().outputPath(`overview-${width}.png`)});
        await (width < 768 ? page.locator('[data-mobile-view="workspaces"]') : page.locator('#workspaceNavBtn')).click();
        if (width >= 768) { await page.locator("#workspaceLayoutPicker > summary").click(); await page.locator('[data-layout="windows"]').click(); }
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
