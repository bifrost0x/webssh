const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test('management surfaces align with the header and give each automation stage the shared working width', async ({page}, info) => {
    await login(page, 'e2e_admin', {workspace:false});
    for (const width of [1440,3440]) {
        await page.setViewportSize({width,height:1000});
        const header = await page.locator('.header-content').boundingBox();
        for (const [name, button, surface] of [
            ['hosts','#manageProfilesBtn','.primary-workspace-view-hosts'],
            ['commands','#commandLibraryBtn','.primary-workspace-view-commands'],
            ['automation','#automationNavBtn','#automationNativeView .automation-main'],
        ]) {
            await page.locator(button).click();
            const panel = page.locator(surface).filter({visible:true});
            const box = await panel.boundingBox();
            expect(Math.abs(box.x-header.x), name).toBeLessThanOrEqual(1);
            expect(Math.abs(box.width-header.width), name).toBeLessThanOrEqual(1);
            expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name).toBe(true);
            await page.screenshot({path:info.outputPath(name+'-'+width+'.png'),animations:'disabled'});
        }
        await page.locator('[data-auto-tab=runbooks]').click();
        for (const [selector,panel] of [['[data-workspace-view=editor]','.automation-editor'],['[data-workspace-view=targets]','.automation-target-section'],['#openSchedule','#automationScheduleInspector']]) {
            await page.locator(selector).click();
            expect((await page.locator(panel).boundingBox()).width).toBeGreaterThan(header.width * .85);
        }
    }
    await assertNoExternalRequests(page);
});
