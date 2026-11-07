const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

for (const width of [390, 1440]) {
    test(`dashboard and route map update every locale without losing arrangement at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width, height:900});
        const errors=[]; page.on('pageerror', error=>errors.push(error.message));
        await login(page, 'e2e_admin', {workspace:false});
        await page.evaluate(()=>{
            JumpHostManager.setJumpHosts([{id:'jump',name:'Gateway'}]);
            ProfileManager.setProfiles([{id:'direct',name:'Server One',group:'Lab'}, {id:'indirect',name:'Server Two',group:'Lab',jump_host_id:'jump'}]);
        });
        const translations={en:'SSH routes',de:'SSH-Verbindungen',vi:'Tuyến SSH',fr:'Routes SSH',es:'Rutas SSH',zh:'SSH 路由'};
        for (const [language, title] of Object.entries(translations)) {
            await page.evaluate(lang=>i18n.setLanguage(lang),language);
            await expect(page.locator('#overviewRouteMap h2')).toHaveText(title);
            await expect(page.locator('#overviewTitle')).toHaveText(await page.evaluate(()=>{
                const hour=new Date().getHours();
                return i18n.t('overview.ui.'+(hour<11?'good_morning':hour<18?'hello':'good_evening'))+', e2e_admin.';
            }));
            await page.locator('#overviewCustomize').click();
            const module=page.locator('[data-module=infrastructure]');
            await expect(module.locator('select').first()).toHaveAccessibleName(await page.evaluate(()=>i18n.t('overview.ui.name_width').replace('{name}',i18n.t('overview.ui.infrastructure'))));
            await expect(module.getByRole('button').filter({hasText:'↑'})).toHaveAccessibleName(await page.evaluate(()=>i18n.t('overview.ui.move_earlier')));
            await module.locator('select').first().selectOption('full');
            await page.locator('#overviewCustomize').click();
            await page.locator('#overviewRouteMap .ssh-map-heading button').click();
            await expect(page.locator('.ssh-map-dialog')).toBeVisible();
            await expect(page.locator('.ssh-map-reset')).toHaveText(await page.evaluate(()=>i18n.t('overview.ui.reset_arrangement')));
            await expect(page.locator('[data-map-node="direct:hosts"] .ssh-destination-heading strong')).toHaveText(await page.evaluate(()=>i18n.t('overview.ui.direct_connections')));
            await expect(page.locator('.ssh-route-target').first()).toHaveAccessibleName(await page.evaluate(()=>i18n.t('overview.ui.inspect')+'Server One'));
            await page.screenshot({path:testInfo.outputPath(`map-${language}.png`)});
            await page.keyboard.press('Escape');
            await expect(module).toHaveAttribute('data-size','full');
            expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
            await expect(page.locator('#connectionOverview')).not.toContainText('overview.ui.');
        }
        expect(errors).toEqual([]);
        await assertNoExternalRequests(page);
    });
}
