const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
test('workspace retains draft, searches and targets across mobile views and tabs', async ({page}) => {
    await page.setViewportSize({width:360,height:800});
    await login(page, 'e2e_admin', {workspace:false});
    await page.route('**/api/automation/state', route => route.fulfill({json:{runbooks:[],profiles:Array.from({length:50},(_,i)=>({id:`host${i}`,name:`Host ${i}`,host:`host${i}.invalid`,username:'operator',supported:true,auth_type:'password'})),enabled:true}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab=library]').click();
    await page.locator('#runbookSearch').fill('Keep filter');
    await page.locator('[data-auto-tab=runbooks]').click();
    await page.locator('#runbookName').fill('Keep this draft');
    await page.locator('#addStep').click();
    await expect(page.locator('#automationStepDetail textarea')).toBeVisible();
    await page.locator('[data-workspace-view="targets"]').click();
    await page.locator('#targetSearch').fill('Host 42');
    await page.locator('#target-host42').check();
    await page.locator('[data-auto-tab="runs"]').click();
    await page.locator('[data-auto-tab="runbooks"]').click();
    await expect(page.locator('#targetSearch')).toHaveValue('Host 42');
    await expect(page.locator('#target-host42')).toBeChecked();
    await page.locator('[data-workspace-view="editor"]').click();
    await expect(page.locator('#runbookName')).toHaveValue('Keep this draft');
    await expect(page.locator('#runbookSearch')).toHaveValue('Keep filter');
    await expect(page.locator('.automation-step')).toHaveCount(2);
    await page.emulateMedia({reducedMotion:'reduce'});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('workspace sequence and target inventory fit narrow and wide themes', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace:false});
    await page.route('**/api/automation/state', route => route.fulfill({json:{runbooks:[{id:'inventory',name:'System inventory',steps:[{name:'Identity and uptime',command:'uname -a && uptime',timeout:30},{name:'Disk capacity',command:'df -hP',timeout:30},{name:'Memory',command:'free -m',timeout:30}]}],profiles:Array.from({length:50},(_,i)=>({id:`host${i}`,name:`Lab server ${i}`,host:`node-${i}.internal.example`,username:'operator',group:i<10?'Lab':'Infrastructure',supported:i!==4,auth_type:i%2?'key':'password'})),enabled:true}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab=runbooks]').click();
    for(const width of [360,768,1280,1920,3440]) {
        await page.setViewportSize({width,height:900});
        for(const theme of ['werkbank','paper','glass']) {
            await page.evaluate(theme=>{document.body.dataset.theme=theme;},theme);
            expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
            if(theme==='werkbank') await page.screenshot({path:testInfo.outputPath(`workspace-${width}.png`),animations:'disabled'});
        }
    }
    await page.setViewportSize({width:360,height:800});
    await page.locator('[data-workspace-view="targets"]').click();
    await expect(page.locator('#targetSearch')).toBeFocused();
    await expect(page.locator('#reviewWorkspace')).toBeVisible();
    await page.screenshot({path:testInfo.outputPath('targets-360.png'),animations:'disabled'});
    expect((await page.locator('#workspaceViews').boundingBox()).y + (await page.locator('#workspaceViews').boundingBox()).height).toBeLessThanOrEqual(240);
    await page.setViewportSize({width:360,height:560});
    await page.screenshot({path:testInfo.outputPath('targets-360x560.png'),animations:'disabled'});
    await page.evaluate(() => window.i18n.setLanguage('de'));
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    await page.screenshot({path:testInfo.outputPath('targets-de-360x560.png'),animations:'disabled'});
});
