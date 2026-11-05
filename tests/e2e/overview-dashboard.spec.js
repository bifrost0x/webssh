const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('dashboard adapts height and persists snapped module layout',async({page},info)=>{
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[{id:'dashboard-run',name:'Inventory',created_at:new Date().toISOString(),status:'succeeded',targets:[]}]}}));
 await page.setViewportSize({width:1440,height:900});await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#overviewTitle')).toContainText('e2e_admin');await expect(page.locator('#overviewGreetingLine')).not.toBeEmpty();
 await expect(page.locator('#overviewQuickConnect')).toHaveCount(0);await expect(page.locator('#overviewWorkSummary')).toHaveCount(0);
 const map=page.locator('[data-module=infrastructure]');const runs=page.locator('[data-module=runs]');
 await expect(page.locator('#overviewAnalytics')).toBeVisible();
 await expect(page.locator('[data-module=activity]')).toHaveCount(1);
 await expect(page.locator('.overview-dashboard-module')).toHaveCount(7);
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});
  expect((await page.locator('.ssh-route-viewport').boundingBox()).height).toBeLessThanOrEqual(400);
  expect((await page.locator('.overview-compact-list').boundingBox()).height).toBeLessThanOrEqual(400);
  expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
  if(width>=1440){
 const boxes=await page.locator('[data-module=infrastructure], [data-module=routes], [data-module=runs], [data-module=activity]').evaluateAll(es=>Object.fromEntries(es.map(e=>{const r=e.getBoundingClientRect();return [e.dataset.module,{top:r.top,bottom:r.bottom}];})));
 expect(Math.abs(boxes.infrastructure.top-boxes.routes.top)).toBeLessThan(2);
 expect(Math.abs(boxes.infrastructure.bottom-boxes.routes.bottom)).toBeLessThan(2);
 expect(Math.abs(boxes.activity.top-boxes.runs.top)).toBeLessThan(2);
 }
 await page.screenshot({path:info.outputPath(`dashboard-${width}.png`),animations:"disabled"});
 }
 await page.locator('#overviewCustomize').click();
 await map.getByLabel('Infrastructure width').selectOption('half');await map.getByLabel('List height').selectOption('compact');
 await runs.locator('.overview-module-handle').dragTo(map.locator('.overview-module-handle'));
 await expect(page.locator('.overview-dashboard-module').nth(1)).toHaveAttribute('data-module','runs');
 await page.locator('#overviewCustomize').click();await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);
 await expect(page.locator('.overview-dashboard-module').nth(1)).toHaveAttribute('data-module','runs');await expect(map).toHaveAttribute('data-size','half');await expect(map).toHaveAttribute('data-height','compact');
 const storedMap=await page.evaluate(()=>{const scope=document.querySelector('meta[name="background-scope"]').content;return localStorage.getItem(`webssh:overview-map:${scope}`);});
 await page.locator('#overviewResetDashboard').click();await expect(page.locator('.overview-dashboard-module').first()).toHaveAttribute('data-module','inventory');
 await expect(map).toHaveAttribute('data-size','half');await expect(map).toHaveAttribute('data-height','normal');
 await expect(page.locator('[data-module=news]')).toBeHidden();
 expect(await page.evaluate(()=>{const scope=document.querySelector('meta[name="background-scope"]').content;return localStorage.getItem(`webssh:overview-map:${scope}`);})).toBe(storedMap);
 await page.locator('#overviewUndoDashboard').click();await expect(map).toHaveAttribute('data-height','compact');
 await page.evaluate(()=>i18n.setLanguage('de'));await expect(page.locator('#overviewCustomize')).toHaveText('Dashboard anpassen');await expect(page.locator('#overviewTitle')).toHaveText(/(Hallo|Guten Morgen|Guten Abend), e2e_admin/);
});
