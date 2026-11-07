const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('dragging a pane down changes order and resizing keeps the grid stable',async({page},info)=>{
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[{id:'grid-run',name:'Inventory',created_at:new Date().toISOString(),status:'succeeded',targets:[]}]}}));
 await page.setViewportSize({width:1440,height:900});await login(page,'e2e_admin',{workspace:false});
 const map=page.locator('[data-module=infrastructure]'),runs=page.locator('[data-module=routes]');
 const before=await map.boundingBox();
 await page.locator('#overviewCustomize').click();
 expect.soft(Math.abs((await map.boundingBox()).width-before.width)).toBeLessThan(2);
 await map.locator('.overview-module-handle').dragTo(runs.locator('.overview-module-handle'));
 await expect(page.locator('.overview-dashboard-module').nth(1)).toHaveAttribute('data-module','routes');
 await expect(page.locator('.overview-dashboard-module').nth(2)).toHaveAttribute('data-module','infrastructure');
 await map.locator('.overview-module-handle').dragTo(runs.locator('.overview-module-handle'));
 await expect(page.locator('.overview-dashboard-module').nth(1)).toHaveAttribute('data-module','infrastructure');
 await map.locator('.overview-module-handle').dragTo(runs.locator('.overview-module-handle'));
 await map.getByLabel('Infrastructure width').selectOption('full');
 await page.locator('#overviewCustomize').click();
 await page.reload();await expect(map).toHaveAttribute('data-size','full');
 await expect(page.locator('.overview-dashboard-module').nth(1)).toHaveAttribute('data-module','routes');
 await page.locator('#overviewCustomize').click();
 await page.locator('[data-module=inventory]').getByRole('checkbox',{name:'Show',exact:true}).uncheck();
 await page.locator('#overviewCustomize').click();
 const gridTop=await page.locator('.overview-dashboard-grid').evaluate(e=>e.getBoundingClientRect().top);
 expect(Math.abs((await runs.boundingBox()).y-gridTop)).toBeLessThan(2);
 for(const width of [390,768,1440,3440]){
  await page.setViewportSize({width,height:900});
  expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
  await page.screenshot({path:info.outputPath('grid-'+width+'.png'),animations:'disabled'});
 }
});
