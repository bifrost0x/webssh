const {test,expect}=require('playwright/test');
const {login}=require('./helpers');

test('failed landing preference saves recover and successful changes survive login',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 for(const width of [390,3440]){
  await page.setViewportSize({width,height:850});await page.goto('/settings#preferences');
  const select=page.locator('#settingsStartPage');const before=await select.inputValue();const next=before==='overview'?'workspaces':'overview';
  await page.route('**/api/account/preferences',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'Temporarily unavailable'})}));
  await select.selectOption(next);await expect(select).toBeEnabled();await expect(select).toHaveValue(before);await expect(page.locator('#settingsPreferenceStatus')).toContainText('Temporarily unavailable');
  await page.unroute('**/api/account/preferences');await select.selectOption(next);await expect(select).toHaveAttribute('data-saved',next);
  await page.context().clearCookies();await login(page,'e2e_admin',{workspace:false});await expect(page.locator('body')).toHaveAttribute('data-primary-workspace',next);
 }
});

test('wide and narrow arrangements survive workspace landing and independent reset',async({page},info)=>{
 await page.setViewportSize({width:3440,height:1000});await login(page,'e2e_admin',{workspace:false});
 const pane=page.locator('#overviewRouteMap'),target=pane.locator('[data-map-node="direct:hosts"]');
 const hostCount=await page.evaluate(()=>ProfileManager.profiles.length);expect(hostCount).toBeGreaterThanOrEqual(20);
 const open=()=>page.locator('#overviewOpenMap').click();
 const move=async()=>{await target.getByRole('button',{name:'Move Direct connections',exact:true}).focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowDown');};
 await open();await move();const wide=await target.getAttribute('style');
 await page.setViewportSize({width:390,height:800});await expect(target).toHaveCSS('transform','none');await move();await move();const narrow=await target.getAttribute('style');expect(narrow).not.toBe(wide);
 await page.keyboard.press('Escape');await page.goto('/settings#preferences');await page.locator('#settingsStartPage').selectOption('workspaces');await expect(page.locator('#settingsStartPage')).toHaveAttribute('data-saved','workspaces');
 await page.goto('/');await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','workspaces');
 await page.locator('#mobileMoreBtn').click();await page.locator('#overviewNavBtn').click();await open();await expect(target).toHaveAttribute('style',narrow);
 await page.setViewportSize({width:3440,height:1000});await expect(target).toHaveAttribute('style',wide);await pane.getByRole('button',{name:'Reset arrangement',exact:true}).click();await expect(target).toHaveCSS('transform','none');
 await page.setViewportSize({width:390,height:800});await expect(target).toHaveAttribute('style',narrow);await page.screenshot({path:info.outputPath('narrow-arrangement.png')});
 await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);await page.locator('#mobileMoreBtn').click();await page.locator('#overviewNavBtn').click();await open();await expect(target).toHaveAttribute('style',narrow);expect(await page.evaluate(()=>ProfileManager.profiles.length)).toBe(hostCount);
 await page.keyboard.press('Escape');await page.goto('/settings#preferences');await page.locator('#settingsStartPage').selectOption('overview');await expect(page.locator('#settingsStartPage')).toHaveAttribute('data-saved','overview');
});
