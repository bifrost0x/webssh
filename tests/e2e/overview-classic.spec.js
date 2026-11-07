const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('account can switch classic overview and dashboard without losing layout',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#connectionOverview[data-overview-workspace]')).toBeVisible();
 const navDirection=await page.locator('.global-navigation').evaluate(e=>getComputedStyle(e).flexDirection);
 const theme=await page.locator('body').getAttribute('data-theme');
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('classic');
 await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','classic');
 await page.goto('/');await page.waitForFunction(()=>ProfileManager.profilesLoaded);await installSshConnectTrap(page);
 await expect(page.locator('#overviewQuickConnect')).toBeVisible();await expect(page.locator('#connectionOverview[data-overview-workspace]')).toHaveCount(0);await expect(page.locator('#overviewSearch')).toHaveCount(0);
 expect(await page.locator('.global-navigation').evaluate(e=>getComputedStyle(e).flexDirection)).toBe(navDirection);
 await expect(page.locator('#overviewHostCount')).not.toHaveText('—');
 await page.locator('#overviewGraphBtn').click();await expect(page.locator('#overviewGraphBtn')).toHaveAttribute('aria-pressed','true');
 await page.locator('#overviewListBtn').click();
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});
  for(const mode of ['Graph','List']){
   await page.locator('#overview'+mode+'Btn').click();
   await page.locator('#overviewHostSearch').fill('Ops first');
   await expect(page.locator('#overviewHosts')).toContainText('Ops first');
   await expect(page.locator('#overviewHosts')).not.toContainText('Password review');
   await page.locator('#overviewHostSearch').fill('');
   await page.locator('#overviewGroupFilter').selectOption({label:'Operations'});
   await expect(page.locator('#overviewHosts')).toContainText('Ops first');
   await expect(page.locator('#overviewHosts')).not.toContainText('Password review');
   await page.locator('#overviewGroupFilter').selectOption('');
   expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
   await page.screenshot({path:info.outputPath(`classic-${mode}-${width}.png`),animations:'disabled'});
  }
 }
 expect(await sshAttempts(page)).toEqual([]);
 await page.goto('/settings#preferences');await expect(page.locator('#settingsOverviewLayout')).toHaveValue('classic');await page.locator('#settingsOverviewLayout').selectOption('dashboard');await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','dashboard');
 await page.goto('/');await expect(page.locator('#connectionOverview[data-overview-workspace]')).toBeVisible();await expect(page.locator('#overviewSearch')).toBeVisible();await expect(page.locator('#overviewQuickConnect')).toHaveCount(0);await expect(page.locator('body')).toHaveAttribute('data-theme',theme);
 expect(await page.locator('.global-navigation').evaluate(e=>getComputedStyle(e).flexDirection)).toBe(navDirection);expect(errors).toEqual([]);
});
