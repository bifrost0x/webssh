const {test,expect}=require('playwright/test');
const themes=['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian'];
test('navigation order, no redundant password shortcuts, resource access retained',async({page})=>{
 await page.goto('/login');await page.locator('#username').fill('e2e_admin');await page.locator('#password').fill('browser-password');await page.locator('form button[type=submit]').click();await page.waitForURL(/\/$/);
 await page.waitForFunction(()=>window.ProfileManager?.profilesLoaded&&window.JumpHostManager?.loaded);
 const ids=['overviewNavBtn','workspaceNavBtn','fileTransferBtn','automationNavBtn','commandLibraryBtn','manageProfilesBtn'];
 expect(await page.locator('#globalNavigation > .global-nav-item').evaluateAll(nodes=>nodes.map(n=>n.id))).toEqual(ids);
 for(const width of [360,1280,3440]){
  await page.setViewportSize({width,height:900});
  if(width===360) await page.locator('#mobileMoreBtn').click();
  for(const theme of themes){
   await page.evaluate(value=>document.body.dataset.theme=value,theme);
   await expect(page.locator('#automationNavBtn')).toBeVisible();
   expect(await page.locator('#automationNavBtn').evaluate(n=>getComputedStyle(n).textDecorationLine)).toBe('none');
   expect(await page.locator('#globalNavigation > .global-nav-item').evaluateAll(nodes=>nodes.slice().sort((a,b)=>Number(getComputedStyle(a).order)-Number(getComputedStyle(b).order)).map(n=>n.id))).toEqual(ids);
  }
 }
 await expect(page.locator('#accountDropdownHeader [data-connection-asset=passwords]')).toHaveCount(0);
 await page.locator('#manageProfilesBtn').click();await page.locator('#profileManagementModal [data-connection-asset=passwords]').click();await expect(page.locator('#credentialManagementView')).toBeVisible();
 await page.goto('/settings');await expect(page.locator('[data-settings-link=credentials]')).toHaveCount(0);
 await page.goto('/credentials');await expect(page.locator('#credentialManagementView')).toBeVisible();
});
