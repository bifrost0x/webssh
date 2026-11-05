const {test, expect}=require('playwright/test');
const {login, installSshConnectTrap, sshAttempts}=require('./helpers');
for(const width of [360,768,1280,1920,3440]) {
 test(`clear access map keeps 28 hosts reachable at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:900});
  await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
  await page.evaluate(()=>{
   const base=ProfileManager.profiles.find(p=>p.id==='password-review');
   JumpHostManager.setJumpHosts([{id:'map-jump',name:'Bastion'}]);
   ProfileManager.setProfiles(Array.from({length:28},(_,i)=>({...base,id:`map-${i}`,name:`Storage replica ${String(i).padStart(2,'0')} — Homelab`,group:`Group ${Math.floor(i/7)}`,favorite:false,jump_host_id:i%2?'map-jump':null})));
  });
  await expect(page.locator('#overviewHostCount')).toHaveText('28');
  await expect(page.locator('#overviewGroupFilter')).toHaveCSS('appearance','none');
  await expect(page.locator('.overview-list-group')).toHaveCount(4);
  await expect(page.locator('.overview-compact-row')).toHaveCount(28);
  await expect(page.locator('.overview-route-bundle[data-selected="true"]')).toHaveCount(0);
  const first=page.locator('.overview-compact-row [data-host-id]').first();
  await first.click();
  await expect(page.locator('.overview-access-inspector')).toBeVisible();
  await expect(page.locator('.overview-heading')).toBeVisible();
  expect(await page.locator('#overviewHosts').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  for(const theme of ['glass','werkbank','paper','arctic-ice']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await page.locator('#overviewHosts').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  await page.screenshot({path:test.info().outputPath(`map-${width}.png`),animations:'disabled'});
  await page.locator('.overview-access-heading button').click();
  await expect(first).toBeFocused();
  await page.locator('#overviewHostSearch').fill('Storage replica');
  const ids=new Set(await page.locator('.overview-compact-row [data-host-id]').evaluateAll(nodes=>nodes.map(n=>n.dataset.hostId)));
  expect(ids.size).toBe(28);
  await page.locator('#overviewHostSearch').fill('Storage replica 27');
  await page.locator('[data-host-id="map-27"]').click();
  await expect(page.locator('.overview-path-stops li')).toHaveCount(3);
  await expect(page.locator('.overview-path-stops')).toContainText('Bastion');
  expect(await sshAttempts(page)).toEqual([]);
 });
}
test('theme preferences survive save and reload without opting users into Werkbank',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/settings#preferences');
 for(const theme of ['glass','arctic-ice','werkbank','glass']){
  await page.locator('#settingsThemeSelect').selectOption(theme);
  await expect(page.locator('#settingsThemeSelect')).toBeEnabled();
  await page.reload();
  await expect(page.locator('#settingsThemeSelect')).toHaveValue(theme);
  await expect(page.locator('body')).toHaveAttribute('data-theme',theme);
 }
});
