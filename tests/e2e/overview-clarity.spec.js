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
  const hosts=page.locator('#overviewHostList .od-host');
  await expect(page.locator('#overviewHostTotal')).toHaveText('28');
  await expect(hosts).toHaveCount(28);
  await expect(page.locator('#odTopology')).toHaveAttribute('aria-label','28 hosts, 14 direct, 1 jump hosts, 0 with an open session');
  await expect(page.locator('#overviewTitle')).toBeVisible();
  expect(await page.locator('#overviewHostList').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  for(const theme of ['glass','werkbank','paper','arctic-ice']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await page.locator('#overviewHostList').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
   expect(await page.locator('#connectionOverview').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  await page.screenshot({path:test.info().outputPath(`map-${width}.png`),animations:'disabled'});
  await page.locator('#overviewSearch').fill('Storage replica');
  const ids=new Set(await page.locator('#overviewHostList .od-host').evaluateAll(nodes=>nodes.map(n=>n.dataset.hostId)));
  expect(ids.size).toBe(28);
  await page.locator('#overviewSearch').fill('Bastion');
  await expect(hosts).toHaveCount(14);await expect(page.locator('#overviewHostList [data-host-id="map-27"]')).toBeVisible();
  await page.locator('#overviewSearch').fill('Storage replica 27');
  await expect(hosts).toHaveCount(1);
  await page.locator('#overviewSearch').press('ArrowDown');
  await expect(page.getByRole('button',{name:'Connect Storage replica 27 — Homelab',exact:true})).toBeFocused();
  expect(await sshAttempts(page)).toEqual([]);
 });
}
test('theme preferences survive save and reload without opting users into Werkbank',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/settings#preferences');
 for(const theme of ['glass','arctic-ice','werkbank','glass']){
  const saved=page.waitForResponse(r=>r.url().endsWith('/api/account/preferences')&&r.request().method()==='POST');
  await page.locator('#settingsThemeSelect').selectOption(theme);
  expect((await saved).ok()).toBe(true);
  await expect(page.locator('#settingsThemeSelect')).toBeEnabled();
  // Drop the browser's copy so the reload proves the account setting was stored.
  await page.evaluate(()=>localStorage.removeItem('websshTheme'));
  await page.reload();
  await expect(page.locator('#settingsThemeSelect')).toHaveValue(theme);
  await expect(page.locator('body')).toHaveAttribute('data-theme',theme);
 }
});
