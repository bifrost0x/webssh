const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
async function seed(page) {
 await login(page,'e2e_admin',{workspace:false});
 await installSshConnectTrap(page);
 await page.evaluate(()=>{
  const base=ProfileManager.profiles.find(p=>p.id==='password-review');
  JumpHostManager.setJumpHosts([{id:'scale-jump',name:'Bastion'}]);
  ProfileManager.setProfiles(Array.from({length:240},(_,i)=>({...base,id:`scale-${i}`,name:`Node ${String(i).padStart(3,'0')}`,host:`node-${i}.example`,favorite:false,group:`Group ${String(Math.floor(i/40)).padStart(2,'0')}`,jump_host_id:i%2?'scale-jump':null})));
 });
 await expect(page.locator('#overviewHostTotal')).toHaveText('240');
}
for(const width of [360,768,1280]) {
 test(`mixed routes and searches keep consistent scope at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:800});await seed(page);
  const rows=page.locator('#overviewHostList .od-host');
  await page.locator('#overviewSearch').fill('Group 00');
  // Searching a group must include both direct and jump-host routes.
  await expect(rows).toHaveCount(40);
  await expect(page.locator('#overviewHostTotal')).toHaveText('40 / 240');
  await expect(page.locator('#overviewHostList [data-host-id="scale-0"]')).toBeVisible();
  await expect(page.locator('#overviewHostList [data-host-id="scale-1"]')).toContainText('Bastion');
  await page.locator('#overviewSearch').fill('Bastion');
  await expect(rows).toHaveCount(120);
  await page.locator('#overviewSearch').fill('does-not-exist');
  await expect(rows).toHaveCount(0);
  await expect(page.locator('#overviewHostsNoMatch')).toBeVisible();
  await page.locator('#overviewSearch').fill('');
  await expect(rows).toHaveCount(240);
  await page.locator('#overviewSearch').fill('Node 239');
  const last=page.locator('#overviewHostList [data-host-id="scale-239"] .od-connect');
  await expect(last).toBeVisible();
  await last.focus();
  await expect(last).toBeInViewport();
  await page.screenshot({path:test.info().outputPath(`scale-${width}.png`),animations:'disabled'});
  const overflow=await page.locator('#connectionOverview').evaluate(el=>el.scrollWidth>el.clientWidth+1);
  expect(overflow).toBe(false);
  expect(await sshAttempts(page)).toEqual([]);
 });
}

test('all matching hosts remain reachable in the list and after resize',async({page})=>{
 await page.setViewportSize({width:1280,height:720});await seed(page);
 await page.locator('#overviewSearch').fill('Node');
 const rows=page.locator('#overviewHostList .od-host');
 await expect(rows).toHaveCount(240);
 const ids=await rows.evaluateAll(nodes=>nodes.map(n=>n.dataset.hostId));
 expect(new Set(ids).size).toBe(240);
 for(let group=0;group<6;group++) {
  await page.locator('#overviewSearch').fill('Group '+String(group).padStart(2,'0'));
  await expect(rows).toHaveCount(40);
  const last=rows.last().locator('.od-connect');
  await expect(rows.last()).toHaveAttribute('data-host-id',`scale-${group*40+39}`);
  // Keyboard focus scrolls the current card into view, including after a status refresh.
  await last.focus();
  await expect(last).toBeInViewport();
  await expect(last).toBeFocused();
 }
 for(const width of [360,768,1024,1280,1920]){
  await page.setViewportSize({width,height:720});
  await expect(rows).toHaveCount(40);
  await expect(rows.last()).toHaveAttribute('data-host-id','scale-239');
  expect(await page.locator('#connectionOverview').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 }
 expect(await sshAttempts(page)).toEqual([]);
});
