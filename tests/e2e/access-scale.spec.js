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
 await expect(page.locator('#overviewHostCount')).toHaveText('240');
}
for(const width of [360,768,1280]) {
 test(`mixed routes, searches and inspector keep consistent scope at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:800});await seed(page);
  await page.locator('#overviewGroupFilter').selectOption('group:Group 00');
  await expect(page.locator('#overviewHosts .overview-compact-row')).toHaveCount(40);
  await page.locator('#overviewHostSearch').fill('Node 0');
  // Searching the group must include both direct and jump-host routes.
  await expect(page.locator('#overviewHosts .overview-compact-row')).toHaveCount(40);
  await expect(page.locator('#overviewHosts .overview-list-group')).toHaveCount(1);
  await expect(page.locator('[data-host-id="scale-1"]')).toBeVisible();
  await page.locator('[data-host-id="scale-1"]').click();
  await expect(page.locator('.overview-path-stops')).toContainText('Bastion');
  await page.locator('#overviewHostSearch').fill('does-not-exist');
  await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
  await page.locator('#overviewHostSearch').fill('');
  await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
  await page.locator('#overviewGroupFilter').selectOption('group:Group 05');
  await expect(page.locator('#overviewHostCount')).toHaveText('40');
  await expect(page.locator('#overviewGroupFilter')).toHaveValue('group:Group 05');
  await page.locator('#overviewHostSearch').fill('Node 239');
  await expect(page.locator('[data-host-id="scale-239"]')).toBeVisible();
  await page.locator('[data-host-id="scale-239"]').click();
  await expect(page.locator('#overviewAccessTitle')).toHaveText('Node 239');
  await expect(page.locator('#overviewAccessTitle')).toBeInViewport();
  await page.screenshot({path:test.info().outputPath(`scale-${width}.png`),animations:'disabled'});
  const overflow=await page.locator('#overviewHosts').evaluate(el=>el.scrollWidth>el.clientWidth+1);
  expect(overflow).toBe(false);
  await page.locator('.overview-access-heading button').click();
  await expect(page.locator('[data-host-id="scale-239"]')).toBeFocused();
  expect(await sshAttempts(page)).toEqual([]);
 });
}

test('empty search clears selection rather than reopening an obsolete inspector',async({page})=>{
 await seed(page);
 await page.locator('[data-host-id]').first().click();
 await page.locator('#overviewHostSearch').fill('does-not-exist');
 await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
 await page.locator('#overviewHostSearch').fill('');
 await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
});

test('all matching hosts remain reachable in the list and after resize with details open',async({page})=>{
 await page.setViewportSize({width:1280,height:720});await seed(page);
 await page.locator('#overviewHostSearch').fill('Node');
 const rows=page.locator('#overviewHosts .overview-compact-row');
 await expect(rows).toHaveCount(240);
 const ids=await rows.locator('[data-host-id]').evaluateAll(nodes=>nodes.map(n=>n.dataset.hostId));
 expect(new Set(ids).size).toBe(240);
 for(let group=0;group<6;group++) {
  await page.locator('#overviewGroupFilter').selectOption('group:Group '+String(group).padStart(2,'0'));
  await expect(rows).toHaveCount(40);
  const last=rows.last().locator('[data-host-id]');
  await last.scrollIntoViewIfNeeded();await last.click();
  await expect(page.locator('#overviewAccessTitle')).toBeInViewport();
  await page.locator('.overview-access-heading button').click();
  await expect(last).toBeFocused();
 }
 await rows.last().locator('[data-host-id]').click();
 const title=await page.locator('#overviewAccessTitle').innerText();
 for(const width of [360,768,1024,1280,1920]){
  await page.setViewportSize({width,height:720});
  await expect(page.locator('#overviewAccessTitle')).toHaveText(title);
  expect(await page.locator('#overviewHosts').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 }
 await page.locator('#overviewGroupFilter').focus();
 await page.locator('#overviewGroupFilter').selectOption('group:Group 00');
 await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
 await expect(page.locator('#overviewGroupFilter')).toBeFocused();
 expect(await sshAttempts(page)).toEqual([]);
});

test('small-screen inspector keeps file and jump-host actions reachable and returns to the same search',async({page})=>{
 await page.setViewportSize({width:360,height:640});
 await login(page,'e2e_admin',{workspace:false});
 await installSshConnectTrap(page);
 await page.locator('#overviewHostSearch').fill('Password review');
 await page.locator('#overviewHosts [data-host-id]').first().click();
 await page.getByRole('button',{name:'Open files',exact:true}).click();
 await expect(page.locator('#fmQcProfile')).toHaveValue('password-review');
 await page.keyboard.press('Escape');
 await page.locator('#mobileMoreBtn').click();
 await page.locator('#overviewNavBtn').click();
 await expect(page.locator('#overviewHostSearch')).toHaveValue('Password review');
 await expect(page.locator('#overviewAccessTitle')).toHaveText('Password review');
 await expect(page.getByRole('button',{name:'Open files',exact:true})).toBeFocused();
 await page.getByRole('button',{name:'Manage jump hosts',exact:true}).click();
 await expect(page.locator('#jumpHostManagementModal')).toBeVisible();
 expect(await sshAttempts(page)).toEqual([]);
});
