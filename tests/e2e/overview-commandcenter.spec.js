const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts,assertNoExternalRequests}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));
test('commandcenter bounds large inventories and retains every host through group filtering and search',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'bastion',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:120},(_,i)=>({...base,id:'cc-'+i,name:`Lab node ${String(i).padStart(3,'0')}`,group:'Group '+Math.floor(i/20),favorite:false,jump_host_id:i%3?'bastion':null})));});
 await expect(page.locator('.overview-list-group')).toHaveCount(6);
 await expect(page.locator('.overview-compact-row')).toHaveCount(120);
 await expect(page.locator('#overviewHostCount')).toHaveText('120');
 await expect(page.locator('#overviewHosts > .overview-pagination')).toHaveCount(0);
 await page.locator('#overviewGroupFilter').selectOption('group:Group 0');
 await expect(page.locator('.overview-compact-row')).toHaveCount(20);
 expect(new Set(await page.locator('.overview-compact-row [data-host-id]').evaluateAll(es=>es.map(e=>e.dataset.hostId))).size).toBe(20);
 await page.locator('#overviewGroupFilter').selectOption('');
 await page.locator('#overviewHostSearch').fill('Lab node 119');
 await page.locator('[data-host-id="cc-119"]').click();
 await expect(page.locator('.overview-path-stops')).toContainText('Gateway');
 await expect(page.locator('.overview-path-stops')).toContainText('Lab node 119');
 expect(await sshAttempts(page)).toEqual([]);
 await page.locator('.overview-access-heading button').click();await page.locator('#overviewHostSearch').fill('');
 for(const width of [390,768,1440,3440]){
  await page.setViewportSize({width,height:1000});
  await expect(page.locator('#overviewTitle')).toBeVisible();
  expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
  await page.screenshot({path:info.outputPath('commandcenter-'+width+'.png'),animations:'disabled'});
 }
 await expect(page.locator('#overviewMotion')).toHaveCount(0);
 expect(errors).toEqual([]);
});
test('commandcenter keeps readable layouts across all existing themes',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 for(const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']){
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  for(const width of [390,1440,3440]){await page.setViewportSize({width,height:1000});expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);await expect(page.locator('#overviewHostSearch')).toBeVisible();await expect(page.locator('#overviewCreateHost')).toBeVisible();}
 }
 await page.emulateMedia({reducedMotion:'reduce'});expect(await page.locator('.overview-access-inspector').count()).toBe(0);
});

test('commandcenter animates only matching connected sessions and respects motion controls',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{
  const p=ProfileManager.profiles[0];
  ProfileManager.setProfiles([{...p,id:'live-host',name:'Active host',jump_host_id:null}]);
  window.commandcenterSession={id:'local-test',connected:true,profileId:'live-host',host:p.host,port:p.port||22,username:p.username,jumpHostId:null};
  SessionManager.getAllSessions=()=>[window.commandcenterSession];
  window.dispatchEvent(new Event('session-workspace-change'));
 });
 const path=page.locator('.overview-session-indicator');
 await expect(page.locator('.overview-compact-row[data-live="true"]')).toHaveCount(1);
 await expect(path).toHaveCount(1);
 await expect(path).toHaveCSS('animation-name','overview-session-pulse');
 await page.emulateMedia({reducedMotion:'reduce'});await expect(path).toHaveCSS('animation-name','none');
 await page.emulateMedia({reducedMotion:'no-preference'});await expect(path).toHaveCSS('animation-name','overview-session-pulse');
 await page.emulateMedia({reducedMotion:'reduce'});await expect(path).toHaveCSS('animation-name','none');
 await page.evaluate(()=>{window.commandcenterSession.host='changed.invalid';window.dispatchEvent(new Event('session-workspace-change'));});
 await expect(path).toHaveCount(0);
 await expect(page.locator('.overview-compact-row[data-live="true"]')).toHaveCount(0);
});
