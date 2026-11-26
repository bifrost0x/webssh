const {test,expect}=require('playwright/test');
const {login,openWorkspace,installSshConnectTrap,sshAttempts}=require('./helpers');
// Switching to classic is per account on a shared server; never leave it behind.
test.afterEach(async({page})=>{const token=await page.locator('meta[name="csrf-token"]').getAttribute('content',{timeout:1000}).catch(()=>null);if(token)await page.request.post('/api/account/preferences',{data:{overview_layout:'dashboard'},headers:{'X-CSRFToken':token}}).catch(()=>{});});
test('account can switch classic overview and dashboard without losing layout',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#connectionOverview[data-overview-workspace]')).toBeVisible();
 const navDirection=await page.locator('.global-navigation').evaluate(e=>getComputedStyle(e).flexDirection);
 const theme=await page.locator('body').getAttribute('data-theme');
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('classic');
 await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','classic');
 await page.goto('/');await page.waitForFunction(()=>ProfileManager.profilesLoaded);await installSshConnectTrap(page);
 await expect(page.locator('#overviewQuickConnect')).toBeVisible();await expect(page.locator('#connectionOverview[data-overview-workspace]')).toHaveCount(0);await expect(page.locator('#overviewSearch')).toHaveCount(0);await expect(page.locator('.shell-grouping')).toHaveCount(0);
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
test('classic host rows show platform, virtualization, role and up to three service logos',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('classic');
 await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','classic');
 await page.goto('/');await page.waitForFunction(()=>ProfileManager.profilesLoaded);await installSshConnectTrap(page);
 const base={host:'x.example.invalid',port:22,username:'demo',auth_type:'password',group:'Lab'};
 await page.evaluate(items=>ProfileManager.setProfiles(items),[
  {...base,id:'pve',name:'pve-one',detected_platform:'proxmox',detected_virt:'bare-metal',detected_services:['docker','grafana','prometheus','nginx','redis']},
  {...base,id:'plain',name:'plain'},
  {...base,id:'long',name:'a-rather-long-host-name-for-a-narrow-row-that-keeps-going-on',detected_platform:'debian',detected_services:['docker','grafana','prometheus']},
 ]);
 const row=id=>page.locator(`#overviewHosts .overview-row[data-host-id="${id}"]`);
 await expect(row('pve')).toBeVisible();
 await expect(row('pve').locator('.host-platform-icon')).toHaveAttribute('data-platform','proxmox');
 await expect(row('pve').locator('.overview-row-virt')).toHaveText('Bare Metal');
 await expect(row('pve').locator('.overview-role')).toContainText('Hypervisor');
 await expect(row('pve').locator('.shell-host-service')).toHaveCount(3);
 await page.setViewportSize({width:360,height:800});
 const title=row('pve').locator('.overview-row-title');
 await expect(title).toHaveText('pve-one');
 expect(await title.evaluate(e=>e.scrollWidth<=e.clientWidth)).toBe(true);
 const logos=id=>row(id).locator('.shell-host-service:visible').count();
 const nameWhole=id=>row(id).locator('.overview-row-title').evaluate(e=>e.scrollWidth<=e.clientWidth);
 // Classic rows wrap the name instead of cutting it, so the logos keep their place at any width.
 const inside=id=>row(id).evaluate(e=>{const box=e.getBoundingClientRect();
  return e.scrollWidth<=e.clientWidth&&[...e.querySelectorAll('.shell-host-service')].every(tile=>{const r=tile.getBoundingClientRect();return r.left>=box.left&&r.right<=box.right;});});
 for(const width of [1440,360]){
  await page.setViewportSize({width,height:900});
  await expect(row('long').locator('.overview-row-title')).toHaveText('a-rather-long-host-name-for-a-narrow-row-that-keeps-going-on');
  await expect.poll(()=>logos('long'),{message:`${width}px`}).toBe(3);
  expect(await nameWhole('long'),`${width}px name`).toBe(true);
  expect(await inside('long'),`${width}px row`).toBe(true);
 }
 await page.setViewportSize({width:1440,height:900});
 await expect(row('pve').locator('.overview-row-title')).toHaveText('pve-one');
 await expect(row('plain').locator('.overview-role')).toContainText('Server');
 await expect(row('plain').locator('.overview-row-virt')).toHaveCount(0);
 await expect(row('plain').locator('.shell-host-service')).toHaveCount(0);
 expect(await sshAttempts(page)).toEqual([]);
});
test('classic rail rows show the platform icon without a role tint',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('classic');
 await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','classic');
 await page.goto('/');await page.waitForFunction(()=>ProfileManager.profilesLoaded);await installSshConnectTrap(page);
 const base={host:'x.example.invalid',port:22,username:'demo',auth_type:'password',group:'Lab'};
 await page.evaluate(items=>{ProfileManager.setProfiles(items);SessionManager.createSession({session_id:'rail-test',host:'fixture.example.invalid',username:'demo',port:22});},[
  {...base,id:'pve',name:'pve-one',detected_platform:'proxmox',detected_services:['docker']},
 ]);
 await page.setViewportSize({width:1440,height:900});
 await openWorkspace(page);
 if(await page.locator('#toggleHostRail').getAttribute('aria-expanded')!=='true')await page.evaluate(()=>document.getElementById('toggleHostRail').click());
 const item=page.locator('#shellGroups .shell-host').first();
 await expect(item).toBeVisible();
 await expect(item.locator('.host-platform-icon')).toHaveAttribute('data-platform','proxmox');
 await expect(item).not.toHaveAttribute('data-role',/.+/);
 expect(await sshAttempts(page)).toEqual([]);
});
