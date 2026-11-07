const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
for(const width of [360,768,1280,1920])test(`mixed access routes have one group and complete host identities at ${width}`,async({page})=>{
 await page.setViewportSize({width,height:900});await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{
  const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'a',name:'Bastion A'},{id:'b',name:'Bastion B'}]);
  ProfileManager.setProfiles(Array.from({length:24},(_,i)=>({...base,id:'mixed-'+i,name:`Node ${String(i).padStart(2,'0')}`,group:i<12?'Homelab':'Services',favorite:false,jump_host_id:i%3===0?null:i%3===1?'a':'b'})));
 });
 await expect(page.locator('.overview-list-group')).toHaveCount(2);
 await expect(page.locator('.overview-list-group h3')).toHaveText(['Homelab12','Services12']);
 await expect(page.locator('.overview-compact-row')).toHaveCount(24);
 await page.locator('[data-host-id="mixed-1"]').click();
 await expect(page.locator('.overview-path-stops > li > strong')).toHaveText(['WebSSH server','Bastion A','Node 01']);
 await expect(page.locator('.overview-list-group')).toHaveCount(2);
 expect(await page.locator('#overviewHosts').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
 await page.screenshot({path:test.info().outputPath(`mixed-${width}.png`),animations:'disabled'});
 await page.locator('.overview-access-heading button').click();
 await page.locator('#overviewGroupFilter').selectOption('group:Homelab');
 await expect(page.locator('.overview-compact-row')).toHaveCount(12);
 await page.locator('#overviewHostSearch').fill('Node 02');
 await page.locator('[data-host-id="mixed-2"]').click();
 await expect(page.locator('.overview-path-stops')).toContainText('Bastion B');
 expect(await sshAttempts(page)).toEqual([]);
});
