const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
for(const width of [360,768,1280,1920])test(`mixed access routes have one group and complete host identities at ${width}`,async({page})=>{
 await page.setViewportSize({width,height:900});await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{
  const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'a',name:'Bastion A'},{id:'b',name:'Bastion B'}]);
  ProfileManager.setProfiles(Array.from({length:24},(_,i)=>({...base,id:'mixed-'+i,name:`Node ${String(i).padStart(2,'0')}`,group:i<12?'Homelab':'Services',favorite:false,jump_host_id:i%3===0?null:i%3===1?'a':'b'})));
 });
 const hosts=page.locator('#overviewHostList .od-host');
 await expect(hosts).toHaveCount(24);
 await expect(page.locator('#odTopology')).toHaveAttribute('aria-label','24 hosts, 8 direct, 2 jump hosts, 0 with an open session');
 await expect(page.locator('#odTopology')).toContainText('Bastion A');await expect(page.locator('#odTopology')).toContainText('Bastion B');
 expect(await hosts.evaluateAll(cards=>cards.every(card=>card.querySelector('.od-host-name').textContent && card.querySelector('.od-host-destination').textContent))).toBe(true);
 await expect(page.getByRole('button',{name:'Connect Node 01',exact:true})).toBeVisible();
 expect(await page.locator('#overviewHostList').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
 expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
 await page.screenshot({path:test.info().outputPath(`mixed-${width}.png`),animations:'disabled'});
 await page.locator('#overviewSearch').fill('Homelab');
 await expect(hosts).toHaveCount(12);
 await page.locator('#overviewSearch').fill('Bastion B');
 await expect(hosts).toHaveCount(8);await expect(page.locator('#overviewHostList [data-host-id="mixed-2"]')).toBeVisible();
 await page.locator('#overviewSearch').fill('Node 02');
 await expect(hosts).toHaveCount(1);await expect(hosts.first()).toHaveAttribute('data-host-id','mixed-2');
 expect(await sshAttempts(page)).toEqual([]);
});
