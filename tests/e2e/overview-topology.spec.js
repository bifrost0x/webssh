const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('compact inventory and route topology support large inventories, fullscreen and all themes',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'bastion',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:120},(_,i)=>({...base,id:'topo-'+i,name:'Server '+String(i).padStart(3,'0'),group:'Group '+Math.floor(i/20),favorite:false,jump_host_id:i%3?'bastion':null})));});
 const map=page.locator('#overviewRouteMap');
 await expect(page.locator('.overview-compact-row')).toHaveCount(120);
 await expect(page.locator('.overview-list-group')).toHaveCount(6);
 await expect(page.locator('#overviewHosts .overview-map')).toHaveCount(0);
 await expect(map.locator('.ssh-route-source')).toHaveCount(1);
 await expect(map.locator('svg path')).toHaveCount(3);
 await expect(map.locator('.ssh-route-host')).toHaveCount(0);await expect(map.locator('.ssh-route-summary')).toHaveCount(2);
 await page.locator('#overviewHostSearch').fill('Server 119');await expect(page.locator('.overview-compact-row')).toHaveCount(1);
 await page.locator('[data-host-id="topo-119"]').click();await expect(page.locator('.overview-path-stops')).toContainText('Gateway');await page.locator('.overview-access-heading button').click();
 await page.locator('#overviewHostSearch').fill('');
 await map.getByRole('button',{name:'Expand map',exact:true}).click();await expect(page.locator('dialog.ssh-map-dialog')).toBeVisible();
 await map.getByRole('searchbox').fill('Server 119');await expect(map.locator('.ssh-route-host')).toHaveCount(1);
 await map.getByRole('button',{name:'Inspect Server 119',exact:true}).click();await expect(page.locator('dialog.ssh-map-dialog')).not.toBeVisible();await expect(page.locator('.overview-path-stops')).toContainText('Server 119');
 await page.locator('.overview-access-heading button').click();await map.getByRole('searchbox').fill('');
 await map.getByRole('button',{name:'Expand map',exact:true}).click();await page.keyboard.press('Escape');await expect(page.locator('dialog.ssh-map-dialog')).not.toBeVisible();
 for(const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']){
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  for(const width of [390,1440,3440]){await page.setViewportSize({width,height:900});expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);}
 }
 await page.setViewportSize({width:1440,height:1000});await page.locator('#overviewHostSearch').scrollIntoViewIfNeeded();await page.screenshot({path:info.outputPath('topology-1440.png')});
 await map.getByRole('button',{name:'Expand map',exact:true}).click();await map.getByRole('button',{name:'Fit map',exact:true}).click();await page.screenshot({path:info.outputPath('topology-expanded.png')});
 await page.setViewportSize({width:390,height:800});await expect(map.getByRole('button',{name:'Close map',exact:true})).toBeInViewport();await expect(map.locator('.ssh-map-server')).toBeInViewport();await page.screenshot({path:info.outputPath('topology-mobile.png')});
 await map.getByRole('button',{name:'Close map',exact:true}).click();
 expect(await sshAttempts(page)).toEqual([]);expect(errors).toEqual([]);
});
