const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
async function seedHosts(page){
 await page.evaluate(()=>{const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'bastion',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:120},(_,i)=>({...base,id:'topo-'+i,name:'Server '+String(i).padStart(3,'0'),group:'Group '+Math.floor(i/20),favorite:false,jump_host_id:i%3?'bastion':null})));});
}
test('compact inventory and route topology support large inventories and fullscreen',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await seedHosts(page);
 const map=page.locator('#overviewRouteMap'),hosts=page.locator('#overviewHostList .od-host'),dialog=page.locator('dialog.ssh-map-dialog');
 await expect(hosts).toHaveCount(120);
 await expect(page.locator('#odTopology')).toHaveAttribute('aria-label','120 hosts, 40 direct, 1 jump hosts, 0 with an open session');
 await page.locator('#overviewSearch').fill('Server 119');await expect(hosts).toHaveCount(1);
 await expect(page.getByRole('button',{name:'Connect Server 119',exact:true})).toBeVisible();
 await page.locator('#overviewSearch').fill('');await expect(hosts).toHaveCount(120);
 await page.locator('#overviewOpenMap').click();await expect(dialog).toBeVisible();
 await expect(map.locator('.ssh-route-source')).toHaveCount(1);
 await expect(map.locator('svg path')).toHaveCount(3);
 await map.getByRole('searchbox').fill('Server 119');await expect(map.locator('.ssh-route-host')).toHaveCount(1);
 await map.getByRole('button',{name:'Inspect Server 119',exact:true}).click();await expect(dialog).not.toBeVisible();
 await expect(page.locator('#overviewSearch')).toHaveValue('Server 119');await expect(hosts).toHaveCount(1);
 await expect(page.getByRole('button',{name:'Connect Server 119',exact:true})).toBeFocused();
 await page.locator('#overviewSearch').fill('');await expect(hosts).toHaveCount(120);
 await page.locator('#overviewOpenMap').click();await map.getByRole('searchbox').fill('');await page.keyboard.press('Escape');await expect(dialog).not.toBeVisible();
 await page.setViewportSize({width:1440,height:1000});await page.locator('#overviewSearch').scrollIntoViewIfNeeded();await page.screenshot({path:info.outputPath('topology-1440.png')});
 await page.locator('#overviewOpenMap').click();await map.getByRole('button',{name:'Fit map',exact:true}).click();await page.screenshot({path:info.outputPath('topology-expanded.png')});
 await page.setViewportSize({width:390,height:800});await expect(map.getByRole('button',{name:'Close map',exact:true})).toBeInViewport();await expect(map.locator('.ssh-map-server')).toBeInViewport();await page.screenshot({path:info.outputPath('topology-mobile.png')});
 await map.getByRole('button',{name:'Close map',exact:true}).click();await expect(dialog).not.toBeVisible();
 expect(await sshAttempts(page)).toEqual([]);expect(errors).toEqual([]);
});
for(const theme of ['glass','retro','paper','werkbank']){
 test(`120-host compact inventory fits narrow and wide layouts in ${theme}`,async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);await seedHosts(page);
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  for(const width of [390,1440,3440]){
   await page.setViewportSize({width,height:900});
   await expect(page.locator('#overviewHostList .od-host')).toHaveCount(120);
   await expect(page.locator('#odTopology svg, #odTopology .od-route-list').first()).toBeVisible();
   expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);
  }
  expect(await sshAttempts(page)).toEqual([]);expect(errors).toEqual([]);
 });
}
