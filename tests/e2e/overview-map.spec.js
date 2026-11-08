const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('map supports large inventories, pan, zoom, group drilldown and responsive themes',async({page},info)=>{
 // 121 hosts across four themes and three widths: more work than the default budget allows on shared runners.
 test.slow();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 // The dashboard offers the full map once a saved route uses a jump host.
 await page.evaluate(()=>{const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'map-gate',name:'Gateway'}]);ProfileManager.setProfiles([...Array.from({length:120},(_,i)=>({...base,id:'map-'+i,name:'Map host '+i,group:'Group '+Math.floor(i/20),jump_host_id:null})),{...base,id:'map-gated',name:'Gated host',group:'Edge',jump_host_id:'map-gate'}]);});
 const hosts=page.locator('#overviewHostList .od-host');await expect(hosts).toHaveCount(121);
 await page.locator('#overviewOpenMap').click();
 await expect(page.locator('.ssh-route-more')).toHaveAttribute('aria-expanded','false');
 await expect(page.locator('[data-map-node="direct:hosts"] .ssh-route-host')).toHaveCount(2);
 await page.getByRole('button',{name:'Zoom in SSH routes',exact:true}).click();
 const canvas=page.locator('.ssh-route-canvas');const before=await canvas.getAttribute('style');
 const viewport=page.locator('.ssh-route-viewport');await viewport.focus();await page.keyboard.press('ArrowRight');
 expect(await canvas.getAttribute('style')).not.toBe(before);
 const rect=await viewport.boundingBox();const prior=await canvas.getAttribute('style');
 await page.mouse.move(rect.x+8,rect.y+8);await page.mouse.down();await page.mouse.move(rect.x+68,rect.y+48,{steps:5});await page.mouse.up();
 expect(await canvas.getAttribute('style')).not.toBe(prior);
 await page.getByRole('button',{name:'Fit map',exact:true}).click();
 await page.locator('.ssh-route-more').click();
 await expect(page.locator('[data-map-node="direct:hosts"] .ssh-route-host')).toHaveCount(120);
 await page.locator('.ssh-map-toolbar input').fill('Map host 119');
 await expect(page.locator('.ssh-route-host')).toHaveCount(1);
 await page.locator('.ssh-route-target').click();
 await expect(page.locator('.ssh-map-dialog')).not.toBeVisible();
 await expect(page.locator('#overviewSearch')).toHaveValue('Map host 119');await expect(hosts).toHaveCount(1);
 await page.locator('#overviewSearch').fill('Group 0');
 await expect(hosts).toHaveCount(20);
 await page.locator('#overviewSearch').fill('Map host 119');
 await expect(hosts).toHaveCount(1);await expect(page.getByRole('button',{name:'Connect Map host 119',exact:true})).toBeVisible();
 await page.locator('#overviewSearch').fill('');
 // Themes with distinct geometry (glass default, retro type, paper light, werkbank shell);
 // every theme's containment is covered by the theme and presentation specs.
 for(const theme of ['glass','retro','paper','werkbank']){
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  for(const width of [390,1440,3440]){
   await page.setViewportSize({width,height:900});
   expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);
  }
 }
 await page.locator('#overviewOpenMap').click();
 await page.locator('.ssh-map-toolbar input').fill('');
 await page.locator('.ssh-map-dialog').screenshot({path:info.outputPath('map-large.png'),animations:'disabled'});
 await page.setViewportSize({width:390,height:760});
 await expect(page.getByRole('button',{name:'Close map',exact:true})).toBeInViewport();
 await expect(page.getByRole('button',{name:'Fit map',exact:true})).toBeInViewport();
 await page.locator('.ssh-map-dialog').screenshot({path:info.outputPath('map-small.png'),animations:'disabled'});
 expect(await sshAttempts(page)).toEqual([]);expect(errors).toEqual([]);
});
