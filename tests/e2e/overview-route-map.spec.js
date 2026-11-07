const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('SSH route pane handles mixed routes, large inventories, themes and saved camera',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{
  const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'bastion',name:'Gateway'}]);
  ProfileManager.setProfiles(Array.from({length:120},(_,i)=>({...base,id:'route-'+i,name:'Server '+String(i).padStart(3,'0'),group:'Group '+Math.floor(i/20),favorite:false,jump_host_id:i%3?'bastion':null})));
 });
 // The dashboard shows a route summary; the complete map opens on request.
 await page.locator('#overviewOpenMap').click();
 const pane=page.locator('#overviewRouteMap'),viewport=pane.locator('.ssh-route-viewport');
 await expect(pane.locator('.ssh-map-count')).toHaveText('120 / 120 hosts');
 await expect(pane.locator('.ssh-route-branch')).toHaveCount(2);
 await expect(pane.locator('.ssh-route-source').filter({hasText:'Gateway'})).toHaveCount(1);
 await expect(pane.locator('svg path')).toHaveCount(3);
 await expect(pane.locator('.ssh-route-host')).toHaveCount(4);
 await pane.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();
 await expect(pane.locator('.ssh-route-host')).toHaveCount(42);
 const search=pane.getByRole('searchbox');
 await search.fill('Server 119');await expect(pane.locator('.ssh-route-host')).toHaveCount(1);
 await expect(pane.locator('.ssh-route-source')).toContainText('Gateway');
 await pane.getByRole('button',{name:'Inspect Server 119',exact:true}).click();
 await expect(page.locator('dialog.ssh-map-dialog')).toBeHidden();
 await expect(page.locator('#overviewSearch')).toHaveValue('Server 119');
 await expect(page.locator('#overviewHostList .od-host')).toHaveCount(1);
 await page.locator('#overviewSearch').press('Escape');
 await page.locator('#overviewOpenMap').click();await search.fill('');
 await pane.getByRole('button',{name:'Fit map',exact:true}).click();
 const percent=await pane.locator('output').innerText();
 await pane.getByRole('button',{name:'Zoom in SSH routes',exact:true}).click();
 await expect(pane.locator('output')).not.toHaveText(percent);
 await viewport.scrollIntoViewIfNeeded();
 const box=await viewport.boundingBox();
 const canvas=pane.locator('.ssh-route-canvas');
 const transform=await canvas.getAttribute('style');
 await page.mouse.move(box.x+20,box.y+20);await page.mouse.down();
 await page.mouse.move(box.x+80,box.y+60,{steps:6});await page.mouse.up();
 expect(await canvas.getAttribute('style')).not.toBe(transform);
 const wheelZoom=await pane.locator('output').innerText();
 await page.mouse.wheel(0,-120);await expect(pane.locator('output')).not.toHaveText(wheelZoom);
 await viewport.focus();await page.keyboard.press('ArrowRight');
 await page.waitForTimeout(250);
 const stored=await page.evaluate(()=>localStorage.getItem('webssh:route-map:'+document.querySelector('meta[name=background-scope]').content));
 expect(JSON.parse(stored).fullCamera.scale).toBeGreaterThan(0);
 await page.evaluate(()=>document.body.dataset.theme='werkbank');
 await page.setViewportSize({width:1440,height:900});await pane.scrollIntoViewIfNeeded();
 await pane.getByRole('button',{name:'Fit map',exact:true}).click();
 await page.screenshot({path:info.outputPath('routes-1440.png'),animations:'disabled'});
 await page.emulateMedia({reducedMotion:'reduce'});
 await expect(pane.locator('.ssh-route-branch').first()).toHaveCSS('animation-name','none');
 expect(await sshAttempts(page)).toEqual([]);
 // Use the existing profiles after reload; saved camera is independent of inventory churn.
 await page.waitForTimeout(250);
 const before=await page.evaluate(()=>JSON.parse(localStorage.getItem('webssh:route-map:'+document.querySelector('meta[name=background-scope]').content)).camera);
 await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded&&JumpHostManager.loaded);
 await page.locator('#overviewOpenMap').click();
 await expect(pane.locator('.ssh-map-count')).toContainText('hosts');
 const after=await page.evaluate(()=>JSON.parse(localStorage.getItem('webssh:route-map:'+document.querySelector('meta[name=background-scope]').content)).camera);
 expect(after).toEqual(before);
 expect(errors).toEqual([]);
});

// Each theme gets its own bounded browser case; retain the full 120-host matrix.
for (const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']) {
 test(`expanded 120-host route map fits narrow and wide layouts in ${theme}`, async ({page}) => {
  await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{
  const base=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'bastion',name:'Gateway'}]);
  ProfileManager.setProfiles(Array.from({length:120},(_,i)=>({...base,id:'route-'+i,name:'Server '+String(i).padStart(3,'0'),group:'Group '+Math.floor(i/20),favorite:false,jump_host_id:i%3?'bastion':null})));
 });
  await page.locator('#overviewOpenMap').click();
  const pane=page.locator('#overviewRouteMap');
  await expect(pane.locator('.ssh-map-count')).toHaveText('120 / 120 hosts');
  await pane.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();
  await expect(pane.locator('.ssh-route-host')).toHaveCount(42);
  await expect(pane.getByRole('button',{name:'Close map',exact:true})).toBeVisible();
  await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
  for(const width of [390,1440,3440]) {
   await page.setViewportSize({width,height:900});
   expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);
   expect(await pane.evaluate(e=>e.scrollWidth<=e.clientWidth+1),theme+' '+width).toBe(true);
  }
  expect(await sshAttempts(page)).toEqual([]);
 });
}
