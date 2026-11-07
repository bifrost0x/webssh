const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('expanded topology preserves dragged nodes and edges through collapse, reload and responsive changes',async({page},info)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.setViewportSize({width:1440,height:1000});
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 const seed=()=>page.evaluate(()=>{const b=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'gate',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:50},(_,i)=>({...b,id:'move-'+i,name:'Node '+i,group:'Group '+i%4,jump_host_id:i%2?'gate':null})));});
 await seed();
 for(const width of [390,1440]) {
  await page.setViewportSize({width,height:1000});
  const row=page.locator('.overview-compact-row').first(), menu=row.locator('.overview-host-move');
  await expect(menu).toHaveCSS('position','relative');
  await menu.locator('summary').click();await expect(menu.locator('select')).toBeInViewport();
  expect(await menu.evaluate(e=>{const r=e.getBoundingClientRect(),p=e.closest('.overview-compact-row').getBoundingClientRect();return r.left>=p.left&&r.right<=p.right&&r.top>=p.top&&r.bottom<=p.bottom;})).toBe(true);
  await menu.locator('summary').click();
 }
 const pane=page.locator('#overviewRouteMap');
 const read=()=>page.evaluate(()=>JSON.parse(localStorage.getItem('webssh:route-map:'+document.querySelector('meta[name=background-scope]').content)));
 await expect(pane.locator('.ssh-route-summary')).toHaveCount(2);
 await pane.getByRole('button',{name:'Expand map',exact:true}).click();
 const target=pane.locator('[data-map-node="direct:hosts"]'),handle=target.getByRole('button',{name:'Move Direct connections',exact:true});
 await expect(handle).toBeVisible();await expect(handle).toBeInViewport();
 const paths=await pane.locator('svg path').evaluateAll(a=>a.map(p=>p.getAttribute('d')));
 const box=await handle.boundingBox();await page.mouse.move(box.x+box.width/2,box.y+box.height/2);await page.mouse.down();await page.mouse.move(box.x+130,box.y+45,{steps:8});await page.mouse.up();
 await expect(target).toHaveCSS('transform',/matrix/);
 const moved=await target.evaluate(e=>e.style.transform);expect(moved).not.toBe('');
 expect(await pane.locator('svg path').evaluateAll(a=>a.map(p=>p.getAttribute('d')))).not.toEqual(paths);
 expect((await read()).positions.some(([id])=>id==='wide:direct:hosts')).toBe(true);
 await pane.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();await expect(target.locator('.ssh-route-host')).toHaveCount(25);await target.locator('.ssh-route-host').last().scrollIntoViewIfNeeded();await expect(target.locator('.ssh-route-host').last()).toBeInViewport();await expect(target).toHaveAttribute('style',`transform: ${moved};`);
 await pane.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();await expect(target.locator('.ssh-route-host')).toHaveCount(2);
 await pane.getByRole('button',{name:'Close map',exact:true}).click();await expect(pane.locator('.ssh-route-summary')).toHaveCount(2);expect((await read()).positions.find(([id])=>id==='wide:direct:hosts')[1]).toBeTruthy();await expect(pane.locator('.ssh-map-server')).toBeInViewport();
 await pane.getByRole('button',{name:'Expand map',exact:true}).click();await expect(target).toHaveAttribute('style',`transform: ${moved};`);
 await page.setViewportSize({width:390,height:800});await expect(pane.locator('.ssh-map-server')).toBeInViewport();await expect(target).toHaveCSS('transform','none');
 await page.setViewportSize({width:1440,height:1000});await expect(target).toHaveAttribute('style',`transform: ${moved};`);
 await pane.getByRole('button',{name:'Fit map',exact:true}).click();await page.screenshot({path:info.outputPath('arranged-map.png')});
 await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);await seed();await pane.getByRole('button',{name:'Expand map',exact:true}).click();await expect(target).toHaveAttribute('style',`transform: ${moved};`);
 await handle.focus();await page.keyboard.press('ArrowRight');expect(await target.evaluate(e=>e.style.transform)).not.toBe(moved);
 await pane.getByRole('button',{name:'Reset arrangement',exact:true}).click();await expect(target).toHaveCSS('transform','none');expect((await read()).positions.filter(([id])=>id.startsWith('wide:'))).toEqual([]);
 await page.keyboard.press('Escape');await expect(page.locator('dialog.ssh-map-dialog')).not.toBeVisible();await page.setViewportSize({width:390,height:800});await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);await seed();await pane.getByRole('button',{name:'Expand map',exact:true}).click();await expect(pane.locator('.ssh-map-server')).toBeInViewport();await page.keyboard.press('Escape');expect(await sshAttempts(page)).toEqual([]);expect(errors).toEqual([]);
});
