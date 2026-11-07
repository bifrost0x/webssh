const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts,assertNoExternalRequests,assertRouteGeometry}=require('./helpers');
const layout=async(page,value)=>{const response=await page.request.post('/api/account/preferences',{data:{overview_layout:value},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});expect(response.ok()).toBe(true);};
let classic=false;
test.afterEach(async({page})=>{if(classic){classic=false;await layout(page,'dashboard');}await assertNoExternalRequests(page);});
for(const width of [390,1440,3440])test(`group selection and route geometry remain consistent at ${width}`,async({page},info)=>{
 await page.setViewportSize({width,height:900});await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{const p=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'g',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:160},(_,i)=>({...p,id:'journey-'+i,name:'Host '+i,group:'Group '+Math.floor(i/20),jump_host_id:i%2?'g':null})));});
 const hosts=page.locator('#overviewHostList .od-host');
 await expect(hosts).toHaveCount(160);
 await page.locator('#overviewOpenMap').click();await expect(page.locator('dialog.ssh-map-dialog')).toBeVisible();
 await assertRouteGeometry(page);
 await page.keyboard.press('Escape');await expect(page.locator('dialog.ssh-map-dialog')).not.toBeVisible();
 await page.locator('#overviewSearch').fill('Group 7');
 await expect(hosts).toHaveCount(20);await expect(page.locator('#overviewHostTotal')).toHaveText('20 / 160');
 for(const inspectWidth of [390,3440,width]){
  await page.setViewportSize({width:inspectWidth,height:900});
  await expect(hosts.first().locator('.od-connect')).toBeVisible();
  expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
 }
 await page.locator('#overviewSearch').fill('Group 0');await expect(hosts).toHaveCount(20);
 await page.locator('#overviewSearch').fill('Host 19');await expect(hosts).toHaveCount(1);
 await page.locator('#overviewSearch').fill('');await expect(hosts).toHaveCount(160);
 await page.emulateMedia({reducedMotion:'reduce'});await expect(page.locator('.od-scene')).toHaveCSS('animation-name','none');
 await page.screenshot({path:info.outputPath('journey-'+width+'.png'),animations:'disabled'});
 expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);expect(await sshAttempts(page)).toEqual([]);
});

test('removing the selected group returns to a complete overview without stale route state',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 // The group filter lives in the classic overview layout.
 await layout(page,'classic');classic=true;await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);
 await page.evaluate(()=>{const p=ProfileManager.profiles[0];ProfileManager.setProfiles([{...p,id:'remove-a',group:'Temporary',name:'Temporary host'},{...p,id:'keep-b',group:'Remaining',name:'Remaining host'}]);});
 await page.locator('#overviewGroupFilter').selectOption('group:Temporary');await expect(page.locator('#overviewHosts [data-host-id]')).toHaveCount(1);
 await page.evaluate(()=>ProfileManager.setProfiles(ProfileManager.profiles.filter(p=>p.id!=='remove-a')));
 await expect(page.locator('#overviewGroupFilter')).toHaveValue('');
 await expect(page.locator('#overviewTitle')).toBeVisible();await expect(page.locator('#overviewHosts .overview-host-group')).toHaveCount(1);
 await expect(page.locator('#overviewHosts [data-host-id="keep-b"]')).toBeVisible();
});
