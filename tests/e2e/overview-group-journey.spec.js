const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts,assertNoExternalRequests,assertRouteGeometry}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));
for(const width of [390,1440,3440])test(`group selection and route geometry remain consistent at ${width}`,async({page},info)=>{
 await page.setViewportSize({width,height:900});await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>{const p=ProfileManager.profiles[0];JumpHostManager.setJumpHosts([{id:'g',name:'Gateway'}]);ProfileManager.setProfiles(Array.from({length:160},(_,i)=>({...p,id:'journey-'+i,name:'Host '+i,group:'Group '+Math.floor(i/20),jump_host_id:i%2?'g':null})));});
 await expect(page.locator('.overview-list-group')).toHaveCount(8);
 await page.getByRole('button',{name:'Expand map',exact:true}).click();
 await assertRouteGeometry(page);
 await page.keyboard.press('Escape');
 await page.locator('#overviewGroupFilter').selectOption('group:Group 7');
 await expect(page.locator('.overview-compact-row')).toHaveCount(20);
 await page.locator('.overview-compact-row [data-host-id]').first().click();await expect(page.locator('.overview-access-inspector')).toBeVisible();
 for(const inspectWidth of [390,3440,width]){
  await page.setViewportSize({width:inspectWidth,height:900});
  await expect(page.locator('.overview-access-heading button')).toBeVisible();
  expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);
 }
 await page.locator('#overviewGroupFilter').selectOption('group:Group 0');await expect(page.locator('.overview-access-inspector')).toHaveCount(0);await expect(page.locator('.overview-compact-row')).toHaveCount(20);
 await page.locator('#overviewHostSearch').fill('Host 19');await expect(page.locator('.overview-compact-row')).toHaveCount(1);
 await page.locator('#overviewGroupFilter').selectOption('');await expect(page.locator('.overview-list-group')).toHaveCount(8);
 await page.emulateMedia({reducedMotion:'reduce'});await expect(page.locator('.overview-scene')).toHaveCSS('animation-name','none');
 await page.screenshot({path:info.outputPath('journey-'+width+'.png'),animations:'disabled'});
 expect(await page.locator('#connectionOverview').evaluate(e=>e.scrollWidth<=e.clientWidth+1)).toBe(true);expect(await sshAttempts(page)).toEqual([]);
});

test('removing the selected group returns to a complete overview without stale route state',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{const p=ProfileManager.profiles[0];ProfileManager.setProfiles([{...p,id:'remove-a',group:'Temporary',name:'Temporary host'},{...p,id:'keep-b',group:'Remaining',name:'Remaining host'}]);});
 await page.locator('#overviewGroupFilter').selectOption('group:Temporary');await expect(page.locator('.overview-compact-row')).toHaveCount(1);
 await page.evaluate(()=>ProfileManager.setProfiles(ProfileManager.profiles.filter(p=>p.id!=='remove-a')));
 await expect(page.locator('#overviewGroupFilter')).toHaveValue('');
 await expect(page.locator('#connectionOverview')).toHaveAttribute('data-journey','welcome');
 await expect(page.locator('#overviewTitle')).toBeVisible();await expect(page.locator('.overview-list-group')).toHaveCount(1);
});
