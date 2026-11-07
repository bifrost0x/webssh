const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));
async function defaultPanels(page){const token=await page.locator('meta[name="csrf-token"]').getAttribute('content');expect((await page.request.put('/api/overview/preferences',{data:{panels:null},headers:{'X-CSRFToken':token}})).ok()).toBe(true);}
async function overviewLayout(page,layout){const token=await page.locator('meta[name="csrf-token"]').getAttribute('content');const response=await page.request.post('/api/account/preferences',{data:{overview_layout:layout},headers:{'X-CSRFToken':token}});expect(response.ok()).toBe(true);}
test('welcome aligns key figures, routes, hosts and side panels in the responsive dashboard grid',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});
 await defaultPanels(page);await page.reload();
 const hero=page.locator('.od-hero');await expect(hero).toBeVisible();
 await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
 // Measure the settled layout, not the entrance animation.
 await expect(page.locator('#connectionOverview')).toHaveAttribute('data-settled',/.*/);
 for(const size of [{width:2126,height:836},{width:1280,height:720},{width:390,height:844},{width:3440,height:1440}]){
  await page.setViewportSize(size);await expect(hero).toBeVisible();
  const bounds=await hero.boundingBox();expect(bounds.height).toBeGreaterThanOrEqual(80);
  expect(bounds.x+bounds.width).toBeLessThanOrEqual(size.width);
  const kpis=await page.locator('.od-kpis').boundingBox();const map=await page.locator('.od-topology').boundingBox();
  expect(kpis.y).toBeGreaterThanOrEqual(bounds.y+bounds.height-1);expect(map.y).toBeGreaterThanOrEqual(kpis.y+kpis.height-1);
  const hosts=await page.locator('.od-hosts').boundingBox();const side=await page.locator('#odAttention').boundingBox();
  expect(hosts.y).toBeGreaterThanOrEqual(map.y+map.height-1);
  // Wide: attention and automation start beside the routes, in the first view.
  if(size.width>=1280){expect(Math.abs(side.y-map.y)).toBeLessThan(2);expect(side.x).toBeGreaterThanOrEqual(map.x+map.width);expect(side.x).toBeGreaterThanOrEqual(hosts.x+hosts.width);}
  // Stacked: open issues follow the routes, before the host list.
  else {expect(side.y).toBeGreaterThanOrEqual(map.y+map.height-1);expect(hosts.y).toBeGreaterThanOrEqual(side.y+side.height-1);}
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  expect(await page.locator('#connectionOverview').evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
 }
});
test('command code and description clicks open the matching right inspector without taking over action buttons',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});await page.locator('#commandLibraryBtn').click();const rows=page.locator('#commandsList .command-row');await expect(rows.first()).toBeVisible();
 const first=rows.first();const id=await first.getAttribute('data-command-id');await first.locator('.command-text').click();await expect(first).toHaveClass(/is-selected/);await expect(page.locator('#commandLibraryDetails')).toBeVisible();const list=await page.locator('#commandsList').boundingBox();const details=await page.locator('#commandLibraryDetails').boundingBox();expect(details.x).toBeGreaterThanOrEqual(list.x+list.width);await expect(page.locator('#commandFormModal')).toBeHidden();
 const next=rows.nth(1);await next.locator('.command-desc').click();await expect(next).toHaveClass(/is-selected/);expect(await page.evaluate(()=>CommandLibrary.selectedCommandId)).not.toBe(id);
 const selected=await page.evaluate(()=>CommandLibrary.selectedCommandId);await first.locator('.command-favorite').click();expect(await page.evaluate(()=>CommandLibrary.selectedCommandId)).toBe(selected);
 await page.locator('#commandLibraryDetails .inspector-return').click();await expect(page.locator('#commandLibraryDetails')).toHaveCount(0);await first.locator('.command-inspect-button').focus();await page.keyboard.press('Enter');await expect(page.locator('#commandLibraryDetails')).toBeVisible();
});

test('classic session list retains long session names and resumes the same terminal',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});await overviewLayout(page,'classic');
 try{
  await page.goto('/');await page.waitForFunction(()=>ProfileManager.profilesLoaded);await page.evaluate(()=>{
   window.socket.emit=()=>window.socket;
   SessionManager.createSession({session_id:'composition-resume',host:'homelab-primary.example',username:'admin',port:22,display_name:'Homelab primary - maintenance terminal'});
   SessionManager.assignSessionToPane('composition-resume',0);
  });
  await page.locator('#overviewNavBtn').click();const session=page.locator('#overviewSessions > .overview-row').first();await expect(session).toBeVisible();await expect(session).toContainText('Homelab primary - maintenance terminal');const card=await session.boundingBox();const support=await page.locator('.overview-sessions-card').boundingBox();expect(card.x+card.width).toBeLessThanOrEqual(support.x+support.width);
  await session.click();await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','workspaces');expect(await page.evaluate(()=>SessionManager.paneAssignments[0])).toBe('composition-resume');
 }finally{await overviewLayout(page,'dashboard');}
});
