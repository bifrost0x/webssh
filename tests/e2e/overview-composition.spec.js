const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));
test('welcome aligns inventory, routes and continuation in the responsive dashboard grid',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});
 const scene=page.locator('.overview-scene');await expect(scene).toBeVisible();
 await expect(page.locator('.overview-inventory-sidebar #overviewInventorySummary')).toBeVisible();
 const rail=await page.locator('.overview-inventory-sidebar').boundingBox();
 const network=await page.locator('.overview-primary').boundingBox();
 expect(rail.y+rail.height).toBeLessThanOrEqual(network.y);
 for(const size of [{width:2126,height:836},{width:1280,height:720},{width:390,height:844},{width:3440,height:1440}]){
  await page.setViewportSize(size);await expect(scene).toBeVisible();
  const bounds=await scene.boundingBox();expect(bounds.height).toBeGreaterThanOrEqual(80);
  expect(bounds.x+bounds.width).toBeLessThanOrEqual(size.width);
  const map=await page.locator('.overview-primary').boundingBox();const support=await page.locator('.overview-session-strip').boundingBox();
  expect(support.y).toBeGreaterThanOrEqual(map.y+map.height-1);
  await expect(page.locator('[data-module=news]')).toBeHidden();
  const routes=await page.locator('[data-module=routes]').boundingBox();
  const infrastructure=await page.locator('[data-module=infrastructure]').boundingBox();
  if(size.width>=1280) expect(Math.abs(routes.y-infrastructure.y)).toBeLessThan(2);
  else expect(routes.y).toBeGreaterThanOrEqual(infrastructure.y+infrastructure.height);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 await page.setViewportSize({width:1280,height:720});await page.locator('#overviewGroupFilter').selectOption('group:Operations');await expect(scene).toBeHidden();await expect(page.locator('.overview-list-group')).toHaveCount(1);await expect(page.locator('.overview-session-strip')).toBeHidden();
});
test('command code and description clicks open the matching right inspector without taking over action buttons',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});await page.locator('#commandLibraryBtn').click();const rows=page.locator('#commandsList .command-row');await expect(rows.first()).toBeVisible();
 const first=rows.first();const id=await first.getAttribute('data-command-id');await first.locator('.command-text').click();await expect(first).toHaveClass(/is-selected/);await expect(page.locator('#commandLibraryDetails')).toBeVisible();const list=await page.locator('#commandsList').boundingBox();const details=await page.locator('#commandLibraryDetails').boundingBox();expect(details.x).toBeGreaterThanOrEqual(list.x+list.width);await expect(page.locator('#commandFormModal')).toBeHidden();
 const next=rows.nth(1);await next.locator('.command-desc').click();await expect(next).toHaveClass(/is-selected/);expect(await page.evaluate(()=>CommandLibrary.selectedCommandId)).not.toBe(id);
 const selected=await page.evaluate(()=>CommandLibrary.selectedCommandId);await first.locator('.command-favorite').click();expect(await page.evaluate(()=>CommandLibrary.selectedCommandId)).toBe(selected);
 await page.locator('#commandLibraryDetails .inspector-return').click();await expect(page.locator('#commandLibraryDetails')).toHaveCount(0);await first.locator('.command-inspect-button').focus();await page.keyboard.press('Enter');await expect(page.locator('#commandLibraryDetails')).toBeVisible();
});

test('the continuation below the network retains long session names and resumes the same terminal',async({page})=>{
 await page.setViewportSize({width:2126,height:836});await login(page,'e2e_admin',{workspace:false});await page.evaluate(()=>{
  window.socket.emit=()=>window.socket;
  SessionManager.createSession({session_id:'composition-resume',host:'homelab-primary.example',username:'admin',port:22,display_name:'Homelab primary - maintenance terminal'});
  SessionManager.assignSessionToPane('composition-resume',0);
 });
 await page.locator('#overviewNavBtn').click();const session=page.locator('#overviewSessions > .overview-row').first();await expect(session).toBeVisible();await expect(session).toContainText('Homelab primary - maintenance terminal');const card=await session.boundingBox();const support=await page.locator('.overview-session-strip').boundingBox();expect(card.x+card.width).toBeLessThanOrEqual(support.x+support.width);
 await session.click();await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','workspaces');expect(await page.evaluate(()=>SessionManager.paneAssignments[0])).toBe('composition-resume');
});
