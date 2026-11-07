const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.use({viewport:{width:1600,height:900}});
test.afterEach(async({page})=>assertNoExternalRequests(page));

test('Werkbank overview aligns the welcome above routes and compact hosts',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
 const positions=await page.evaluate(()=>{
  const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom}};
  return {welcome:box('.od-hero'),routes:box('.od-topology'),hosts:box('.od-hosts'),side:box('.od-side')};
 });
 expect(positions.welcome.bottom-positions.welcome.top).toBeGreaterThanOrEqual(80);
 expect(positions.routes.top).toBeGreaterThanOrEqual(positions.welcome.bottom);
 expect(positions.hosts.top).toBeGreaterThanOrEqual(positions.routes.bottom);
 expect(Math.abs(positions.side.top-positions.hosts.top)).toBeLessThan(24);
 await expect(page.locator('.od-host .od-connect').first()).toBeVisible();
 await page.locator('.od-host [data-key^="edit:"]').first().click();
 await expect(page.locator('#profileEditorView')).toBeVisible();
});

test('host search and compact host cards remain usable across widths',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.locator('#overviewSearch').fill('Operations');
 await expect(page.locator('#overviewHostList .od-host')).toHaveCount(2);
 await page.locator('#overviewSearch').fill('');
 for(const width of [1600,1280,1024,740,390]){
  await page.setViewportSize({width,height:800});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await expect(page.locator('#overviewSearch')).toBeVisible();
  await expect(page.locator('.od-host .od-connect').first()).toBeVisible();
 }
});

test('overview creation and primary navigation retain host, file and command workflows',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.locator('#overviewNewHost').click();
 await expect(page.locator('#profileEditorView')).toBeVisible();
 await page.locator('#overviewNavBtn').click();
 await page.locator('#fileTransferBtn').click();
 await expect(page.locator('#sftpFileManager')).toBeVisible();
 await page.locator('#overviewNavBtn').click();
 await page.locator('#commandLibraryBtn').click();
 await expect(page.locator('#commandWorkspaceModal')).toBeVisible();
});

test.describe('touch host previews',()=>{
 test.use({viewport:{width:390,height:844},hasTouch:true});
 test('host preview actions retain touch targets and open the existing editor',async({page})=>{
  await login(page,'e2e_admin',{workspace:false});
  const card=page.locator('#overviewHostList .od-host:not(.od-skeleton)').first();
  await expect(card).toBeVisible();
  for(const selector of ['.od-connect','[data-key^="edit:"]']){
   const box=await card.locator(selector).boundingBox();
   expect(box.width).toBeGreaterThanOrEqual(44);
   expect(box.height).toBeGreaterThanOrEqual(44);
  }
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await expect(card.locator('.od-host-name')).toBeVisible();
  await card.locator('[data-key^="edit:"]').tap();
  await expect(page.locator('#profileEditorView')).toBeVisible();
 });
});
