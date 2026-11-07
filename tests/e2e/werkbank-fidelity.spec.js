const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.use({viewport:{width:1600,height:900}});
test.afterEach(async({page})=>assertNoExternalRequests(page));

test('Werkbank overview aligns inventory above compact hosts and routes',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#overviewInventorySummary .overview-resource-link').first()).toBeVisible();
 const positions=await page.evaluate(()=>{
  const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom}};
  return {sidebar:box('.overview-inventory-sidebar'),network:box('.overview-primary'),routes:box('[data-module=routes]'),welcome:box('.overview-heading')};
 });
 expect(positions.sidebar.bottom).toBeLessThanOrEqual(positions.network.top);
 expect(Math.abs(positions.routes.top-positions.network.top)).toBeLessThan(24);
 await expect(page.locator('[data-module=news]')).toBeHidden();
 expect(positions.welcome.bottom-positions.welcome.top).toBeGreaterThanOrEqual(80);
 expect(positions.network.top).toBeGreaterThanOrEqual(positions.welcome.bottom);
 await expect(page.locator('.overview-compact-row > button').first()).toBeVisible();
 await page.locator('.overview-compact-row .overview-host-edit').first().click();
 await expect(page.locator('#profileEditorView')).toBeVisible();
});

test('sidebar group filtering and compact route cards remain usable across widths',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.locator('#overviewGroupFilter').selectOption('group:Operations');
 await expect(page.locator('#overviewGroupFilter')).toHaveValue('group:Operations');
 await expect(page.locator('.overview-compact-row')).toHaveCount(2);
 await page.locator('#overviewGroupFilter').selectOption('');
 for(const width of [1600,1280,1024,740,390]){
  await page.setViewportSize({width,height:800});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await expect(page.locator('#overviewHostSearch')).toBeVisible();
  await expect(page.locator('.overview-compact-row > button').first()).toBeVisible();
 }
});

test('overview creation and primary navigation retain host, file and command workflows',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.locator('#overviewCreateHost').click();
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
  const card=page.locator('.overview-compact-row').first();
  for(const selector of [':scope > button','.overview-host-edit']){
   const box=await card.locator(selector).boundingBox();
   expect(box.width).toBeGreaterThanOrEqual(44);
   expect(box.height).toBeGreaterThanOrEqual(44);
  }
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await expect(card.locator('.overview-row-title')).toBeVisible();
  await card.locator('.overview-host-edit').tap();
  await expect(page.locator('#profileEditorView')).toBeVisible();
 });
});
