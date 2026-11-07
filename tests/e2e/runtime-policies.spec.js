const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('runtime policies save through reauthentication and explain deployment locks',async({page},testInfo)=>{
 await login(page);
 await page.request.post('/api/account/tour',{data:{state:'completed',acknowledged:true},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
 await page.goto('/settings#integrations');
 const toggle=page.locator('#runtime-server_operations_enabled');
 await expect(toggle).toBeEnabled();
 const initial=await toggle.isChecked();await toggle.setChecked(!initial);
 await expect(page.locator('#stepUpModal')).toBeVisible();
 await page.locator('#stepUpPassword').fill('browser-password');await page.locator('#stepUpSubmit').click();
 await expect(page.locator('#stepUpModal')).toBeHidden();
 await expect(toggle).toBeChecked({checked:!initial});
 await expect.poll(async()=> (await (await page.request.get('/admin/api/settings')).json()).server_operations_enabled).toBe(!initial);
 await expect(toggle).toBeEnabled();
 await page.reload();await expect(toggle).toBeChecked({checked:!initial});
 await page.route('**/admin/api/settings',async route=>{
  const response=await route.fetch();const data=await response.json();
  data.runtime_features.server_operations_enabled={enabled:false,locked:true,source:'compose',environment_key:'SERVER_OPERATIONS_ENABLED',saved_value:true,migrated:true};
  await route.fulfill({json:data});
 });
 await page.reload();await expect(toggle).toBeDisabled();
 await expect(toggle.locator('..')).toHaveAttribute('title',/SERVER_OPERATIONS_ENABLED/);
 await expect(page.locator('#runtimeFeatureSettings')).toContainText('SERVER_OPERATIONS_ENABLED=false');
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});
  for(const theme of ['glass','werkbank','paper','noir','solar','retro','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  }
  await toggle.locator('..').focus();
  await page.screenshot({path:testInfo.outputPath(`policies-${width}.png`),fullPage:true});
 }
});
