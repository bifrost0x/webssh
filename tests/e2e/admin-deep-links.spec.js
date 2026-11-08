const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('administration redirects preserve deep links and the default Users entry',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 // Complete acknowledgement so page loads are not obscured by the tour.
 await page.request.post('/api/account/tour',{data:{state:'completed',acknowledged:true},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
 for(const width of [390,1440]){
  await page.setViewportSize({width,height:850});
  for(const section of ['integrations','authentication','backup','operations','registration']){
   await page.goto('/admin#'+section);
   const target=page.locator(`[data-settings-panel="${section}"],#tab-${section}`);
   await expect(target).toBeVisible();
   await expect(page.locator('#tab-users')).toBeHidden();
   expect(new URL(page.url()).hash).toBe('#'+section);
  }
 }
 await page.goto('/admin');await expect(page.locator('#tab-users')).toBeVisible();
});
