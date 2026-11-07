const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
for (const outcome of ['cancel','save','failure']) {
 const save = outcome === 'save';
 test(`security toggle keeps confirmed state when refresh fails after ${outcome}`,async({page})=>{
  await login(page);
  let failRefresh=false;
  const feature={name:'totp',active:false,admin_enabled:false,deployment_allowed:true,ready:true};
  await page.route('**/admin/api/security-features',route=>route.fulfill(failRefresh?{status:503,json:{error:'Status unavailable'}}:{json:{features:[feature]}}));
  await page.route('**/admin/api/security-features/totp',route=>route.fulfill(outcome === 'failure' ? {status:503,json:{error:'Save unavailable'}} : {json:{feature:{...feature,active:true,admin_enabled:true}}}));
  await page.goto('/settings#authentication');
  const toggle=page.locator('[data-security-feature="totp"]');
  await expect(toggle).toBeEnabled();
  await expect(toggle).not.toBeChecked();
  failRefresh=true;
  await toggle.check();
  await expect(page.locator('#stepUpModal')).toBeVisible();
  if(outcome !== 'cancel'){await page.locator('#stepUpPassword').fill('browser-password');await page.locator('#stepUpSubmit').click();}
  else await page.locator('#stepUpCancelButton').click();
  await expect(page.locator('#securityFeatureStatus')).toContainText('Status unavailable');
  await expect(toggle).toBeEnabled();
  if(save) await expect(toggle).toBeChecked();
  else await expect(toggle).not.toBeChecked();
 });
}
