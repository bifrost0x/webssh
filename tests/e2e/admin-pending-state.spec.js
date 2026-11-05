const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('failed audit pagination retries the same page instead of skipping records',async({page})=>{
 await login(page);
 const offsets=[];
 let failNext=true;
 await page.route('**/admin/api/audit?**',route=>{
  const offset=Number(new URL(route.request().url()).searchParams.get('offset'));
  offsets.push(offset);
  if(offset===100&&failNext){failNext=false;return route.fulfill({status:503,json:{error:'Temporary page failure'}});}
  return route.fulfill({json:{offset,total:300,items:[{timestamp:'2026-11-02T12:00:00Z',level:'INFO',logger:'audit',message:`offset-${offset}`}]}});
 });
 await page.goto('/settings#audit');
 await expect(page.locator('#adminAuditBody')).toContainText('offset-0');
 await page.locator('#auditNext').click();
 await expect(page.locator('#notificationContainer')).toContainText('Temporary page failure');
 await expect(page.locator('#adminAuditBody')).toContainText('offset-0');
 await page.locator('#auditNext').click();
 await expect(page.locator('#adminAuditBody')).toContainText('offset-100');
 expect(offsets.slice(-2)).toEqual([100,100]);
 await page.locator('#auditPrev').click();
 await expect(page.locator('#adminAuditBody')).toContainText('offset-0');
});

test('registration control is locked during authentication and restored after cancellation',async({page})=>{
 await login(page);
 await page.goto('/settings#registration');
 const toggle=page.locator('#settingRegistration');
 await expect(toggle).toBeVisible();
 await expect(toggle).toBeEnabled();
 const previous=await toggle.isChecked();
 await toggle.setChecked(!previous);
 await expect(page.locator('#stepUpModal')).toBeVisible();
 await expect(toggle).toBeDisabled();
 await page.locator('#stepUpCancelButton').click();
 await expect(toggle).toBeEnabled();
 await expect(toggle).toBeChecked({checked:previous});
});


test('registration waits for its persisted value before becoming interactive',async({page})=>{
 await login(page);
 let release;
 const delay=new Promise(resolve=>{release=resolve;});
 await page.route('**/admin/api/settings',async route=>{
  await delay;
  await route.fulfill({json:{registration_enabled:true,ssh_gateway_enabled:false}});
 });
 await page.goto('/settings#registration');
 const toggle=page.locator('#settingRegistration');
 await expect(toggle).toBeVisible();
 await expect(toggle).toBeDisabled();
 release();
 await expect(toggle).toBeEnabled();
 await expect(toggle).toBeChecked();
});
