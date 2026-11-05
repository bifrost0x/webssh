const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('disabled automation blocks the editor and can recover after enablement',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 let enabled=false;
 await page.route('**/api/automation/state',route=>route.fulfill(enabled?{json:{enabled:true,runbooks:[],profiles:[],vault:{credentials:[]}}}:{status:403,json:{code:'disabled'}}));
 await page.route('**/api/automation/schedules',route=>route.fulfill({json:{schedules:[]}}));
 await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs:[]}}));
 for(const width of [390,1440]){
  await page.setViewportSize({width,height:800});
  if (width === 390) await page.locator('#mobileMoreBtn').click();
  await page.locator('#automationNavBtn').click();
  await expect(page.locator('#automationDisabled')).toBeVisible();
  await expect(page.locator('#automationApp')).toBeHidden();
  await expect(page.locator('#automationDisabled a').first()).toHaveAttribute('href',/github.com\/bifrost0x\/webssh\/wiki/);
 }
 enabled=true;await page.locator('#automationNavBtn').click();
 await expect(page.locator('#automationApp')).toBeVisible();
 enabled=false;await page.locator('#automationNavBtn').click();
 await expect(page.locator('#automationApp')).toBeHidden();
});
