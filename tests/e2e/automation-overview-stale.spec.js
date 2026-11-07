const {test,expect}=require('playwright/test');const {login}=require('./helpers');
test('overview retains stale status through language changes until a successful refresh',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[],profiles:[]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 let offline=false;await page.route('**/api/automation/runs',r=>r.fulfill(offline?{status:503,json:{code:'unavailable'}}:{json:{runs:[{id:'old',name:'Last confirmed result',status:'succeeded',created_at:'2026-11-04T09:00:00Z',targets:[]}]}}));
 await page.goto('/');await expect(page.locator('#overviewAutomation')).toBeVisible();offline=true;await expect(page.locator('#overviewAutomationStale')).toBeVisible({timeout:10000});
 expect(await page.evaluate(()=>{window.i18n.setLanguage('de');return document.getElementById('overviewAutomationStale').hidden;})).toBe(false);await expect(page.locator('#overviewAutomationStale')).toBeVisible();await expect(page.locator('#overviewAutomationStale')).toContainText('veraltet');
 offline=false;await expect(page.locator('#overviewAutomationStale')).toBeHidden({timeout:10000});
});
