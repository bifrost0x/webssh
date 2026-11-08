const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));

test('schedule editing cannot replace a workflow while its save is pending',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const books=['Alpha','Beta'].map(name=>({id:name.toLowerCase(),name,steps:[{name:'Identity',command:'id',timeout:30,sudo:false}],stop_on_error:true}));
 const schedule={id:'schedule-beta',runbook_id:'beta',name:'Beta',cron:'0 9 * * *',timezone:'UTC',enabled:false,profile_ids:['host'],groups:[]};
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:books,profiles:[{id:'host',name:'Host',host:'host.invalid',username:'op',auth_type:'key',supported:true}]}}));
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[schedule]}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));
 let release,seen;const gate=new Promise(r=>release=r),saving=new Promise(r=>seen=r);
 await page.route('**/api/automation/runbooks',async r=>{const book=r.request().postDataJSON();seen();await gate;await r.fulfill({json:{runbook:book}});});
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();await expect(page.locator('#runbookName')).toHaveValue('Alpha');
 await page.locator('#saveRunbook').click();await saving;
 await page.locator('[data-auto-tab=schedules]').click();
 await expect(page.locator('#scheduleList').getByRole('button',{name:'Review schedule',exact:true})).toBeDisabled();
 release();await expect(page.locator('body')).not.toHaveAttribute('aria-busy','true');
 await page.locator('[data-auto-tab=runbooks]').click();
 await expect(page.locator('#runbookName')).toHaveValue('Alpha');
 await expect(page.locator('#runbookList .automation-library-entry[aria-current=true]')).toContainText('Alpha');
 await page.locator('[data-auto-tab=schedules]').click();
 await page.locator('#scheduleList').getByRole('button',{name:'Review schedule',exact:true}).click();
 await expect(page.locator('#runbookName')).toHaveValue('Beta');
 await expect(page.locator('#scheduleCron')).toHaveValue('0 9 * * *');
});

test('Automation preserves the application language when its labels fall back to English',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/automation');
 for(const language of ['fr','es','zh']){
  await page.evaluate(lang=>window.i18n.setLanguage(lang),language);
  await expect(page.locator('html')).toHaveAttribute('lang',language);
  await expect(page.locator('main[data-native-automation]')).toHaveAttribute('lang','en');
  await expect(page.locator('#automationNavBtn')).not.toHaveAttribute('lang','en');
  await expect(page.locator('[data-auto-tab=runs] [data-auto-i18n]')).toHaveText('Runs');
 }
});
