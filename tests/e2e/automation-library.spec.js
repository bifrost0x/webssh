const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test('workflow library exposes actions and preserves drafts without executing on selection',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 let books=Array.from({length:22},(_,i)=>({id:'book-'+i,name:'Maintenance '+i,steps:[{name:'Identity',command:'id',timeout:30}],stop_on_error:true}));
 let starts=0,deleted=[];
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:books,profiles:[]}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 await page.route('**/api/automation/start',r=>{starts++;return r.fulfill({json:{}});});
 await page.route('**/api/automation/runbooks/*',r=>{deleted.push(r.request().url().split('/').pop());books=books.filter(b=>b.id!==deleted.at(-1));return r.fulfill({json:{ok:true}});});
 await page.goto('/automation');
 await expect(page.locator('#auto-library')).toBeVisible();
 await expect(page.locator('.automation-library-item')).toHaveCount(22);
 await page.locator('#runbookSearch').fill('Maintenance 21');
 const row=page.locator('.automation-library-item');
 await expect(row).toHaveCount(1);
 await row.getByRole('button',{name:'Edit',exact:true}).click();
 await expect(page.locator('#runbookName')).toHaveValue('Maintenance 21');
 await page.locator('#runbookName').fill('Unsaved draft');
 await page.locator('#backToWorkflows').click();
 await page.locator('[data-auto-tab=runbooks]').click();
 await expect(page.locator('#runbookName')).toHaveValue('Unsaved draft');
 await page.locator('#runbookName').fill('Maintenance 21');
 await page.locator('#backToWorkflows').click();
 await row.getByRole('button',{name:'Execute now',exact:true}).click();
 await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('.automation-target-section')).toBeVisible();
 expect(starts).toBe(0);
 await page.locator('#backToWorkflows').click();
 await row.getByRole('button',{name:'Delete',exact:true}).click();
 await expect(page.locator('#automationPrompt')).toContainText('Maintenance 21');
 await page.locator('#promptCancel').click(); expect(deleted).toEqual([]);
 await row.getByRole('button',{name:'Delete',exact:true}).click();
 await page.locator('#promptForm button[type=submit]').click();
 await expect.poll(()=>deleted).toEqual(['book-21']);
 await page.locator('#runbookSearch').fill('');
 await expect(page.locator('.automation-library-item')).toHaveCount(21);
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});
  for(const theme of ['glass','paper','werkbank','arctic-ice']){
   await page.evaluate(t=>document.body.dataset.theme=t,theme);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  }
  await page.screenshot({path:info.outputPath('workflows-'+width+'.png'),animations:'disabled'});
 }
 await page.locator('#newRunbook').click();await expect(page.locator('#runbookName')).toHaveValue('');
 expect(starts).toBe(0);await assertNoExternalRequests(page);
});
