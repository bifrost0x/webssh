const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test('wide workflow editor keeps steps, destinations and schedule readable and preserves commands',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 const book={id:'editor',name:'Inventory',steps:[{name:'Identity',command:'id',timeout:30},{name:'Storage',command:'df -h',timeout:60}]};
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[book],profiles:Array.from({length:24},(_,i)=>({id:'h'+i,name:'Server '+i,host:'host-'+i+'.invalid',username:'op',group:i<12?'Lab':'Services',auth_type:'key',supported:true}))}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 let saved;await page.route('**/api/automation/runbooks',r=>{saved=r.request().postDataJSON();return r.fulfill({json:{runbook:saved}});});
 await page.goto('/automation');await page.locator('.automation-library-item').getByRole('button',{name:'Edit',exact:true}).click();
 await page.locator('#automationStepDetail textarea').fill('id -un');
 await page.locator('.automation-step').nth(1).getByRole('button',{name:'Edit step',exact:true}).click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -h');
 await page.locator('.automation-step').first().getByRole('button',{name:'Edit step',exact:true}).click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id -un');
 await page.locator('#saveRunbook').click();await expect.poll(()=>saved?.steps[0].command).toBe('id -un');
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:1000});
  for(const [name,selector] of [['steps','[data-workspace-view=editor]'],['targets','[data-workspace-view=targets]'],['schedule','#openSchedule']]){
   await page.locator(selector).click();
   if(name==='steps')expect((await page.locator('.automation-step [data-field=name]').first().boundingBox()).width).toBeGreaterThan(120);
   if(name==='targets'){await page.locator('#target-h0').check();await expect(page.locator('#target-h0')).toBeChecked();}
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await page.screenshot({path:info.outputPath(name+'-'+width+'.png'),animations:'disabled'});
  }
 }
 await page.locator('[data-workspace-view=editor]').click();
 await page.locator('.automation-step.is-active').getByRole('button',{name:'Remove step',exact:true}).click();
 await expect(page.locator('#activeStepEditor .automation-step-detail')).toHaveCount(1);
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -h');
 await page.locator('#saveRunbook').click();await expect.poll(()=>saved?.steps.length).toBe(1);expect(saved.steps[0].command).toBe('df -h');
 await assertNoExternalRequests(page);
});
