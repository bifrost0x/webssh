const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');

test('analytics advances its calendar with unchanged history after midnight',async({page})=>{
 const before=new Date(2026,10,4,23,59,0);
 await page.clock.setFixedTime(before);
 const runs=[{id:'midnight',name:'Evening run',created_at:before.toISOString(),status:'failed',targets:[]}];
 await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs}}));
 await login(page,'e2e_admin',{workspace:false});
 const days=page.locator('.overview-analytics-day');
 await expect(days.last()).toHaveAttribute('data-analytics-focus','2026-11-04');
 // Establish the deduplication signature before moving the browser clock.
 await page.evaluate(()=>window.dispatchEvent(new CustomEvent('automation-runs-updated',{detail:window.WebSSHAutomation.getRunSnapshot()})));
 await page.clock.setFixedTime(new Date(2026,10,5,0,1,0));
 await expect(days.last()).toHaveAttribute('data-analytics-focus','2026-11-05',{timeout:10000});
 await expect(days.last().locator('.overview-analytics-day-count')).toHaveText('0');
 await expect(days.nth(5).locator('.overview-analytics-day-count')).toHaveText('1');
});

test('history refresh preserves keyboard context when a focused run disappears',async({page})=>{
 let runs=[{id:'removed',name:'Removed run',created_at:new Date().toISOString(),status:'failed',targets:[]}];
 await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs}}));
 await login(page,'e2e_admin',{workspace:false});
 const section=page.locator('#overviewAnalytics');
 await section.locator('.overview-analytics-day').last().click();
 await section.locator('.overview-analytics-run').focus();
 runs=[];
 await expect(section.locator('.overview-analytics-empty')).toBeVisible({timeout:10000});
 await expect(section.locator('select')).toBeFocused();
 // Updates must never take focus from navigation outside the chart.
 await page.locator('#overviewNavBtn').focus();
 runs=[{id:'new',name:'New run',created_at:new Date().toISOString(),status:'failed',targets:[]}];
 await expect(section.locator('.overview-analytics-day')).toHaveCount(7,{timeout:10000});
 await expect(page.locator('#overviewNavBtn')).toBeFocused();
});

test('analytics uses safe real run metadata and opens selected-day logs',async({page},testInfo)=>{
 const today=new Date();today.setHours(12,0,0,0);
 const runs=['succeeded','failed','unknown','running'].map((status,index)=>({id:'analytic-'+index,name:'Daily run '+index,created_at:today.toISOString(),status,targets:[{id:'profile-'+index,name:'Synthetic host',host:'synthetic.invalid',port:22,username:'ops',status,steps:[{name:'Step',status,exit_code:status==='succeeded'?0:status==='failed'?1:null,duration:1,stdout:'PRIVATE OUTPUT SENTINEL',stderr:'PRIVATE ERROR SENTINEL',command:'SECRET COMMAND SENTINEL'}]}]}));
 // An inconsistent historical success must never count as confirmed.
 runs.push({...runs[0],id:'unconfirmed',name:'Legacy run',targets:[{...runs[0].targets[0],steps:[{...runs[0].targets[0].steps[0],exit_code:null}]}]});
 let offline=false;
 await page.route('**/api/automation/runs',route=>route.fulfill(offline?{status:503,json:{code:'unavailable'}}:{json:{runs}}));
 await login(page,'e2e_admin',{workspace:false});
 await expect(page.locator('#overviewAnalytics')).toBeVisible();
 const snapshot=await page.evaluate(()=>window.WebSSHAutomation.getRunSnapshot());
 expect(snapshot.runs.map(run=>run.outcome)).toEqual(['succeeded','failed','unknown','other','unknown']);
 for(const run of snapshot.runs)expect(Object.keys(run).sort()).toEqual(['created_at','id','name','outcome','status','targetIds']);
 expect(JSON.stringify(snapshot)).not.toContain('SENTINEL');
 const section=page.locator('#overviewAnalytics');
 await expect(section.locator('.overview-analytics-day')).toHaveCount(7);
 await expect(section.locator('.overview-analytics-legend')).toContainText('Confirmed 1');
 await expect(section.locator('.overview-analytics-legend')).toContainText('Unconfirmed 2');
 await section.locator('select').selectOption('14');
 await expect(section.locator('.overview-analytics-day')).toHaveCount(14);
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await section.scrollIntoViewIfNeeded();
  await page.screenshot({path:testInfo.outputPath('analytics-'+width+'.png'),animations:'disabled'});
  expect(await section.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);
 }
 await section.locator('.overview-analytics-day').last().click();
 await expect(section.locator('.overview-analytics-run')).toHaveCount(5);
 await section.locator('.overview-analytics-run').filter({hasText:'Daily run 1'}).click();
 const exact=page.locator('.automation-run[data-run-id="analytic-1"]');
 await expect(exact).toBeVisible();await expect(exact).toHaveAttribute('open','');
 await expect(exact.locator('.automation-run-diagnostic')).toHaveAttribute('open','');
 await page.setViewportSize({width:1440,height:1000});
 await page.locator('#overviewNavBtn').click();
 offline=true;await expect(section.locator('.overview-analytics-notice')).toBeVisible({timeout:10000});
 await expect(section.locator('.overview-analytics-legend')).toContainText('Confirmed 1');
 offline=false;
 await expect(section.locator('.overview-analytics-notice')).toHaveCount(0,{timeout:10000});
 await assertNoExternalRequests(page);
});

test('empty and authorization-disabled history never fabricate analytics',async({page})=>{
 let mode='empty';
 await page.route('**/api/automation/runs',route=>route.fulfill(mode==='empty'?{json:{runs:[]}}:{status:403,json:{code:'authentication_required'}}));
 await login(page,'e2e_admin',{workspace:false});
 const section=page.locator('#overviewAnalytics');
 await expect(section).toBeVisible();await expect(section.locator('.overview-analytics-empty')).toBeVisible();
 await expect(section.locator('.overview-analytics-day')).toHaveCount(0);
 mode='auth';await expect(section).toBeHidden({timeout:10000});
 const snapshot=await page.evaluate(()=>window.WebSSHAutomation.getRunSnapshot());expect(snapshot.enabled).toBe(false);expect(snapshot.runs).toEqual([]);
 await assertNoExternalRequests(page);
});

test('analytics bars share a baseline and preserve a one-to-six count ratio',async({page})=>{
 const today=new Date();today.setHours(12,0,0,0);const yesterday=new Date(today);yesterday.setDate(yesterday.getDate()-1);
 const runs=Array.from({length:7},(_,i)=>({id:'ratio-'+i,name:'Run '+i,created_at:(i?today:yesterday).toISOString(),status:'failed',targets:[{id:'p',status:'failed',steps:[{status:'failed',exit_code:1}]}]}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs}}));await login(page,'e2e_admin',{workspace:false});
 const bars=page.locator('.overview-analytics-segment');await expect(bars).toHaveCount(2);
 const geometry=await bars.evaluateAll(a=>a.map(e=>{const r=e.getBoundingClientRect();return {height:r.height,bottom:r.bottom};}));
 expect(Math.abs(geometry[0].bottom-geometry[1].bottom)).toBeLessThan(1);
 expect(geometry[1].height/geometry[0].height).toBeCloseTo(6,1);
 await assertNoExternalRequests(page);
});
