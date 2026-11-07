const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('workflow command-set copies, overview log links and reachable stage actions',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 const book={id:'b',name:'Check',steps:[{name:'Identity',command:'id',timeout:30,sudo:false}]};
 const run={id:'recent-run',name:'Latest check',status:'running',created_at:'2026-11-04T09:00:00Z',targets:[{name:'Host A',host:'example.invalid',username:'op',status:'running',steps:[{name:'Identity',status:'running',exit_code:null,duration:null,stdout:'',stderr:''}]}]};
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[book],profiles:Array.from({length:30},(_,i)=>({id:'h'+i,name:'Host '+i,host:'example.invalid',username:'op',group:'Lab',auth_type:'key',supported:true}))}}));
 let unavailable=false;await page.route('**/api/automation/runs',r=>r.fulfill(unavailable?{status:503,json:{code:'unavailable'}}:{json:{runs:[run]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 const writes=[];page.on('request',r=>{if(r.url().includes('/api/automation/')&&r.method()!=='GET')writes.push(r.url());});
 await page.goto('/automation');await expect(page.locator('#useWorkflowTemplate')).toBeVisible();
 await page.evaluate(()=>{Object.defineProperty(window.CommandSetManager,'commandSets',{get:()=>[{id:'own',name:'My sequence',description:'Local sequence',steps:[],resolved_command:'cd /tmp && pwd',parameters:[]}],set:()=>{},configurable:true});window.dispatchEvent(new Event('languageChanged'));});
 await page.locator('#workflowTemplate').selectOption('set:own');await page.locator('#useWorkflowTemplate').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('cd /tmp && pwd');await expect(page.locator('#runbookName')).toHaveValue('My sequence');
 for(const size of [{width:390,height:667},{width:1440,height:768},{width:3440,height:1440}]){
  await page.setViewportSize(size);await page.locator('[data-workspace-view=targets]').click();
  await page.locator('#target-h0').check();
  const button=page.locator('#reviewWorkspace');await button.scrollIntoViewIfNeeded();
  const rect=await button.boundingBox();expect(rect.y+rect.height).toBeLessThanOrEqual(size.height);expect(rect.y).toBeGreaterThanOrEqual(0);
  expect(await button.evaluate(el=>{const r=el.getBoundingClientRect();return el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})).toBe(true);
  for(const theme of ['glass','retro','solar','paper','noir','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank','arctic-ice']){
   await page.evaluate(t=>document.body.dataset.theme=t,theme);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await expect(button).toBeInViewport();
  }
  await page.screenshot({path:info.outputPath('targets-'+size.width+'.png'),animations:'disabled'});
 }
 await page.locator('#overviewNavBtn').click();await expect(page.locator('#overviewAutomation')).toBeVisible();await expect(page.locator('#overviewAutomation')).toContainText('Latest check');await page.locator('#overviewAutomation').screenshot({path:info.outputPath('overview-runs.png')});
 run.status='failed';run.targets[0].steps[0]={name:'Identity',status:'failed',exit_code:1,duration:1,stdout:'diagnostic text',stderr:'failure detail'};
 await expect(page.locator('#overviewAutomation .automation-state')).toHaveText('Failed',{timeout:10000});
 unavailable=true;await expect(page.locator('#overviewAutomationStale')).toBeVisible({timeout:10000});unavailable=false;await expect(page.locator('#overviewAutomationStale')).toBeHidden({timeout:10000});
 await page.locator('.overview-automation-run').click();await expect(page.locator('#auto-runs')).toBeVisible();await expect(page.locator('#runHistory pre').filter({hasText:'failure detail'})).toBeVisible();
 expect(writes).toEqual([]);
});
test('command-set parameter resolution and missing references do not import broken drafts',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[],profiles:[]}}));await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 await page.goto('/automation');await expect(page.locator('#useWorkflowTemplate')).toBeVisible();
 await page.evaluate(()=>{
  Object.defineProperty(window.CommandSetManager,'commandSets',{get:()=>[{id:'param',name:'Parameter check',steps:[],parameters:[{name:'directory'}]},{id:'broken',name:'Missing library entry',steps:[],resolution_error:'missing_command'}],set:()=>{},configurable:true});
  window.socket.timeout=()=>({emit:(event,payload,callback)=>{window.parameterRequest={event,payload};callback(null,{success:true,resolved_command:"ls -- '/tmp/a b'"});}});
  window.dispatchEvent(new Event('languageChanged'));
 });
 await page.locator('#workflowTemplate').selectOption('set:broken');await page.locator('#useWorkflowTemplate').click();await expect(page.locator('#automationError')).toContainText('cannot be imported');await expect(page.locator('#auto-library')).toBeVisible();
 await page.locator('#workflowTemplate').selectOption('set:param');await page.locator('#useWorkflowTemplate').click();await page.locator('#promptInput').fill('/tmp/a b');await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue("ls -- '/tmp/a b'");expect(await page.evaluate(()=>window.parameterRequest)).toEqual({event:'resolve_command_set_parameters',payload:{command_set_id:'param',values:{directory:'/tmp/a b'},use_sudo:false}});
 await page.locator('#backToWorkflows').click();await page.evaluate(()=>{Object.defineProperty(window.CommandSetManager,'commandSets',{get:()=>[],configurable:true});window.dispatchEvent(new Event('languageChanged'));});await expect(page.locator('#workflowTemplate')).toHaveValue('set:param');await expect(page.locator('#workflowTemplateEffect')).toContainText('cannot be imported');
});
