const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test('workflow examples explain scope and load independent editable drafts without execution',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[],profiles:[]}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 const writes=[];page.on('request',r=>{if(r.url().includes('/api/automation/')&&r.method()!=='GET')writes.push(r.url());});
 await page.goto('/automation');await expect(page.locator('.automation-start-copy')).toContainText('SSH commands');
 await page.evaluate(()=>new Promise(resolve=>{socket.once('command_sets_list',resolve);CommandSetManager.load();}));
 const ownSets=await page.evaluate(()=>CommandSetManager.commandSets.map(set=>({id:'set:'+set.id,title:set.name})));
 await expect.poll(()=>page.locator('#workflowTemplate option').evaluateAll(options=>options.filter(option=>option.value.startsWith('set:')).map(option=>({id:option.value,title:option.textContent})))).toEqual(ownSets);
 const options=await page.locator('#workflowTemplate option').evaluateAll(options=>options.map(o=>({id:o.value,title:o.textContent})));
 const templates=options.filter(item=>!item.id.startsWith('set:'));
 expect(templates).toHaveLength(23);
 expect(options.filter(item=>item.id.startsWith('set:'))).toEqual(ownSets);
 for(const item of templates){
  await page.locator('#workflowTemplate').selectOption(item.id);
  await expect(page.locator('#workflowTemplateRequirements')).not.toBeEmpty();
  await page.locator('#useWorkflowTemplate').click();
  if(await page.locator('#automationPrompt').isVisible())await page.locator('#promptForm button[type=submit]').click();
  await expect(page.locator('#runbookName')).toHaveValue(item.title);
  await expect(page.locator('#automationStepDetail textarea')).not.toHaveValue('');
  await expect(page.locator('#deleteRunbook')).toBeHidden();
  await expect(page.locator('#saveState')).toHaveText('Unsaved changes');
  await page.locator('#backToWorkflows').click();
 }
 expect(writes).toEqual([]);
 await page.locator('#workflowTemplate').selectOption('apt-upgrade');await expect(page.locator('#workflowTemplateEffect')).toContainText('Changes');
 await page.locator('#useWorkflowTemplate').click();await page.locator('#promptCancel').click();await expect(page.locator('#auto-library')).toBeVisible();
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:1000});
  for(const theme of ['glass','paper','werkbank','arctic-ice']){
   await page.evaluate(t=>document.body.dataset.theme=t,theme);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  }
  await page.screenshot({path:info.outputPath('workflow-start-'+width+'.png'),animations:'disabled'});
 }
 await page.evaluate(()=>window.i18n.setLanguage('de'));
 await expect(page.locator('#useWorkflowTemplate')).toHaveText('Vorlage im Editor öffnen');
 await expect(page.locator('#workflowTemplate')).toHaveValue('apt-upgrade');
 expect(writes).toEqual([]);await assertNoExternalRequests(page);
});
