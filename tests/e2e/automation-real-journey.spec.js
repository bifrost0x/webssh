const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test('own command set through real backend SSH run and exact overview history link',async({page},info)=>{
 test.setTimeout(120000);
 await login(page,'e2e_user',{workspace:false});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.locator('#commandLibraryBtn').click();await page.locator('#commandSetsTab').click();await page.locator('#newCommandSetBtn').click();
 const name='Browser SSH workflow '+Date.now();
 await page.locator('#commandSetNameInput').fill(name);await page.locator('#addInlineCommandStepBtn').click();await page.locator('#commandSetSteps textarea').fill('id');await page.locator('#saveCommandSetBtn').click();
 await expect(page.locator('#commandSetManagementList')).toContainText(name);
 await page.locator('#automationNavBtn').click();
 const option=page.locator('#workflowTemplate option').filter({hasText:name});await expect(option).toHaveCount(1);await page.locator('#workflowTemplate').selectOption(await option.getAttribute('value'));await page.locator('#useWorkflowTemplate').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id');
 async function execute(command,status){
  await page.locator('[data-workspace-view=editor]').click();await page.locator('#automationStepDetail textarea').fill(command);await page.locator('[data-workspace-view=targets]').click();await page.locator('#targetGroups').getByLabel('Automation lab (1)',{exact:true}).check();await page.locator('#reviewWorkspace').click();
  await expect(page.locator('#automationPreviewContent pre')).toHaveText(command);await page.locator('#runConfirmation').fill('1');await page.locator('#startRun').click();
  await expect(page.locator('#automationPrompt')).toBeVisible();if(await page.locator('#promptSelect').isVisible()){await page.locator('#promptSelect').selectOption('password');await page.locator('#promptForm button[type=submit]').click();}
  await page.locator('#promptInput').fill('browser-password');await page.locator('#promptForm button[type=submit]').click();
  await expect(page.locator('.automation-run').first()).toContainText(status,{timeout:20000});
  const id=await page.locator('.automation-run').first().getAttribute('data-run-id');return id;
 }
 const success=await execute('id','Succeeded');await page.locator('[data-auto-tab=runbooks]').click();const failure=await execute('fail','Failed');expect(success).not.toBe(failure);
 await page.locator('#runStatusFilter').selectOption('attention');await page.locator('#runSearch').fill('no matching workflow');
 await page.locator('#overviewNavBtn').click();await expect(page.locator('#overviewAutomation')).toBeVisible();
 for(const [id,status] of [[success,'Succeeded'],[failure,'Failed']]){
  await page.locator(`#overviewAutomationRuns button[data-run-id="${id}"]`).click();
  const detail=page.locator(`#runHistory > details[data-run-id="${id}"]`);await expect(detail).toHaveAttribute('open','');await expect(detail.locator('summary').first()).toContainText(status);await expect(detail.locator('pre').filter({hasText:'fixture command completed'})).toBeVisible();await expect(page.locator('#runSearch')).toHaveValue('');await expect(page.locator('#runStatusFilter')).toHaveValue('');
  await page.screenshot({path:info.outputPath(status+'-run.png')});await page.locator('#overviewNavBtn').click();
 }
 expect(await page.evaluate(name=>window.CommandSetManager.commandSets.find(s=>s.name===name).resolved_command,name)).toBe('id');
 expect(errors).toEqual([]);await assertNoExternalRequests(page);
});
test('real parameterized command set imports server-quoted values and cancellation preserves the draft',async({page})=>{
 await login(page,'e2e_user',{workspace:false});
 await page.locator('#commandLibraryBtn').click();await page.locator('#commandSetsTab').click();await page.locator('#newCommandSetBtn').click();
 const name='Parameter import '+Date.now();await page.locator('#commandSetNameInput').fill(name);await page.locator('#commandSetParameterNames').fill('path');await page.locator('#addArgumentCommandStepBtn').click();await page.locator('[data-step-field="argv"]').fill('["ls", "--", "{{path}}"]');await page.locator('#saveCommandSetBtn').click();await expect(page.locator('#commandSetManagementList')).toContainText(name);
 await page.locator('#automationNavBtn').click();const option=page.locator('#workflowTemplate option').filter({hasText:name});await expect(option).toHaveCount(1);await page.locator('#workflowTemplate').selectOption(await option.getAttribute('value'));await page.locator('#useWorkflowTemplate').click();
 const value="a'; $(id)";await page.locator('#promptInput').fill(value);await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue("'ls' -- 'a'\"'\"'; $(id)'");
 await page.locator('#runbookName').fill('Keep my imported draft');await page.locator('#backToWorkflows').click();await page.locator('#useWorkflowTemplate').click();await page.locator('#promptForm button[type=submit]').click();await expect(page.locator('#promptInput')).toBeVisible();await page.locator('#promptCancel').click();await page.locator('[data-auto-tab=runbooks]').click();await expect(page.locator('#runbookName')).toHaveValue('Keep my imported draft');await expect(page.locator('#saveState')).toHaveText('Unsaved changes');await assertNoExternalRequests(page);
});
