const {test,expect}=require('playwright/test');
const {login}=require('./helpers');

test('source search preserves selected source and draft, without execution',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.goto('/automation');await page.locator('#newRunbook').click();
 await page.evaluate(()=>{
  Object.defineProperty(window.CommandLibrary,'commands',{get:()=>[{id:'identity',name:'Identity',command:'id',parameters:''},{id:'space',name:'Disk space',command:'df',parameters:'-h'}],configurable:true});
  window.dispatchEvent(new Event('languageChanged'));
 });
 const writes=[];page.on('request',request=>{if(request.method()!=='GET'&&request.url().includes('/api/automation/'))writes.push(request.url());});
 await page.locator('#runbookName').fill('Keep this draft');
 await page.locator('#editorSourceSearch').fill('DISK');
 await expect(page.locator('#editorSource option[value="command:space"]')).toHaveCount(1);
 await expect(page.locator('#editorSource option[value="command:identity"]')).toHaveCount(0);
 await page.locator('#editorSource').selectOption('command:space');
 await page.locator('#editorSourceSearch').fill('Identity');
 await expect(page.locator('#editorSource')).toHaveValue('command:space');
 await expect(page.locator('#editorSourcePreview code')).toHaveText('df -h');
 await expect(page.locator('#editorSource option[value="command:identity"]')).toHaveCount(1);
 await page.locator('#editorSource').selectOption('command:identity');
 await page.locator('#addEditorSource').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id');
 await expect(page.locator('#runbookName')).toHaveValue('Keep this draft');
 await page.locator('#editorSourceSearch').fill('');
 await expect(page.locator('#editorSource optgroup')).toHaveCount(3);
 expect(writes).toEqual([]);
});


test('account alert opt-in is visible and unavailable delivery is explained on desktop and mobile',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});await page.goto('/automation');
 await page.locator('[data-auto-tab="runs"]').click();
 await expect(page.locator('#workflowNotifications')).not.toBeChecked();
 await expect(page.locator('#workflowNotificationStatus')).toContainText('unavailable');
 const saved=page.waitForResponse(response=>response.url().endsWith('/api/automation/notifications')&&response.request().method()==='POST');
 await page.locator('#workflowNotifications').check();await saved;
 await expect(page.locator('#workflowNotifications')).toBeChecked();
 await expect(page.getByText('Only the latest 50 runs', {exact:false})).toBeVisible();
 await expect(page.getByText('Step output appears after the step completes.',{exact:false})).toBeVisible();
 for (const width of [390,1440]) {
  await page.setViewportSize({width,height:900});
  await page.locator('#workflowNotifications').scrollIntoViewIfNeeded();
  await expect(page.locator('#workflowNotifications')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:info.outputPath('workflow-alerts-'+width+'.png')});
 }
 await page.locator('#workflowNotifications').uncheck();
});
