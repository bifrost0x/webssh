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


test('result guidance is available on demand without external notification requests',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const notificationRequests=[];
 page.on('request',request=>{if(request.url().includes('/api/automation/notifications'))notificationRequests.push(request.url());});
 await page.goto('/automation');
 await page.locator('[data-auto-tab="runs"]').click();
 await expect(page.locator('#workflowNotifications')).toHaveCount(0);
 const help=page.locator('.automation-results-help');
 await expect(help.locator('[data-auto-i18n="retentionExplanation"]')).toBeHidden();
 await help.locator('summary').focus();await page.keyboard.press('Enter');
 await expect(help).toContainText('Only the latest 50 runs');
 await expect(help.locator('[data-auto-i18n="stepOutputExplanation"]')).toBeVisible();
 await page.locator('#refreshRuns').click();
 await expect(help).toHaveAttribute('open','');
 expect(notificationRequests).toEqual([]);
});
