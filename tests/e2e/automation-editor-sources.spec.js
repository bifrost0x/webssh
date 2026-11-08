const {test,expect}=require('playwright/test');
const {login}=require('./helpers');

test('editor adds commands, sets and templates without replacing the draft or executing',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/automation');
 await expect(page.locator('#newRunbook')).toBeVisible();
 await page.evaluate(()=>{
  Object.defineProperty(window.CommandSetManager,'commandSets',{get:()=>[{id:'own',name:'My sequence',resolved_command:'cd /tmp && pwd',parameters:[]}],set:()=>{},configurable:true});
  Object.defineProperty(window.CommandLibrary,'commands',{get:()=>[{id:'identity',name:'Identity',command:'id',parameters:''},{id:'param',name:'List path',command:'ls',parameters:'-la /tmp'}],set:()=>{},configurable:true});
  window.dispatchEvent(new Event('languageChanged'));
 });
 const writes=[];page.on('request',r=>{if(r.method()!=='GET'&&r.url().includes('/api/automation/'))writes.push(r.url());});
 await page.locator('#newRunbook').click();
 await page.locator('#runbookName').fill('Preserve my draft');
 // The library picker is part of the editor, not hidden behind a disclosure.
 await expect(page.locator('#editorSource')).toBeVisible();
 await page.locator('#editorSource').selectOption('command:identity');
 await expect(page.locator('#editorSourcePreview code')).toHaveText('id');
 await page.locator('#addEditorSource').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id');
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(1);
 await page.locator('#editorSource').selectOption('set:own');await page.locator('#addEditorSource').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('cd /tmp && pwd');
 await page.locator('#editorSource').selectOption('services');
 const steps=await page.locator('#editorSourcePreview li').count();expect(steps).toBeGreaterThan(0);
 await page.locator('#addEditorSource').click();
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(2+steps);
 await expect(page.locator('#runbookName')).toHaveValue('Preserve my draft');
 await page.locator('#editorSource').selectOption('command:param');await page.locator('#addEditorSource').click();
 await page.locator('#promptInput').fill('-la /var');await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('ls -la /var');
 await page.locator('#addEditorSource').click();await page.locator('#promptCancel').click();
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(3+steps);
 await page.locator('#addEditorSource').click();await page.locator('#promptInput').fill('');
 await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#automationPrompt')).not.toBeVisible();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('ls');
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});await page.locator('#editorSourceTitle').scrollIntoViewIfNeeded();
  await expect(page.locator('#editorSource')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:info.outputPath('editor-sources-'+width+'.png')});
 }
 for(const theme of ['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']){
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  await expect(page.locator('#editorSource')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 // Parameter prompts must not append into a different stage after navigation.
 await page.locator('#addEditorSource').click();
 await page.evaluate(()=>document.querySelector('[data-workspace-view="targets"]').click());
 await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#automationError')).toContainText('Import cancelled');
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(4+steps);
 await page.locator('[data-workspace-view="editor"]').click();
 await page.setViewportSize({width:390,height:667});
 // An entire template must be rejected when it would exceed the limit.
 while(await page.locator('#runbookSteps > .automation-step').count()<19)await page.locator('#addStep').click();
 await page.locator('#editorSource').selectOption('services');await page.locator('#addEditorSource').click();
 await expect(page.locator('#automationError')).toContainText('20 steps');
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(19);
 await page.locator('#editorSource').selectOption('command:identity');await page.locator('#addEditorSource').click();
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(20);
 await page.locator('#addEditorSource').click();
 await expect(page.locator('#runbookSteps > .automation-step')).toHaveCount(20);
 await page.locator('#addEditorSource').scrollIntoViewIfNeeded();
 expect(await page.locator('#addEditorSource').evaluate(el=>{const r=el.getBoundingClientRect();return el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})).toBe(true);
 expect(writes).toEqual([]);
});

test('compact editor has a clear sequence and reachable library on small screens',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});await page.goto('/automation');await page.locator('#newRunbook').click();
 for(const width of [390,1440,3440]){
  await page.setViewportSize({width,height:900});await page.locator('#runbookName').scrollIntoViewIfNeeded();
  // The library picker is open on every width, not folded away.
  await expect(page.locator('#editorSourceTitle')).toBeVisible();
  await expect(page.locator('#editorSource')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:info.outputPath('compact-editor-'+width+'.png')});
 }
});
