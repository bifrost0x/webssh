const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('native workflow shares step and target inspector and preserves hidden selections',async({page},testInfo)=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',route=>route.fulfill({json:{enabled:true,runbooks:[{id:'native',name:'Inventory',steps:[{name:'Identity',command:'uname -a',timeout:30},{name:'Disk',command:'df -hP',timeout:30}]}],profiles:[{id:'a',name:'Alpha',host:'alpha.invalid',username:'op',supported:true,auth_type:'password',credential_status:'ready'},{id:'b',name:'Beta',host:'beta.invalid',username:'op',supported:true,auth_type:'key'}]}}));
 let saved;
 await page.route('**/api/automation/runbooks',async route=>{saved=route.request().postDataJSON();await route.fulfill({json:{runbook:{...saved,id:'native'}}});});
 await page.route('**/api/automation/schedules',route=>route.fulfill({json:{schedules:[]}}));
 await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs:[]}}));
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('uname -a');
 await expect(page.locator('[data-auto-tab="credentials"]')).toHaveCount(0);
 await page.locator('.automation-step-preview').last().click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -hP');
 await page.locator('#automationStepDetail textarea').fill('df -h');
 await page.locator('[data-workspace-view="targets"]').click();
 await page.locator('#target-a').check();
 await page.locator('#targetSearch').fill('Beta');
 await expect(page.locator('#mobileTargetCount')).toHaveText('1');
 await page.locator('[data-workspace-view="editor"]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -h');
 await page.locator('#saveRunbook').click();
 await expect.poll(()=>saved?.steps?.[1]?.command).toBe('df -h');
 expect(saved.steps[0].command).toBe('uname -a');
 for(const [width,height] of [[360,560],[1280,720],[1920,1080],[3440,1440]]){
  await page.setViewportSize({width,height});
  for(const theme of ['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  }
  await page.evaluate(()=>{document.getElementById('automationNativeView').scrollTop=0;document.querySelector('.automation-main').scrollTop=0;});
  await page.screenshot({path:testInfo.outputPath(`native-${width}.png`),fullPage:true});
 }
});

test('command library copies are independent and schedule review uses exact targets',async({page},testInfo)=>{
 await login(page,'e2e_admin',{workspace:false});
 const book={id:'native',name:'Inventory',stop_on_error:true,steps:[{name:'Identity',command:'uname -a',timeout:30}]};
 const target={id:'a',name:'Alpha',host:'alpha.invalid',username:'op',supported:true,auth_type:'password',credential_status:'ready'};
 await page.route('**/api/automation/state',r=>r.fulfill({json:{runbooks:[book],profiles:[target]}}));
 let saved,review,creation,paused=false,reviewAttempts=0;
 await page.route('**/api/automation/runbooks',async r=>{saved={...r.request().postDataJSON(),id:'native'};await r.fulfill({json:{runbook:saved}});});
 await page.route('**/api/automation/schedules/preview',async r=>{review=r.request().postDataJSON();if(++reviewAttempts===1){await r.fulfill({status:400,json:{code:'invalid_schedule'}});return;}await r.fulfill({json:{intent:'schedule-intent',confirmation:'1',expires_in:300,runbook:saved,targets:[target],next_runs:['2026-11-04T08:00:00Z']}});});
 await page.route('**/api/automation/schedules/job/pause',async r=>{paused=true;await r.fulfill({json:{schedule:{}}});});
 await page.route('**/api/automation/schedules',async r=>{if(r.request().method()==='POST'){creation=r.request().postDataJSON();await r.fulfill({json:{schedule:{id:'job'}}});}else await r.fulfill({json:{schedules:[{id:'job',name:'Inventory',runbook_id:'native',profile_ids:['a'],cron:'0 9 * * 1-5',timezone:'Europe/Berlin',enabled:!paused,last_status:paused?'cancelled':'waiting',next_due:'2026-11-04T08:00:00Z'}]}});});
 await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs:[]}}));
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();
 await page.evaluate(()=>{window.CommandLibrary={commands:[{id:'disk',name:'Disk',command:'df',parameters:'-hP'}]};window.WebSSHSecurityUI.createAccountStepUpClient=()=>({authorize:async()=>({grant:'test'}),header:()=>({'X-Test-Grant':'yes'})});});
 await page.evaluate(()=>window.dispatchEvent(new Event('languageChanged')));await page.locator('#editorSourceTitle').click();
 await page.locator('#editorSource').selectOption('command:disk');await page.locator('#addEditorSource').click();
 await expect(page.locator('#promptInput')).toHaveValue('-hP');await page.locator('#promptForm button[type="submit"]').click();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -hP');
 await page.evaluate(()=>window.CommandLibrary.commands[0].command='dangerous-change');
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('df -hP');
 await page.locator('[data-workspace-view="targets"]').click();await page.locator('#target-a').check();
 await page.locator('#openSchedule').click();await page.locator('#scheduleTimezone').fill('Europe/Berlin');await page.locator('#scheduleForm button[type="submit"]').click();
 await expect(page.locator('#automationError')).toContainText('five-field cron');
 await expect(page.locator('#scheduleReview')).not.toBeVisible();
 await page.locator('#scheduleForm button[type="submit"]').click();
 await expect(page.locator('#scheduleReview')).toBeVisible();expect(review.profile_ids).toEqual(['a']);expect(saved.steps[1].command).toBe('df -hP');
 await expect(page.locator('#scheduleReviewContent')).toContainText('Europe/Berlin');
 await page.setViewportSize({width:360,height:560});
 await page.screenshot({path:testInfo.outputPath('schedule-review-360.png'),fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.locator('#scheduleConfirmation').fill('2');await page.locator('#scheduleStartForm button[type="submit"]').click();
 await expect(page.locator('#scheduleReviewError')).toBeVisible();expect(creation).toBeUndefined();
 await page.locator('#scheduleConfirmation').fill('1');await page.locator('#scheduleStartForm button[type="submit"]').click();
 await expect.poll(()=>creation?.intent).toBe('schedule-intent');expect(creation.confirmation).toBe('1');
 await expect(page.locator('#auto-schedules')).toBeVisible();await page.locator('#scheduleList').getByRole('button',{name:'Pause schedule',exact:true}).click();await expect.poll(()=>paused).toBe(true);await expect(page.locator('#scheduleList')).toContainText('Paused');
});

test('globally disabled Automation still permits pausing an owned schedule',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({status:403,json:{code:'disabled'}}));
 let paused=false;
 await page.route('**/api/automation/schedules/job/pause',async r=>{paused=true;await r.fulfill({json:{schedule:{}}});});
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[{id:'job',name:'Paused safely',cron:'0 9 * * *',timezone:'UTC',enabled:!paused,last_status:'unknown',running:!paused}]}}));
 await page.goto('/automation');
 await expect(page.locator('#automationDisabled')).toBeVisible();
 await expect(page.locator('#auto-schedules')).toBeVisible();
 await page.locator('#scheduleList').getByRole('button',{name:'Pause schedule',exact:true}).click();
 await expect.poll(()=>paused).toBe(true);
 await expect(page.locator('#scheduleList')).toContainText('Paused');
 await expect(page.locator('#scheduleList')).toContainText('Unknown - inspect host');
});

test('native main-shell navigation retains draft and document without reloading',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[],profiles:[]}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 let saved;
 await page.route('**/api/automation/runbooks',async r=>{saved=r.request().postDataJSON();await r.fulfill({json:{runbook:{...saved,id:'shell'}}});});
 await page.goto('/');await page.evaluate(()=>{window.nativeNavigationSentinel={id:'same-document'};});
 await page.locator('#automationNavBtn').click();
 await expect(page.locator('#automationNativeView')).toBeVisible();
 await page.locator('[data-auto-tab=runbooks]').click();
 await page.locator('#runbookName').fill('Keep native draft');
 await page.locator('.automation-step [data-field="name"]').fill('Identity');
 await page.locator('#automationStepDetail textarea').fill('uname -a');
 await page.locator('#overviewNavBtn').click();
 await expect(page.locator('#automationNativeView')).toBeHidden();
 await page.locator('#automationNavBtn').click();
 await expect(page.locator('#runbookName')).toHaveValue('Keep native draft');
 expect(await page.evaluate(()=>window.nativeNavigationSentinel?.id)).toBe('same-document');
 await page.locator('#saveRunbook').click();
 await expect.poll(()=>saved?.name).toBe('Keep native draft');expect(saved.steps[0].command).toBe('uname -a');
});

test('calendar controls describe and review exact schedules, preserving advanced expressions on reapproval',async({page},testInfo)=>{
 await login(page,'e2e_admin',{workspace:false});
 const book={id:'calendar',name:'Daily inventory',steps:[{name:'Identity',command:'uname -a',timeout:30}],stop_on_error:true};
 const target={id:'calendar-host',name:'Inventory host',host:'inventory.invalid',username:'op',supported:true,auth_type:'key'};
 const custom='*/17 6-20 * * 1,3,5';
 await page.route('**/api/automation/state',r=>r.fulfill({json:{runbooks:[book],profiles:[target]}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));
 await page.route('**/api/automation/runbooks',r=>r.fulfill({json:{runbook:{...r.request().postDataJSON(),id:'calendar'}}}));
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[{id:'custom-job',runbook_id:'calendar',name:'Advanced inventory',cron:custom,timezone:'Europe/Berlin',profile_ids:['calendar-host'],enabled:false}]}}));
 const previews=[];let immediatePreviews=0;
 await page.route('**/api/automation/preview',r=>{immediatePreviews++;return r.fulfill({status:400,json:{code:'invalid_request'}});});
 await page.route('**/api/automation/schedules/preview',r=>{previews.push(r.request().postDataJSON());return r.fulfill({json:{runbook:book,targets:[target],confirmation:'1',intent:'frozen',next_runs:['2026-11-05T08:20:00Z'],expires_in:300}});});
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();
 await page.locator('[data-workspace-view="targets"]').click();await page.locator('#target-calendar-host').check();
 await page.locator('#openSchedule').click();await page.locator('#scheduleTimezone').fill('Europe/Berlin');
 for(const [frequency,cron] of [['hourly','17 * * * *'],['daily','20 9 * * *'],['weekdays','20 9 * * 1-5'],['weekly','20 9 * * 0'],['monthly','20 9 31 * *']]){
  await page.locator('#scheduleFrequency').selectOption(frequency);
  if(frequency==='hourly')await page.locator('#scheduleMinute').fill('17');else await page.locator('#scheduleTime').fill('09:20');
  if(frequency==='weekly')await page.locator('#scheduleWeekday').selectOption('0');
  if(frequency==='monthly')await page.locator('#scheduleMonthday').fill('31');
  await expect(page.locator('#scheduleCustomField')).toBeHidden();
  await expect(page.locator('#scheduleSummary')).toContainText('Europe/Berlin');
  await expect(page.locator('#scheduleForm button[type=submit]')).toHaveText('Review schedule');
  await page.locator('#scheduleForm button[type=submit]').click();
  await expect(page.locator('#scheduleReview')).toBeVisible();
  expect(previews.at(-1).cron).toBe(cron);expect(previews.at(-1).profile_ids).toEqual(['calendar-host']);
  await expect(page.locator('#scheduleReviewContent')).toContainText('uname -a');
  await page.locator('#closeScheduleReview').click();
 }
 await page.locator('[data-auto-tab="schedules"]').click();
 await page.locator('#scheduleList').getByRole('button',{name:'Review schedule',exact:true}).click();
 await expect(page.locator('#scheduleFrequency')).toHaveValue('custom');await expect(page.locator('#scheduleCron')).toHaveValue(custom);
 await page.locator('#scheduleForm button[type="submit"]').click();await expect(page.locator('#scheduleReview')).toBeVisible();
 expect(previews.at(-1).cron).toBe(custom);expect(previews.at(-1).schedule_id).toBe('custom-job');
 await page.locator('#closeScheduleReview').click();
 await page.evaluate(()=>window.dispatchEvent(new Event('languageChanged')));
 await page.locator('[data-workspace-view="targets"]').click();await page.locator('#openSchedule').click();
 await expect(page.locator('#scheduleCron')).toHaveValue(custom);
 await page.locator('#scheduleForm button[type="submit"]').click();await expect(page.locator('#scheduleReview')).toBeVisible();
 expect(previews.at(-1).schedule_id).toBe('custom-job');await page.locator('#closeScheduleReview').click();
 await page.locator('#scheduleFrequency').selectOption('weekly');await page.locator('#scheduleTime').fill('09:20');
 for(const width of [360,1280,1920,3440]){
  await page.setViewportSize({width,height:width===360?740:1080});
  await expect(page.locator('#scheduleFrequency')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.evaluate(()=>{document.getElementById('automationNativeView').scrollTop=0;document.querySelector('.automation-main').scrollTop=0;});
  await page.screenshot({path:testInfo.outputPath(`schedule-builder-${width}.png`),fullPage:true});
 }
 await page.locator('[data-auto-tab=library]').click();await page.locator('#newRunbook').click();await page.locator('#runbookName').fill('New schedule context');
 await page.locator('.automation-step [data-field="name"]').fill('Identity');await page.locator('#automationStepDetail textarea').fill('uname -a');
 await page.locator('[data-workspace-view=targets]').click();await expect(page.locator('#target-calendar-host')).not.toBeChecked();await page.locator('#target-calendar-host').check();
 await page.locator('#openSchedule').click();await expect(page.locator('#scheduleFrequency')).toHaveValue('weekdays');
 await page.locator('#scheduleForm button[type="submit"]').click();await expect(page.locator('#scheduleReview')).toBeVisible();
 expect(previews.at(-1).schedule_id).toBeUndefined();
 expect(immediatePreviews).toBe(0);
 await page.locator('#closeScheduleReview').click();
 await page.locator('[data-workspace-view="targets"]').click();
 await expect(page.locator('#reviewWorkspace')).toHaveText('Save & review run');
 await page.locator('#reviewWorkspace').click();await expect.poll(()=>immediatePreviews).toBe(1);
});

test('focused stages preserve drafts on interrupted navigation and isolate saved execution targets',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 const books=[{id:'one',name:'One',steps:[{name:'Identity',command:'id',timeout:30}]},{id:'two',name:'Two',steps:[{name:'Disk',command:'df',timeout:30}]}];
 const targets=[{id:'a',name:'Alpha',host:'alpha.invalid',username:'op',supported:true,auth_type:'key'},{id:'b',name:'Beta',host:'beta.invalid',username:'op',supported:true,auth_type:'key'}];
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:books,profiles:targets}}));
 await page.route('**/api/automation/runs',r=>r.fulfill({json:{runs:[]}}));
 await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[{id:'job',name:'Saved snapshot',runbook_id:'one',profile_ids:['a'],enabled:false,cron:'0 9 * * *',timezone:'UTC'}]}}));
 let starts=0,previewRequest;
 await page.route('**/api/automation/start',r=>{starts++;return r.fulfill({json:{run:{id:'run'}}});});
 await page.route('**/api/automation/runbooks',r=>r.fulfill({json:{runbook:{...r.request().postDataJSON(),id:'two'}}}));
 await page.route('**/api/automation/preview',r=>{previewRequest=r.request().postDataJSON();return r.fulfill({json:{intent:'review-run',confirmation:'1',runbook:books[1],targets:[targets[1]]}});});
 await page.route('**/api/automation/schedules/job/preview-run',r=>r.fulfill({json:{intent:'saved-snapshot',confirmation:'1',runbook:{name:'Saved snapshot',steps:[{name:'Original',command:'echo approved-snapshot',timeout:30}]},targets:[targets[0]]}}));
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();
 expect(await page.evaluate(()=>{
  const ids=[...document.querySelectorAll('[id]')].map(element=>element.id);
  return ids.filter((id,index)=>ids.indexOf(id)!==index);
 })).toEqual([]);
 await expect(page.locator('#automationCurrentWorkflow')).toHaveText('One');
 await page.locator('#automationStepDetail textarea').fill('id -un');
 await page.locator('#nextStage').click();await page.locator('#target-a').check();
 await page.locator('#openSchedule').click();await page.locator('#scheduleFrequency').selectOption('weekly');await page.locator('#scheduleTime').fill('16:42');
 await page.evaluate(()=>{for(let i=0;i<6;i++){document.querySelector('[data-workspace-view=editor]').click();document.querySelector('[data-workspace-view=targets]').click();document.querySelector('#openSchedule').click();}});
 await expect(page.locator('#scheduleTime')).toHaveValue('16:42');
 await expect(page.locator('.automation-editor')).toBeHidden();await expect(page.locator('.automation-target-section')).toBeHidden();
 await page.locator('#previousStage').click();await expect(page.locator('#target-a')).toBeChecked();
 await page.locator('#previousStage').click();await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id -un');
 for(const width of [360,1440,3440]){
  await page.setViewportSize({width,height:900});
  for(const theme of ['paper','werkbank','glass']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   for(const selector of ['[data-workspace-view=editor]','[data-workspace-view=targets]','#openSchedule']){
    await page.locator(selector).click();
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   }
  }
  await page.evaluate(()=>Promise.all(document.getElementById('automationScheduleInspector').getAnimations().map(animation=>animation.finished)));
  await page.screenshot({path:info.outputPath(`focused-schedule-${width}.png`),fullPage:true});
 }
 await page.emulateMedia({reducedMotion:'reduce'});
 await page.locator('[data-auto-tab=library]').click();await page.locator('.automation-library-item').filter({hasText:'Two'}).getByRole('button',{name:'Execute now',exact:true}).click();
 await expect(page.locator('#automationPrompt')).toBeVisible();await page.locator('#promptForm button[type=submit]').click();
 await expect(page.locator('#target-a')).not.toBeChecked();await expect(page.locator('#target-b')).not.toBeChecked();
 await page.locator('#target-b').check();await page.locator('#reviewWorkspace').click();
 await expect(page.locator('#runPreview')).toBeVisible();expect(previewRequest.profile_ids).toEqual(['b']);expect(previewRequest.runbook_id).toBe('two');
 await page.locator('#closePreview').click();expect(starts).toBe(0);
 await page.locator('[data-auto-tab=library]').click();await page.locator('.automation-library-item').filter({hasText:'Two'}).getByRole('button',{name:'Execute now',exact:true}).click();
 await expect(page.locator('#runPreview')).toBeVisible();expect(previewRequest.profile_ids).toEqual(['b']);
 await page.locator('#closePreview').click();expect(starts).toBe(0);
 await page.locator('[data-auto-tab=schedules]').click();await page.locator('#scheduleList').getByRole('button',{name:'Execute now',exact:true}).click();
 await expect(page.locator('#runPreview #automationPreviewContent')).toContainText('approved-snapshot');await expect(page.locator('#runPreview #automationPreviewContent')).toContainText('Alpha');await expect(page.locator('#runPreview #automationPreviewContent')).not.toContainText('Beta');
 await page.locator('#closePreview').click();expect(starts).toBe(0);
});
