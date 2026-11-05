const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
const fs=require('node:fs');
const themes=[...new Set([...fs.readFileSync('static/css/style.css','utf8').matchAll(/body\[data-theme="([^"]+)"\]/g)].map(match=>match[1]).concat('werkbank'))];
for (const code of ['https_required', 'unavailable']) {
 test(`host metadata saves only when credential management is explicitly unavailable over HTTP: ${code}`, async ({page}) => {
  await login(page,'e2e_admin',{workspace:false});
  await page.route('**/api/credentials/state',route=>route.fulfill({status:code==='https_required'?403:503,json:{code}}));
  let mutations=0;
  await page.route('**/api/credentials/intents',route=>{mutations++;return route.fulfill({status:500,json:{code:'unexpected'}});});
  await page.locator('#manageProfilesBtn').click();
  await page.locator('.profile-inspect-button').first().click();
  await page.locator('#profileEditorAuthType').selectOption('password');
  await expect(page.locator('#profileEditorCredential')).not.toHaveAttribute('data-loading','true');
  await page.evaluate(()=>{window.__metadataSaves=[];const original=window.socket.emit.bind(window.socket);window.socket.emit=(event,payload,ack)=>{if(event==='save_profile'){window.__metadataSaves.push(payload);return;}return original(event,payload,ack);};});
  await page.locator('#profileEditorName').fill('Metadata only');
  await page.locator('#profileEditorForm button[type=submit]').first().click();
  expect(await page.evaluate(()=>window.__metadataSaves.length)).toBe(code==='https_required'?1:0);
  expect(mutations).toBe(0);
  if(code==='https_required')await expect(page.locator('.native-host-credentials').filter({has:page.locator('#profileEditorCredential')})).toContainText('requires HTTPS');
  else await expect(page.getByRole('button',{name:'Reload passwords',exact:true})).toBeVisible();
 });
}
test('native password resource provides write-only editing in every user theme',async({page},testInfo)=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,credentials:[{id:'password-test',name:'Test resource for visual verification',username:'operator',version:1,uses:[]}],profiles:[],legacy_vault:false}}));
 await page.evaluate(()=>window.openConnectionAssetManager('passwords'));
 await expect(page.locator('#credentialManagementView')).toBeVisible();
 await page.getByRole('button',{name:'Test resource for visual verification'}).click();
 await expect(page.locator('[data-credential-detail] input[type=password]')).toHaveValue('');
 await expect(page.locator('#credentialManagementView iframe')).toHaveCount(0);
 for(const [width,height]of [[360,560],[768,720],[1280,720],[1920,1080],[3200,1200],[3440,1440],[3840,1600]]){
  await page.setViewportSize({width,height});
  for(const theme of themes){await page.evaluate(theme=>document.body.dataset.theme=theme,theme);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:testInfo.outputPath(`credentials-${theme}-${width}.png`),fullPage:true,animations:'disabled'});}
 }
 await page.locator('#automationNavBtn').click();
 await expect(page.locator('#automationNativeView')).toBeVisible();
 await page.locator('#manageProfilesBtn').click();await expect(page.locator('#profileManagementModal')).toBeVisible();
});
test('saving a changed SSH destination uses the submitted target and cancelled editor fences late acknowledgement',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const profile={id:'password-review',name:'Password review',host:'password.local',port:22,username:'passworduser',auth_type:'password',key_id:null,jump_host_id:null,credential_id:'named',credential_status:'ready'};
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,profiles:[profile],credentials:[{id:'named',name:'Assigned password',uses:[{resource_id:profile.id,valid:true}]}],legacy_vault:false}}));
 let mutations=0;await page.route('**/api/credentials/intents',route=>{mutations++;return route.fulfill({json:{intent:'unexpected'}});});
 await page.evaluate(()=>{window.openConnectionAssetManager('hosts');window.ProfileManager.openEditor('password-review');const original=window.socket.emit.bind(window.socket);window.socket.emit=(event,payload,ack)=>{if(event==='save_profile'){window.__capturedSave={payload};window.__saveAck=ack;return;}return original(event,payload,ack);};});
 await expect(page.locator('#profileEditorCredential')).toHaveValue('named');await page.locator('#profileEditorHost').fill('changed.invalid');await page.locator('#profileEditorForm button[type=submit]').first().click();
 await expect.poll(()=>page.evaluate(()=>Boolean(window.__saveAck))).toBe(true);
 await expect(page.locator('.credential-question')).toHaveCount(0);
 expect(await page.evaluate(()=>window.__capturedSave.payload.host)).toBe('changed.invalid');
 expect(await page.evaluate(()=>window.__capturedSave.payload.id)).toBe(profile.id);
 await page.evaluate(()=>{window.ProfileManager.showManagementList();window.__saveAck({success:true,profile:{...window.__capturedSave.payload,id:'password-review'}});});
 expect(mutations).toBe(0);await expect(page.locator('#profileEditorView')).toHaveClass(/hidden/);
});
test('mobile New password enters detail navigation and Back returns to the list',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,credentials:[],profiles:[],legacy_vault:false}}));await page.setViewportSize({width:360,height:560});await page.evaluate(()=>window.openConnectionAssetManager('passwords'));await page.locator('[data-credential-new]').click();await expect(page.locator('.credential-back')).toBeVisible();await expect(page.locator('[data-credential-list]')).toBeHidden();await page.locator('.credential-back').click();await expect(page.locator('[data-credential-new]')).toBeVisible();
});
test('jump editor refresh preserves a new draft and never carries another resource credential',async({page})=>{
 const state={enabled:true,legacy_vault:false,credentials:[{id:'a',name:'Password A',uses:[]},{id:'b',name:'Password B',uses:[]}],profiles:[{id:'jump:x',credential_id:'a',credential_status:'ready'},{id:'jump:y',credential_id:'b',credential_status:'ready'}]};
 let hold=false,pending=[];await page.route('**/api/credentials/state',route=>{if(hold){pending.push(route);return;}return route.fulfill({json:state});});await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{window.JumpHostManager.load=()=>{};for(const id of ['x','y'])window.JumpHostManager.upsertJumpHost({id,name:'Jump '+id,host:id+'.invalid',port:22,username:'operator',auth_type:'password'});window.openConnectionAssetManager('jump-hosts');window.JumpHostManager.edit('x');});
 await expect(page.locator('#jhCredentialExisting')).toHaveValue('a');await page.locator('#jhCredentialSavePassword').check();await page.locator('#jhCredentialName').fill('old draft');await page.locator('#jhCredentialPassword').fill('old-secret');
 page.once('dialog',dialog=>dialog.accept());hold=true;await page.evaluate(()=>window.JumpHostManager.edit('y'));await expect.poll(()=>pending.length).toBeGreaterThan(0);await expect(page.locator('#jhCredentialPassword')).toHaveValue('');await expect(page.locator('#jhCredentialExisting')).toHaveValue('');
 await page.locator('#jhCredentialSavePassword').check();await page.locator('#jhCredentialName').fill('new draft');await page.locator('#jhCredentialPassword').fill('new-secret');hold=false;await Promise.all(pending.map(route=>route.fulfill({json:state})));await expect(page.locator('#jhCredentialPassword')).toHaveValue('new-secret');await expect(page.locator('#jhCredentialExisting')).toHaveValue('');await expect(page.locator('#jhCredentialSavePassword')).toBeChecked();
});
test('cancelled resource editor cannot resume a late intent into a replacement draft',async({page})=>{
 const profile={id:'password-review',name:'Password review',host:'password.local',port:22,username:'passworduser',auth_type:'password',key_id:null,jump_host_id:null,credential_id:'a',credential_status:'ready'};
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,profiles:[profile],credentials:[{id:'a',name:'Password A',uses:[]},{id:'b',name:'Password B',uses:[]}],legacy_vault:false}}));
 let authorization,assignments=0;await page.route('**/api/credentials/intents',route=>{authorization=route;});await page.route('**/api/credentials/assign',route=>{assignments++;return route.fulfill({json:{enabled:true,credentials:[],profiles:[]}});});
 await login(page,'e2e_admin',{workspace:false});await page.evaluate(()=>{window.openConnectionAssetManager('hosts');window.ProfileManager.openEditor('password-review');const original=window.socket.emit.bind(window.socket);window.socket.emit=(event,payload,ack)=>event==='save_profile'?ack({success:true,profile:{...payload,id:'password-review'}}):original(event,payload,ack);});
 await expect(page.locator('#profileEditorCredential')).toHaveValue('a');await page.locator('#profileEditorCredential').selectOption('b');await page.locator('#profileEditorForm button[type=submit]').first().click();await page.locator('.credential-question').getByRole('button',{name:'Confirm',exact:true}).click();await expect.poll(()=>Boolean(authorization)).toBe(true);
 await page.evaluate(()=>{window.ProfileManager.showManagementList();window.ProfileManager.openEditor('ops-first');});await expect(page.locator('#profileEditorCredential option[value=__new]')).toHaveCount(1);await page.locator('#profileEditorCredential').selectOption('__new');await page.locator('#profileEditorCredentialName').fill('Replacement draft');await page.locator('#profileEditorCredentialPassword').fill('replacement-secret');await authorization.fulfill({json:{intent:'late-intent'}});
 await expect(page.locator('#profileEditorCredentialPassword')).toHaveValue('replacement-secret');expect(assignments).toBe(0);await expect(page.locator('#profileEditorView')).not.toHaveClass(/hidden/);
});
test('direct jump-host selection restores its assigned password reference',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});const id=await page.evaluate(()=>{window.ModalManager.open(document.getElementById('connectionModal'));window.setConnectionAdvancedExpanded(true);window.__restored=[];window.CredentialPicker.restore=input=>window.__restored.push(input);return window.JumpHostManager.jumpHosts[0].id;});await page.locator('#jumpHostSelect').selectOption(id);expect(await page.evaluate(()=>window.__restored)).toContain('jumpHostPasswordInput');
});
test('SSH credential metadata ignores stale editor responses and preserves missing assigned references',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});let pending=[];
 await page.route('**/api/credentials/state',route=>{pending.push(route);});
 await page.locator('#manageProfilesBtn').click();const buttons=page.locator('.profile-inspect-button');await buttons.first().click();await expect.poll(()=>pending.length).toBe(1);
 await page.evaluate(()=>{window.ProfileManager.showManagementList();window.ProfileManager.openEditor('ops-first');});await expect.poll(()=>pending.length).toBe(2);
 const currentId=await page.locator('#profileEditorId').inputValue();await pending[1].fulfill({json:{enabled:true,credentials:[{id:'new',name:'Current password',uses:[]}],profiles:[{id:currentId,credential_id:'missing',credential_status:'missing'}]}});
 await expect(page.locator('#profileEditorCredential option:checked')).toHaveText('Assigned password unavailable');await pending[0].fulfill({json:{enabled:true,credentials:[{id:'old',name:'Stale password',uses:[]}],profiles:[]}});await expect(page.locator('#profileEditorCredential option[value=old]')).toHaveCount(0);await expect(page.locator('#profileEditorCredential')).toHaveValue('missing');
});
test('assignment controls preserve dirty password details even after the target panel opens',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});const item={id:'named',name:'Draft safety',username:'operator',uses:[{resource_id:'existing',name:'Existing host',valid:true}]};let intents=0;
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,credentials:[item],profiles:[{id:'other',kind:'ssh',auth_type:'password',name:'Other host',host:'other.invalid',username:'operator'}]}}));await page.route('**/api/credentials/intents',route=>{intents++;return route.fulfill({json:{intent:'unexpected'}});});
 await page.locator('#manageProfilesBtn').click();await page.locator('#profileManagementModal [data-connection-asset=passwords]').click();await page.locator('[data-credential-list]').getByRole('button',{name:/Draft safety/}).click();const detail=page.locator('[data-credential-detail]');await detail.getByRole('button',{name:'Assign to hosts',exact:true}).click();await expect(detail.locator('[data-credential-target]')).toBeVisible();await detail.locator('[name=password]').fill('preserve-this-draft');await detail.getByRole('checkbox',{name:/Other host/}).check();await detail.getByRole('button',{name:'Apply changes',exact:true}).click();await expect(detail.locator('.native-credential-editor > [role=status]')).toContainText('Save your password changes');await detail.getByRole('button',{name:'Remove assignment',exact:true}).click();await expect(detail.locator('[name=password]')).toHaveValue('preserve-this-draft');expect(intents).toBe(0);
});
test('host checklist preserves hidden selections and reports partial assignment accurately',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const item={id:'named',name:'Batch password',username:'operator',uses:[]};const profiles=['Alpha','Beta'].map((name,index)=>({id:'target-'+index,kind:'ssh',auth_type:'password',name,host:name.toLowerCase()+'.invalid',username:'operator',port:22,credential_id:null}));
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,credentials:[item],profiles,legacy_vault:false}}));
 const intents=[],assigned=[];await page.route('**/api/credentials/intents',route=>{intents.push(route.request().postDataJSON());return route.fulfill({json:{intent:'exact-'+intents.length}});});
 await page.route('**/api/credentials/assign',route=>{const body=route.request().postDataJSON();assigned.push(body);if(assigned.length===2)return route.fulfill({status:409,json:{code:'preview_changed'}});profiles[0].credential_id='named';item.uses=[{resource_id:'target-0',name:'Alpha',valid:true}];return route.fulfill({json:{enabled:true,credentials:[item],profiles}});});
 await page.locator('#manageProfilesBtn').click();await page.locator('#profileManagementModal [data-connection-asset=passwords]').click();await page.locator('[data-credential-list]').getByRole('button',{name:/Batch password/}).click();const detail=page.locator('[data-credential-detail]');await detail.getByRole('button',{name:'Assign to hosts',exact:true}).click();
 const search=detail.locator('[data-credential-target-search]');await search.fill('alpha');await detail.getByRole('checkbox',{name:/Alpha/}).check();await search.fill('beta');await detail.getByRole('checkbox',{name:/Beta/}).check();await expect(detail.locator('.credential-targets')).toContainText('2 hosts selected');await detail.getByRole('button',{name:'Apply changes',exact:true}).click();
 await expect(detail.locator('.credential-targets [role=status]')).toContainText('1 / 2 changes applied');await expect(detail.locator('.credential-targets')).toContainText('1 pending changes');await expect(detail.getByRole('checkbox',{name:/Beta/})).toBeChecked();await search.fill('alpha');await expect(detail.getByRole('checkbox',{name:/Alpha/})).toBeChecked();await expect(detail.locator('.credential-target-list')).toContainText('Currently assigned');
 expect(assigned.map(value=>value.resource_id)).toEqual(['target-0','target-1']);expect(intents.map(value=>value.mutation.target.host)).toEqual(['alpha.invalid','beta.invalid']);await expect(page.locator('.credential-question')).toHaveCount(0);
 await detail.locator('[name=name]').fill('Keep later name');await detail.locator('[name=password]').fill('keep-later-secret');await detail.locator('.credential-targets').getByRole('button',{name:'Cancel',exact:true}).click();await expect(detail.locator('[name=name]')).toHaveValue('Keep later name');await expect(detail.locator('[name=password]')).toHaveValue('keep-later-secret');await expect(detail.getByRole('button',{name:'Alpha',exact:true})).toBeVisible();await expect(detail.getByRole('button',{name:'Delete',exact:true})).toBeDisabled();
});
test('password save locks its submitted fields until the intent finishes',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});const item={id:'named',name:'Save safety',username:'operator',uses:[]};const state={enabled:true,credentials:[item],profiles:[],legacy_vault:false};await page.route('**/api/credentials/state',route=>route.fulfill({json:state}));let pending;
 await page.route('**/api/credentials/intents',route=>{pending=route;});await page.route('**/api/credentials/named',route=>{item.name=route.request().postDataJSON().name;return route.fulfill({json:state});});
 await page.locator('#manageProfilesBtn').click();await page.locator('#profileManagementModal [data-connection-asset=passwords]').click();await page.locator('[data-credential-list]').getByRole('button',{name:/Save safety/}).click();const detail=page.locator('[data-credential-detail]');await detail.locator('[name=name]').fill('Submitted name');await detail.locator('[name=password]').fill('submitted-secret');await detail.getByRole('button',{name:'Save',exact:true}).click();await expect.poll(()=>Boolean(pending)).toBe(true);for(const name of ['name','username','password'])await expect(detail.locator('[name='+name+']')).toBeDisabled();await pending.fulfill({json:{intent:'exact'}});await expect(detail.locator('[name=name]')).toHaveValue('Submitted name');await expect(detail.locator('[name=password]')).toHaveValue('');await expect(detail.locator('[name=name]')).toBeEnabled();
});

test('password save preserves the draft and permits retry after an HTML proxy failure',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const item={id:'proxy-retry',name:'Retry password',username:'operator',uses:[]};
 const state={enabled:true,credentials:[item],profiles:[],legacy_vault:false};
 await page.route('**/api/credentials/state',route=>route.fulfill({json:state}));
 let attempts=0,mutations=0;
 await page.route('**/api/credentials/intents',route=>++attempts===1?route.fulfill({status:502,contentType:'text/html',body:'<html>private proxy detail</html>'}):route.fulfill({json:{intent:'retry-intent'}}));
 await page.route('**/api/credentials/proxy-retry',route=>{mutations++;item.name=route.request().postDataJSON().name;return route.fulfill({json:state});});
 await page.locator('#manageProfilesBtn').click();await page.locator('#profileManagementModal [data-connection-asset=passwords]').click();
 await page.locator('[data-credential-list]').getByRole('button',{name:/Retry password/}).click();
 const detail=page.locator('[data-credential-detail]');
 await detail.locator('[name=name]').fill('Preserved name');await detail.locator('[name=password]').fill('retry-test-secret');
 await detail.getByRole('button',{name:'Save',exact:true}).click();
 await expect(detail.locator('[role=status]')).toContainText('Credentials could not be checked');
 await expect(detail).not.toContainText('private proxy');
 await expect(detail.locator('[name=name]')).toHaveValue('Preserved name');
 await expect(detail.locator('[name=password]')).toHaveValue('retry-test-secret');
 await expect(detail.getByRole('button',{name:'Save',exact:true})).toBeEnabled();expect(mutations).toBe(0);
 await detail.getByRole('button',{name:'Save',exact:true}).click();
 await expect(detail.locator('[name=password]')).toHaveValue('');
 await expect(page.locator('[data-credential-list]')).toContainText('Preserved name');expect(mutations).toBe(1);
});
