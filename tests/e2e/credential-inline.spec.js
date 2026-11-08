const {test,expect}=require('playwright/test');
const path=require('node:path');
async function setup(page){
 await page.route('**/inline-fixture',r=>r.fulfill({contentType:'text/html',body:'<style>.hidden{display:none}</style><meta name="app-root" content=""><div id="connectionModal" class="show"><form><input id="hostInput" value="host"><input id="portInput" value="22"><input id="usernameInput" value="alice"><select id="authTypeSelect"><option value="password">Password</option><option value="saved-password">Saved password</option><option value="key">SSH key</option></select><div id="passwordGroup"><input id="passwordInput" type="password" required></div></form></div>'}));
 await page.route('**/api/credentials/state',r=>r.fulfill({json:{enabled:true,credentials:[{id:'named',name:'Lab password',uses:[]}],profiles:[]}}));
 let intents=0;await page.route('**/api/credentials/intents',r=>r.fulfill({json:{intent:'target-intent-'+(++intents)}}));
 await page.goto('/inline-fixture');
 await page.evaluate(()=>{window.ProfileManager={selectedProfileId:null};});
 for(const name of ['native-credentials.js','credential-picker.js']) await page.addScriptTag({path:path.resolve(__dirname,'../../static/js',name)});
 await page.evaluate(()=>window.CredentialPicker.install());
}
test('inline saved mode preserves manual draft and authorizes exact destination at submission',async({page})=>{
 await setup(page);let requests=[];
 await page.route('**/api/credentials/authorize-target',r=>{requests.push(r.request().postDataJSON());return r.fulfill({json:{credential_target_token:'token-'+requests.length}});});
 await page.locator('#passwordInput').fill('manual-draft');await page.locator('#authTypeSelect').selectOption('saved-password');await page.locator('#savedPasswordSelect').selectOption('named');
 await expect(page.getByRole('button',{name:'Use saved password'})).toHaveCount(0);expect(requests).toHaveLength(0);
 expect(await page.evaluate(()=>window.CredentialPicker.resolve('passwordInput'))).toBe('named');expect(requests[0]).toEqual({credential_id:'named',target:{host:'host',port:22,username:'alice',auth_type:'password',jump_host_id:null},confirm_target:true,intent:'target-intent-1'});
 await page.evaluate(()=>window.CredentialPicker.resolve('passwordInput'));expect(requests).toHaveLength(2);
 await page.locator('#hostInput').fill('different');expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();await expect(page.locator('#savedPasswordSelect')).toHaveValue('');
 await page.locator('#authTypeSelect').selectOption('password');await expect(page.locator('#passwordInput')).toHaveValue('manual-draft');await expect(page.locator('#passwordInput')).toBeEnabled();
});
test('destination changes during authorization cannot reuse a pending token',async({page})=>{
 await setup(page);let pending;await page.route('**/api/credentials/authorize-target',r=>{pending=r;});
 await page.locator('#authTypeSelect').selectOption('saved-password');await page.locator('#savedPasswordSelect').selectOption('named');
 await page.evaluate(()=>{window.result=window.CredentialPicker.resolve('passwordInput').then(()=> 'accepted',e=>e.name);});
 await expect.poll(()=>Boolean(pending)).toBe(true);await page.locator('#hostInput').fill('changed');await pending.fulfill({json:{credential_target_token:'obsolete'}});
 expect(await page.evaluate(()=>window.result)).toBe('AbortError');expect(await page.evaluate(()=>window.CredentialPicker.token('passwordInput'))).toBeNull();
});
test('rotation or revoked target authorization fails closed and preserves the selected name',async({page})=>{
 await setup(page);await page.route('**/api/credentials/authorize-target',r=>r.fulfill({status:409,json:{code:'preview_changed'}}));
 await page.locator('#authTypeSelect').selectOption('saved-password');await page.locator('#savedPasswordSelect').selectOption('named');
 expect(await page.evaluate(()=>window.CredentialPicker.resolve('passwordInput').then(()=>false,()=>true))).toBe(true);
 expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();await expect(page.locator('#savedPasswordSelect')).toHaveValue('named');
});
test('saved host restores its assigned named entry without silently changing assignment',async({page})=>{
 await setup(page);
 await page.route('**/api/credentials/state',r=>r.fulfill({json:{enabled:true,profiles:[{id:'profile',host:'host',port:22,username:'alice',auth_type:'password',jump_host_id:null}],credentials:[{id:'named',name:'Lab password',uses:[{resource_id:'profile',valid:true}]}]}}));
 await page.evaluate(async()=>{window.ProfileManager.selectedProfileId='profile';await window.CredentialPicker.restore('passwordInput');});
 await expect(page.locator('#authTypeSelect')).toHaveValue('saved-password');await expect(page.locator('#savedPasswordSelect')).toHaveValue('named');await expect(page.locator('#passwordInput')).toBeDisabled();
 expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();
});
test('deferred blur change for the already reviewed destination keeps the selected password',async({page})=>{
 await setup(page);
 await page.locator('#usernameInput').fill('reviewed-user');
 await page.locator('#authTypeSelect').selectOption('saved-password');
 await page.locator('#savedPasswordSelect').selectOption('named');
 // Native change arrives on blur after input has already invalidated the old target.
 await page.locator('#hostInput').focus();
 await expect(page.locator('#savedPasswordSelect')).toHaveValue('named');
 await page.locator('#usernameInput').fill('new-user');
 await expect(page.locator('#savedPasswordSelect')).toHaveValue('');
});
