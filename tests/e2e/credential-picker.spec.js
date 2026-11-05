const {test,expect}=require('playwright/test');
const path=require('node:path');
async function setup(page,{disabled=false}={}){
 const state={enabled:!disabled,credentials:[{id:'named',name:'Lab password',username:'alice',uses:[]}],profiles:[],legacy_vault:false};
 await page.route('**/api/credentials/state',route=>route.fulfill({json:state}));
 await page.route('**/api/credentials/intents',route=>route.fulfill({json:{intent:'intent'}}));
 await page.route('**/api/account/step-up/intents',route=>route.fulfill({json:{grant:'test-grant'}}));
 await page.route('**/api/credentials/assign',route=>route.fulfill({json:state}));
 await page.route('**/native-fixture',route=>route.fulfill({contentType:'text/html',body:'<meta name="app-root" content=""><div id="connectionModal" class="show"><form><input id="hostInput" value="host"><input id="portInput" value="22"><input id="usernameInput" value="alice"><input id="passwordInput" type="password" required></form></div>'}));
 await page.goto('/native-fixture');
 await page.evaluate(()=>{window.ProfileManager={selectedProfileId:'host-1'};});
 for(const file of ['security-ui.js','native-credentials.js','credential-picker.js'])await page.addScriptTag({path:path.resolve(__dirname,'../../static/js',file)});
 await page.evaluate(()=>window.CredentialPicker.install());
}
test('native chooser preserves cancelled drafts and binds selected reference to exact destination',async({page})=>{
 await setup(page);await page.locator('#passwordInput').fill('manual-draft');const use=page.getByRole('button',{name:'Use saved password',exact:true});await use.click();
 await expect(page.locator('iframe')).toHaveCount(0);await expect(page.locator('dialog')).toContainText('alice@host:22');await page.locator('dialog').getByRole('button',{name:'Cancel'}).click();await expect(page.locator('#passwordInput')).toHaveValue('manual-draft');await expect(use).toBeFocused();
 await use.click();await page.getByRole('button',{name:'Lab password'}).click();await expect(page.locator('dialog')).toHaveCount(0);await expect(page.locator('#passwordInput')).toBeDisabled();expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBe('host-1');
 await page.locator('#hostInput').fill('other');expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();await expect(page.locator('#passwordInput')).toBeEnabled();
});
test('policy disable and failed assignment preserve manual password',async({page})=>{
 await setup(page);await page.route('**/api/credentials/assign',route=>route.fulfill({status:403,json:{error:'denied'}}));await page.locator('#passwordInput').fill('draft');await page.getByRole('button',{name:'Use saved password'}).click();await page.getByRole('button',{name:'Lab password'}).click();await expect(page.locator('dialog [role="status"]')).toContainText('could not be saved');await page.keyboard.press('Escape');await expect(page.locator('#passwordInput')).toHaveValue('draft');expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();
});
test('cancelled pending assignment cannot select after dismissal',async({page})=>{
 await setup(page);let pending;await page.route('**/api/credentials/assign',route=>{pending=route;});await page.locator('#passwordInput').fill('draft');await page.getByRole('button',{name:'Use saved password'}).click();await page.getByRole('button',{name:'Lab password'}).click();await expect.poll(()=>Boolean(pending)).toBe(true);await page.keyboard.press('Escape');await pending.fulfill({json:{enabled:true,credentials:[]}});await expect(page.locator('#passwordInput')).toHaveValue('draft');expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();
});
test('administrator-disabled password storage preserves the manual connection draft',async({page})=>{
 await setup(page,{disabled:true});await page.locator('#passwordInput').fill('draft');await page.getByRole('button',{name:'Use saved password'}).click();await expect(page.locator('.credential-picker-controls [role=status]')).toContainText('disabled');await expect(page.locator('dialog')).toHaveCount(0);await expect(page.locator('#passwordInput')).toHaveValue('draft');
});
test('assigned profile metadata restores saved authentication without another assignment',async({page})=>{
 await setup(page);await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,profiles:[{id:'host-1',host:'host',port:22,username:'alice',auth_type:'password',jump_host_id:null}],credentials:[{id:'named',uses:[{resource_id:'host-1',valid:true}]}]}}));
 await page.evaluate(()=>window.CredentialPicker.restore('passwordInput'));await expect(page.locator('#passwordInput')).toBeDisabled();expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBe('host-1');await page.getByRole('button',{name:'Enter manually'}).click();await expect(page.locator('#passwordInput')).toBeEnabled();expect(await page.evaluate(()=>window.CredentialPicker.get('passwordInput'))).toBeNull();
});
