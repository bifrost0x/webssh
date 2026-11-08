const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.use({viewport:{width:1280,height:720}});
test.afterEach(async({page})=>assertNoExternalRequests(page));
test('quick connection follows destination identity authentication order and exposes errors',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.locator('#shellConnectBtn').click();
 const ids=await page.locator('#connectionDetailsCard input:not([type=hidden]),#connectionDetailsCard select').evaluateAll(nodes=>nodes.map(n=>n.id));
 expect(ids.indexOf('hostInput')).toBeLessThan(ids.indexOf('usernameInput'));expect(ids.indexOf('usernameInput')).toBeLessThan(ids.indexOf('authTypeSelect'));expect(ids.indexOf('authTypeSelect')).toBeLessThan(ids.indexOf('passwordInput'));
 for(const id of ['hostInput','portInput','usernameInput','passwordInput']){const f=page.locator('#'+id);await expect(f).toHaveAttribute('aria-describedby',id.replace('Input','Hint'));}
 await page.locator('#hostInput').fill('bad host');await expect(page.locator('#hostInput')).toHaveAttribute('aria-invalid','true');await expect(page.locator('#hostHint')).not.toBeEmpty();await page.locator('#hostInput').fill('server.example');await expect(page.locator('#hostInput')).not.toHaveAttribute('aria-invalid','true');
 await expect(page.locator('#passwordInput')).toBeInViewport({ratio:1});
 await expect(page.locator('#hostInput')).toHaveAttribute('spellcheck','false');
});
test('settings switches name the actual decision instead of enabled',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.goto('/settings');await page.locator('[data-account-section="preferences"]').click();await expect(page.locator('#confirmSessionCloseInput')).toHaveAccessibleName('Ask before closing a session');
 await page.locator('[data-settings-section="authentication"]').click();await expect(page.locator('#githubAuthEnabled')).toHaveAccessibleName('Enable GitHub sign-in');await expect(page.locator('#githubAuthAutoProvision')).toHaveAccessibleName('Automatically provision users');
 await page.locator('[data-settings-section="registration"]').click();await expect(page.locator('#settingRegistration')).toHaveAccessibleName('Allow self-registration');
});
test('authentication and platform choices have group names without misleading required state',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.evaluate(()=>window.openConnectionAssetManager('jump-hosts'));await page.locator('#jumpResourceNew').click();await expect(page.getByRole('group',{name:'Authentication Method',exact:true})).toBeVisible();await expect(page.locator('#jumpHostsList')).not.toContainText('*');
 await page.locator('#commandLibraryBtn').click();await page.locator('#addCommandBtn').click();await expect(page.getByRole('group',{name:'Operating systems',exact:true})).toBeVisible();await expect(page.locator('#commandFormCommand')).toHaveAttribute('spellcheck','false');
});

test('workspace entry fields keep accessible names after placeholder text disappears',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 for(const id of ['mobileInput','terminalSearchInput','commandPaletteInput']){await expect(page.locator('#'+id)).toHaveAttribute('aria-label',/\S/);}
 await expect(page.locator('#broadcastInput')).toHaveAttribute('aria-labelledby','broadcastAudienceLabel');
});

test('key metadata follows the selected interface language',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.evaluate(()=>window.openConnectionAssetManager('keys'));await page.evaluate(()=>window.i18n.setLanguage('de'));await expect(page.locator('#keysList .key-date').first()).toContainText('Hochgeladen:');await page.evaluate(()=>window.i18n.setLanguage('en'));await expect(page.locator('#keysList .key-date').first()).toContainText('Uploaded:');
});

test('password feedback stays attached to its field and clears after correction',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await page.goto('/change-password');await expect(page.locator('#new_password')).toHaveAttribute('aria-describedby','newPasswordHint');await page.locator('#new_password').fill('short');await expect(page.locator('#new_password')).toHaveAttribute('aria-invalid','true');await page.locator('#new_password').fill('long-enough-example');await expect(page.locator('#new_password')).not.toHaveAttribute('aria-invalid','true');
});
