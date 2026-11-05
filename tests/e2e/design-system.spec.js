const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests,assertRouteGeometry}=require('./helpers');

test.use({viewport:{width:1440,height:900}});
test.afterEach(async({page})=>assertNoExternalRequests(page));

test('Warm Graphite Sand separates cream actions, selection and status across views',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{document.body.dataset.theme='werkbank';});
 await expect.poll(()=>page.locator('body').evaluate(e=>getComputedStyle(e).getPropertyValue('--ws2-accent').trim())).toBe('#d6c3a1');
 const palette=await page.locator('body').evaluate(e=>{const s=getComputedStyle(e);return ['--ws2-accent','--ws2-success','--ws2-warning','--ws2-danger'].map(k=>s.getPropertyValue(k).trim())});
 expect(new Set(palette).size).toBe(4);
 for(const id of ['overviewNavBtn','manageProfilesBtn','commandLibraryBtn','fileTransferBtn']){
   await page.locator(`#${id}`).click();
   await expect(page.locator('#shellConnectBtn')).toHaveCSS('background-color','rgb(39, 37, 30)');
   await expect(page.locator('#shellConnectBtn')).toHaveCSS('color','rgb(242, 232, 213)');
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 await page.locator('#workspaceNavBtn').click();
 if (!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await expect(page.locator('#contextNotesPanel')).toBeVisible();
 await expect(page.locator('#contextNotesTab')).toHaveAttribute('aria-selected','true');
 await expect(page.locator('#contextNotesTab')).toHaveCSS('color','rgb(240, 233, 221)');
});

test('Werkbank shell uses a sand header and readable dark navigation without changing utility orientation',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{document.body.dataset.theme='werkbank';});
 await expect(page.locator('.header').first()).toHaveCSS('background-color','rgb(223, 209, 184)');
 await expect(page.locator('#overviewNavBtn')).toHaveCSS('color','rgb(39, 37, 30)');
 await expect(page.locator('.overview-compact-row .overview-row-title').first()).toBeAttached();
 await page.locator('#accountBtnHeader').click();
 await expect(page.locator('.account-profile-copy > strong')).toHaveCSS('color','rgb(240, 233, 221)');
 await page.locator('#accountBtnHeader').click();
 await page.locator('#workspaceNavBtn').click();
 const tabs=page.locator('#contextWorkspaceTabs');
 await expect(page.locator('#workspaceLayoutPicker > summary')).toHaveCSS('color','rgb(240, 233, 221)');
 await expect(tabs).toHaveCSS('flex-direction','column');
 if (!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await page.locator('#sessionNotepad').fill('Werkbank keeps the note workflow.');
 await page.locator('#contextWorkspaceClose').click();
 await page.locator('#contextNotesTab').click();
 await expect(page.locator('#sessionNotepad')).toHaveValue('Werkbank keeps the note workflow.');
});

test('surface and tool motion have a visible authored duration with an immediate reduced-motion path',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.locator('#manageProfilesBtn').click();
 await expect(page.locator('#profileManagementModal')).toHaveCSS('animation-name','ws-surface-open');
 await page.locator('#workspaceNavBtn').click();
 if (!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await expect(page.locator('#contextNotesPanel')).toHaveCSS('animation-duration','0.32s');
 await page.emulateMedia({reducedMotion:'reduce'});
 await expect(page.locator('#contextNotesPanel')).toHaveCSS('animation-name','none');
 await page.locator('#manageProfilesBtn').click();
 await expect(page.locator('#profileManagementModal')).toHaveCSS('animation-name','none');
});

test('reduced motion keeps selected routes and usable tool panels immediately visible',async({page})=>{
 await page.emulateMedia({reducedMotion:'reduce'});
 await login(page,'e2e_admin',{workspace:false});
 await expect.poll(()=>page.locator('.ssh-route-canvas > svg > path').count()).toBeGreaterThan(0);
 expect(await page.locator('.ssh-route-canvas > svg > path').first().evaluate(e=>getComputedStyle(e).animationName)).toBe('none');
 await page.locator('#workspaceNavBtn').click();
 if (!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await expect(page.locator('#contextNotesPanel')).toBeVisible();
 await expect(page.locator('#contextNotesPanel')).toHaveCSS('animation-name','none');
 await page.locator('#sessionNotepad').fill('Notes remain editable with reduced motion.');
 await expect(page.locator('#sessionNotepad')).toHaveValue('Notes remain editable with reduced motion.');
});

test('route geometry remains aligned after resize and enabled news artwork loads',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await expect.poll(()=>page.locator('.ssh-route-canvas > svg > path').count()).toBeGreaterThan(0);
 await page.setViewportSize({width:1480,height:900});
 await assertRouteGeometry(page);
 await page.locator('#overviewCustomize').click();
 await page.locator('[data-module=news] input[type=checkbox]').check();
 await page.locator('#overviewCustomize').click();
 await expect(page.locator('.overview-news-art')).toHaveCount(2);
 await page.locator('#overviewNews > summary').click();
 for(const art of await page.locator('.overview-news-art').all()){
   await expect(art).toHaveAttribute('src',/\.svg\?v=/);
   await art.scrollIntoViewIfNeeded();
   await expect.poll(()=>art.evaluate(e=>e.complete&&e.naturalWidth>0)).toBe(true);
 }
});

test('selected host and route inspector survive redundant geometry measurements',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 const hosts=page.locator('.overview-compact-row > button');
 await expect.poll(()=>hosts.count()).toBeGreaterThan(1);
 await hosts.first().click();
 const path=page.locator('.overview-path-stops');
 await expect(path).toBeVisible();
 const labels=await path.locator('strong').allTextContents();
 await path.evaluate(el=>{window.__routeInspector=el;window.dispatchEvent(new Event('resize'));});
 await expect.poll(()=>page.evaluate(()=>document.querySelector('.overview-path-stops')===window.__routeInspector)).toBe(true);
 await expect(path.locator('strong')).toHaveText(labels);
 await expect(hosts.first()).toHaveAttribute('aria-pressed','true');
});



test('Paper keeps a readable primary editor action after shared role changes',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{document.body.dataset.theme='paper';});
 await page.locator('#manageProfilesBtn').click();
 await page.locator('#newProfileBtn').click();
 const save=page.locator('#profileEditorForm button[type="submit"]').first();
 await expect(save).toHaveCSS('color','rgb(255, 255, 255)');
 await expect(save).toHaveCSS('background-color','rgb(36, 95, 158)');
});
