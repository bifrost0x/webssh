const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test.afterEach(async({page})=>assertNoExternalRequests(page));

for (const view of ['overviewNavBtn', 'manageProfilesBtn', 'commandLibraryBtn']) {
 test(`Escape in ${view} preserves the hidden terminal tool`, async ({page}) => {
  await page.setViewportSize({width:820,height:800});
  await login(page);
  await page.evaluate(()=>{socket.emit=()=>socket;SessionManager.createSession({session_id:'journey-terminal',host:'lab.example',username:'admin',port:22});SessionManager.assignSessionToPane('journey-terminal',0);SessionManager.switchSession('journey-terminal');});
  await page.locator('#contextWorkspaceLauncher').click();
  await page.locator('#contextNotesTab').click();
  await page.locator('#sessionNotepad').fill('Keep my place across views');
  await page.locator(`#${view}`).click();
  await expect(page.locator('#contextNotesPanel')).toBeHidden();
  await page.locator(`#${view}`).focus();
  await page.keyboard.press('Escape');
  await expect(page.locator(`#${view}`)).toBeFocused();
  await page.locator('#workspaceNavBtn').click();
  await expect(page.locator('#contextNotesPanel')).toBeVisible();
  await expect(page.locator('#sessionNotepad')).toHaveValue('Keep my place across views');
  await page.locator('#sessionNotepad').focus();
  await page.keyboard.press('Escape');
  await expect(page.locator('#contextNotesPanel')).toBeHidden();
  await expect(page.locator('#terminal-journey-terminal .xterm-helper-textarea').first()).toBeFocused();
 });
}
test('returning from a connection attempt keeps the host search',async({page})=>{
 await page.setViewportSize({width:1280,height:720});await login(page,'e2e_admin',{workspace:false});
 await page.locator('#overviewSearch').fill('Usable');
 const connect=page.locator('#overviewHostList .od-connect').first();
 await expect(connect).toHaveAccessibleName('Connect Usable key');
 await expect.poll(()=>page.evaluate(()=>ProfileManager.keysLoaded)).toBe(true);
 await page.evaluate(()=>{const emit=socket.emit.bind(socket);window.__journeyConnects=[];socket.emit=(event,...args)=>{if(event==='ssh_connect'){window.__journeyConnects.push(args[0]);return socket;}return emit(event,...args);};});
 await connect.click();
 await expect.poll(()=>page.evaluate(()=>window.__journeyConnects.length)).toBe(1);
 await page.locator('#overviewNavBtn').click();
 await expect(page.locator('#overviewSearch')).toHaveValue('Usable');
 await expect(connect).toBeFocused();
 await expect(connect).toHaveAccessibleName(/Usable key$/);
 await page.locator('#workspaceNavBtn').click();await page.locator('#overviewNavBtn').click();await expect(page.locator('#overviewTitle')).toBeFocused();
});
for(const width of [390,820,1280,1920])test(`closing tools returns input to the terminal at ${width}px`,async({page},testInfo)=>{
 await page.setViewportSize({width,height:800});await login(page);
 await page.evaluate(()=>{socket.emit=()=>socket;SessionManager.createSession({session_id:'journey-terminal',host:'lab.example',username:'admin',port:22});SessionManager.assignSessionToPane('journey-terminal',0);SessionManager.switchSession('journey-terminal');});
 if(await page.locator('#contextWorkspaceLauncher').isVisible()) await page.locator('#contextWorkspaceLauncher').click();
 if(!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await expect(page.locator('#contextNotesPanel')).toBeVisible();
 if(width<768) await expect(page.locator('#mobileCommandToggle')).toBeHidden();
 await page.locator('#sessionNotepad').fill('Remember this note');
 await page.screenshot({path:testInfo.outputPath('notes-open.png'),animations:'disabled'});
 if(width>=1024){
  await page.locator('#terminal-journey-terminal .xterm-helper-textarea').focus();
  await page.keyboard.press('Escape');
  await expect(page.locator('#contextNotesPanel')).toBeVisible();
  await page.locator('#sessionNotepad').focus();
 }

 await page.keyboard.press('Escape');
 await expect(page.locator('#contextNotesPanel')).toBeHidden();
 if(width<768) await expect(page.locator('#mobileCommandToggle')).toBeVisible();
 await expect(page.locator('#terminal-journey-terminal .xterm-helper-textarea').first()).toBeFocused();
 if(await page.locator('#contextWorkspaceLauncher').isVisible()) await page.locator('#contextWorkspaceLauncher').click();
 if(!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
 await expect(page.locator('#sessionNotepad')).toHaveValue('Remember this note');
 await page.locator('#contextWorkspaceClose').click();
 await expect(page.locator('#terminal-journey-terminal .xterm-helper-textarea').first()).toBeFocused();
});
