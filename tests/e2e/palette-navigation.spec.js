const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
async function open(page){await login(page,'e2e_admin',{workspace:false});await page.evaluate(()=>ProfileManager.setProfiles(Array.from({length:40},(_,i)=>({id:`lab-${i}`,name:`Lab ${String(i).padStart(2,'0')}`,host:`lab-${i}.example`,username:'admin'}))));await page.keyboard.press('Control+k');await page.locator('#commandPaletteInput').fill('Lab');}
test.afterEach(async({page})=>assertNoExternalRequests(page));
for(const width of [390,1280])test(`palette keyboard selection stays visible at ${width}px`,async({page},testInfo)=>{
 await page.setViewportSize({width,height:740});await open(page);
 const input=page.locator('#commandPaletteInput');
 for(let i=0;i<30;i++)await input.press('ArrowDown');
 const active=page.locator('.palette-item[aria-selected="true"]');
 await expect(active).toHaveAttribute('data-palette-id','lab-30');
 await expect(active).toBeInViewport();
 const inside=await active.evaluate(el=>{const a=el.getBoundingClientRect(),b=el.parentElement.getBoundingClientRect();return a.top>=b.top&&a.bottom<=b.bottom;});expect(inside).toBe(true);
 await expect(input).toBeFocused();
 await page.screenshot({path:testInfo.outputPath('palette-selected.png'),animations:'disabled'});
 await expect(input).toHaveAttribute('aria-activedescendant',await active.getAttribute('id'));
 await input.fill('no such host');await expect(page.locator('.palette-empty')).toBeVisible();
 await expect(input).not.toHaveAttribute('aria-activedescendant',/.+/);
 await input.fill('Lab');await expect(page.locator('.palette-item.active')).toHaveAttribute('data-palette-id','lab-0');
 await expect(page.locator('.palette-item.active')).toBeInViewport();
});
test('palette retains the selected host when inventory updates and launches that host',async({page})=>{
 await open(page);const input=page.locator('#commandPaletteInput');await input.press('ArrowDown');
 await expect(page.locator('.palette-item.active')).toHaveAttribute('data-palette-id','lab-1');
 await page.evaluate(()=>{window.__paletteLaunches=[];window.launchProfileForPane=id=>window.__paletteLaunches.push(id);ProfileManager.setProfiles([{id:'new-lab',name:'Lab 00 new',host:'new.example'},...ProfileManager.profiles]);});
 await expect(page.locator('.palette-item.active')).toHaveAttribute('data-palette-id','lab-1');
 await input.press('Enter');expect(await page.evaluate(()=>window.__paletteLaunches)).toEqual(['lab-1']);
});

test('choosing a live session from another workspace reveals and focuses its terminal',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>{const emit=socket.emit.bind(socket);socket.emit=()=>socket;SessionManager.createSession({session_id:'palette-live',host:'palette.example',username:'admin',port:22});SessionManager.assignSessionToPane('palette-live',0);socket.emit=emit;});
 await page.locator('#fileTransferBtn').click();await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','files');
 await page.keyboard.press('Control+k');await page.locator('#commandPaletteInput').fill('palette.example');
 await expect(page.locator('.palette-item[data-palette-kind="session"]')).toHaveCount(1);
 await page.locator('#commandPaletteInput').press('Enter');
 await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','workspaces');
 await expect(page.locator('#terminal-palette-live')).toBeVisible();
 await expect(page.locator('#terminal-palette-live .xterm-helper-textarea').first()).toBeFocused();
});


test('removing the selected search result requires a new selection before Enter can launch',async({page})=>{
 await open(page);const input=page.locator('#commandPaletteInput');await input.press('ArrowDown');
 await page.evaluate(()=>{window.__paletteLaunches=[];window.launchProfileForPane=id=>window.__paletteLaunches.push(id);ProfileManager.setProfiles(ProfileManager.profiles.filter(p=>p.id!=='lab-1'));});
 await input.press('Enter');expect(await page.evaluate(()=>window.__paletteLaunches)).toEqual([]);
 await expect(input).not.toHaveAttribute('aria-activedescendant',/.+/);
 await page.evaluate(()=>window.dispatchEvent(new Event('profile-list-change')));
 await input.press('Enter');expect(await page.evaluate(()=>window.__paletteLaunches)).toEqual([]);
 await input.press('ArrowDown');await input.press('Enter');expect(await page.evaluate(()=>window.__paletteLaunches)).toEqual(['lab-0']);
});
