const {test,expect}=require('playwright/test');const {login,assertNoExternalRequests}=require('./helpers');
const themes=['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian'];
// Both sides of each layout breakpoint plus a phone, a desktop and an ultrawide screen.
const sizes=[{width:360,height:740},{width:767,height:1024},{width:768,height:1024},{width:1023,height:768},{width:1024,height:768},{width:1920,height:1080},{width:3440,height:1440}];
async function verify(page, label) {
 const state = await page.evaluate(() => {
  const shown = e => e.checkVisibility({visibilityProperty:true}) && !e.closest('[hidden],[aria-hidden="true"]');
  const fields = [...document.querySelectorAll('input:not([type=hidden]),select,textarea')].filter(shown);
  const originalAuth = Boolean(document.querySelector('.auth-container')) && !document.querySelector('link[href*="design-system.css"]');
  const style = getComputedStyle(document.body);
  return {
   overflow: document.documentElement.scrollWidth > innerWidth + 1,
   outside: fields.filter(e => { const b=e.getBoundingClientRect(); return b.left < -.5 || b.right > innerWidth + .5; }).map(e=>e.id),
   font: style.fontFamily,
   originalAuth,
   scene: style.getPropertyValue(originalAuth ? '--theme-background-image-source' : '--theme-scene-image').trim(),
   headings: [...document.querySelectorAll('.auth-header h1,.admin-page-header h2')].filter(shown).map(e=>parseFloat(getComputedStyle(e).fontSize)),
  };
 });
 expect(state.overflow,label).toBe(false);
 expect(state.outside,label).toEqual([]);
 // Authentication deliberately retains the original layout and typeface.
 expect(state.font,label).toContain(state.originalAuth ? 'Inter' : 'WebSSH UI');
 expect(state.scene,label).toContain('url(');
 for (const size of state.headings) {
  expect(size,label).toBeGreaterThanOrEqual(20);
  expect(size,label).toBeLessThanOrEqual(state.originalAuth ? 28 : 26);
 }
}
for(const theme of themes){test(`account surfaces remain coherent in ${theme}`,async({page},testInfo)=>{test.setTimeout(120000);page.setDefaultTimeout(5000);await page.goto('/login');for(const route of ['/login','/register']){await page.goto(route);await expect(page.locator('.auth-header h1')).toBeVisible();await page.evaluate(t=>{localStorage.setItem('websshTheme',t);document.body.dataset.theme=t},theme);for(const size of sizes){await page.setViewportSize(size);await verify(page,route+' '+size.width);if(size.width===1920)await page.screenshot({path:testInfo.outputPath(route.slice(1)+'-'+theme+'.png'),animations:'disabled'});}}
 await login(page,'e2e_admin',{workspace:false});await page.goto('/change-password');await page.evaluate(t=>document.body.dataset.theme=t,theme);for(const size of sizes){await page.setViewportSize(size);await verify(page,'password '+size.width);}await page.goto('/settings');await page.evaluate(t=>document.body.dataset.theme=t,theme);
 const sections=await page.locator('.settings-center-navigation .admin-tab').evaluateAll(buttons=>buttons.map(b=>({value:b.dataset.accountSection||b.dataset.settingsSection||b.dataset.tab,selector:b.dataset.accountSection?'[data-account-section="'+b.dataset.accountSection+'"]':b.dataset.settingsSection?'[data-settings-section="'+b.dataset.settingsSection+'"]':'[data-tab="'+b.dataset.tab+'"]'})));for(const size of sizes){await page.setViewportSize(size);for(const section of sections){if(await page.locator('#settingsMobileSection').isVisible())await page.locator('#settingsMobileSection').selectOption(section.value);else await page.locator(section.selector).first().click();await verify(page,section.value+' '+size.width);}if(size.width===1920)await page.screenshot({path:testInfo.outputPath('admin-'+theme+'.png'),animations:'disabled'});}
 await assertNoExternalRequests(page);
 });}

for(const theme of themes){test(`main workspaces retain all primary views in ${theme}`,async({page},testInfo)=>{
 test.setTimeout(120000);page.setDefaultTimeout(5000);await login(page,'e2e_admin',{workspace:false});await page.evaluate(t=>document.body.dataset.theme=t,theme);
 const views=[['overview','#overviewNavBtn'],['hosts','#manageProfilesBtn'],['files','#fileTransferBtn'],['commands','#commandLibraryBtn'],['workspaces','#workspaceNavBtn']];
 for(const size of sizes){await page.setViewportSize(size);for(const [view,id]of views){if(size.width<768){if(view==='overview'){await page.locator('.app-brand').click();await page.evaluate(t=>document.body.dataset.theme=t,theme);}else await page.locator(`.mobile-dock-item[data-mobile-view="${view}"]`).click();}else await page.locator(id).click();await expect(page.locator('body')).toHaveAttribute('data-primary-workspace',view);await verify(page,view+' '+size.width);if(theme==='glass'&&size.width===1920)await page.screenshot({path:testInfo.outputPath(view+'-'+theme+'.png'),animations:'disabled'});}}
 await assertNoExternalRequests(page);
});}
