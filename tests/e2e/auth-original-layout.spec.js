const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('original authentication layout retains responsive forms and authentication',async({page},info)=>{
 test.setTimeout(120000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 for(const route of ['/login','/register','/change-password']) {
  if(route==='/change-password')await login(page,'e2e_admin',{workspace:false});
  await page.goto(route);await expect(page.locator('.auth-header h1')).toBeVisible();
  await expect(page.locator('.auth-context-footer')).not.toHaveText('brand.tagline');
  if(route==='/register')await expect(page.locator('.auth-form-eyebrow')).not.toHaveText('auth.registration');
  await expect(page.locator('link[href*="account-ui.css"],link[href*="design-system.css"]')).toHaveCount(0);
  for(const form of await page.locator('form[method=POST],form[method=post]').all())await expect(form.locator('input[name="csrf_token"]')).toHaveCount(1);
  for(const theme of ['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']) {
   await page.evaluate(t=>document.body.dataset.theme=t,theme);
   for(const width of [390,1440,3440]) {
    await page.setViewportSize({width,height:900});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
    for(const field of await page.locator('input:not([type=hidden]):visible').all()) {
     expect(await field.evaluate(e=>{const r=e.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth;})).toBe(true);
    }
    if(theme==='glass'&&width!==1440)await page.screenshot({path:info.outputPath(route.slice(1)+'-'+width+'.png'),animations:'disabled'});
   }
  }
  if(route==='/register') {
   await page.locator('#username').fill('layout_check');await page.locator('#password').fill('TemporaryExample123!');await page.locator('#confirm_password').fill('DifferentExample123!');await page.locator('#confirm_password').blur();
   await expect(page.locator('#confirm_password')).toHaveAttribute('aria-invalid','true');
  }
 }
 expect(errors).toEqual([]);
});
