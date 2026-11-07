const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
async function seedHosts(page) {
 await page.waitForFunction(()=>ProfileManager.profilesLoaded && JumpHostManager.loaded);
 await page.evaluate(() => {
  const base = ProfileManager.profiles[0];
  JumpHostManager.setJumpHosts([{id: 'summary-gateway', name: 'Nextcloud'}]);
  ProfileManager.setProfiles(Array.from({length: 120}, (_, i) => ({
   ...base, id: 'summary-' + i, name: 'Server ' + i, group: 'Group ' + i % 6,
   jump_host_id: i % 2 ? 'summary-gateway' : null,
  })));
 });
}

test('dashboard summarizes routes at readable size and opens complete editable topology',async({page})=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.setViewportSize({width:1440,height:1000});
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 const seed = () => seedHosts(page);
 await seed();const map=page.locator('#overviewRouteMap');
 await expect(map.locator('.ssh-route-summary')).toHaveCount(2);await expect(map.locator('.ssh-route-host')).toHaveCount(0);
 await expect(map.locator('.ssh-route-summary').first()).toContainText('60');
 await map.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();
 await expect(page.locator('dialog.ssh-map-dialog')).toBeVisible();await expect(map.locator('[data-map-node="direct:hosts"] .ssh-route-host')).toHaveCount(60);
 const handle=map.getByRole('button',{name:'Move Direct connections',exact:true});await handle.focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowDown');const moved=await map.locator('[data-map-node="direct:hosts"]').evaluate(e=>e.style.transform);
 await page.keyboard.press('Escape');await expect(map.locator('.ssh-route-host')).toHaveCount(0);
 await map.getByRole('button',{name:'Expand map',exact:true}).click();await expect(map.locator('[data-map-node="direct:hosts"]')).toHaveAttribute('style',`transform: ${moved};`);
 await map.getByRole('searchbox').fill('Server 119');await expect(map.locator('.ssh-route-host')).toHaveCount(1);await map.getByRole('button',{name:'Inspect Server 119',exact:true}).click();await expect(page.locator('.overview-path-stops')).toContainText('Server 119');await page.locator('.overview-access-heading button').click();await map.getByRole('searchbox').fill('');
 await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);await seed();await map.getByRole('button',{name:'Expand map',exact:true}).click();await expect(map.locator('[data-map-node="direct:hosts"]')).toHaveAttribute('style',`transform: ${moved};`);await page.keyboard.press('Escape');
 await page.setViewportSize({width:390,height:800});await map.locator('.ssh-route-summary').last().click();await expect(map.locator('.ssh-route-host')).toHaveCount(120);await expect(map.getByRole('button',{name:'Show hosts: Nextcloud',exact:true})).toBeInViewport();await page.keyboard.press('Escape');
 expect(errors).toEqual([]);expect(await sshAttempts(page)).toEqual([]);
});

for (const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']) {
 test(`route summary remains readable through size changes in ${theme}`, async ({page}, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page, 'e2e_admin', {workspace: false});
  await installSshConnectTrap(page);
  await seedHosts(page);
  const map = page.locator('#overviewRouteMap');
  await page.evaluate(value => document.body.dataset.theme = value, theme);
  for (const width of [390,1440,3440]) {
   await page.setViewportSize({width, height:1000});
   await map.scrollIntoViewIfNeeded();
   await expect(map.locator('.ssh-route-summary')).toHaveCount(2);
   expect(await map.evaluate(element => element.scrollWidth <= element.clientWidth + 1), theme + ' ' + width).toBe(true);
   expect(await map.locator('.ssh-route-summary').first().evaluate(element => element.getBoundingClientRect().width / element.offsetWidth)).toBeGreaterThanOrEqual(.99);
   if (theme === 'arctic-ice') await page.screenshot({path:info.outputPath('summary-' + width + '.png')});
  }
  expect(errors).toEqual([]);
  expect(await sshAttempts(page)).toEqual([]);
 });
}
