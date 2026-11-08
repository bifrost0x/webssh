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
 await seed();const map=page.locator('#overviewRouteMap'),topology=page.locator('#odTopology'),dialog=page.locator('dialog.ssh-map-dialog');
 await expect(topology).toHaveAttribute('data-mode','graph');
 await expect(topology).toHaveAttribute('aria-label','120 hosts, 60 direct, 1 jump hosts, 0 with an open session');
 await expect(topology.locator('.od-hub')).toHaveCount(2);await expect(topology.locator('.od-hub-label')).toHaveText(['Direct','Nextcloud']);
 // Large hubs show a readable sample and the rest as a count.
 await expect(topology.locator('.od-node')).toHaveCount(24);await expect(topology.locator('.od-hub')).toContainText(['+48','+48']);
 await page.locator('#overviewOpenMap').click();await expect(dialog).toBeVisible();
 await map.getByRole('button',{name:'Show hosts: Direct SSH',exact:true}).click();
 await expect(map.locator('[data-map-node="direct:hosts"] .ssh-route-host')).toHaveCount(60);
 const handle=map.getByRole('button',{name:'Move Direct connections',exact:true});await handle.focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowDown');const moved=await map.locator('[data-map-node="direct:hosts"]').evaluate(e=>e.style.transform);
 await page.keyboard.press('Escape');await expect(dialog).not.toBeVisible();
 await page.locator('#overviewOpenMap').click();await expect(map.locator('[data-map-node="direct:hosts"]')).toHaveAttribute('style',`transform: ${moved};`);
 await map.getByRole('searchbox').fill('Server 119');await expect(map.locator('.ssh-route-host')).toHaveCount(1);await map.getByRole('button',{name:'Inspect Server 119',exact:true}).click();
 await expect(dialog).not.toBeVisible();await expect(page.locator('#overviewSearch')).toHaveValue('Server 119');await expect(page.locator('#overviewHostList .od-host')).toHaveCount(1);
 await page.locator('#overviewOpenMap').click();await map.getByRole('searchbox').fill('');await page.keyboard.press('Escape');
 await page.reload();await page.waitForFunction(()=>ProfileManager.profilesLoaded);await seed();await page.locator('#overviewOpenMap').click();await expect(map.locator('[data-map-node="direct:hosts"]')).toHaveAttribute('style',`transform: ${moved};`);await page.keyboard.press('Escape');
 await page.setViewportSize({width:390,height:800});await expect(topology).toHaveAttribute('data-mode','list');await expect(topology.locator('.od-route-item')).toHaveCount(2);
 await page.locator('#overviewOpenMap').click();await map.getByRole('button',{name:'Show hosts: Nextcloud',exact:true}).click();await expect(map.locator('.ssh-route-host')).toHaveCount(120);await expect(map.getByRole('button',{name:'Close map',exact:true})).toBeInViewport();await page.keyboard.press('Escape');
 expect(errors).toEqual([]);expect(await sshAttempts(page)).toEqual([]);
});

for (const theme of ['glass','retro','paper','werkbank']) {
 test(`route summary remains readable through size changes in ${theme}`, async ({page}, info) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page, 'e2e_admin', {workspace: false});
  await installSshConnectTrap(page);
  await seedHosts(page);
  const topology = page.locator('#odTopology');
  await page.evaluate(value => document.body.dataset.theme = value, theme);
  for (const width of [390,1440,3440]) {
   await page.setViewportSize({width, height:1000});
   await topology.scrollIntoViewIfNeeded();
   await expect(topology).toHaveAttribute('data-mode', width < 600 ? 'list' : 'graph');
   await expect(topology.locator(width < 600 ? '.od-route-item' : '.od-hub')).toHaveCount(2);
   expect(await topology.evaluate(element => element.scrollWidth <= element.clientWidth + 1), theme + ' ' + width).toBe(true);
   expect(await page.locator('#connectionOverview').evaluate(element => element.scrollWidth <= element.clientWidth + 1), theme + ' ' + width).toBe(true);
   await expect(page.locator('#overviewOpenMap')).toBeVisible();
   if (theme === 'arctic-ice') await page.screenshot({path:info.outputPath('summary-' + width + '.png')});
  }
  expect(errors).toEqual([]);
  expect(await sshAttempts(page)).toEqual([]);
 });
}
