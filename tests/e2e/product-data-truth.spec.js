const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');
test('system command arguments are explicitly library defaults, not discovered host values',async({page})=>{
 await login(page);await installSshConnectTrap(page);
 await page.evaluate(()=>CommandLibrary.openLibrary());
 await expect.poll(()=>page.evaluate(()=>CommandLibrary.commands.some(c=>c.id==='net-022'))).toBe(true);
 await page.evaluate(()=>CommandLibrary.selectCommand('net-022'));
 await expect(page.locator('#commandLibraryDetails .command-template-hint')).toContainText('not values detected');
 await expect(page.locator('#commandLibraryDetails')).toContainText('192.168.1.10/24 dev eth0');
 await page.evaluate(()=>i18n.setLanguage('de'));
 await page.evaluate(()=>CommandLibrary.selectCommand('net-022'));
 await expect(page.locator('#commandLibraryDetails .command-template-hint')).toContainText('keine erkannten Serverwerte');
 expect(await sshAttempts(page)).toEqual([]);
});
test('an empty host store never substitutes sample hosts or configured route nodes',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});await installSshConnectTrap(page);
 await page.evaluate(()=>ProfileManager.setProfiles([]));
 await expect(page.locator('#overviewHosts')).toContainText('No saved connections');
 await expect(page.locator('#overviewHostCount')).toHaveText('0');
 await expect(page.locator('#overviewHosts [data-host-id]')).toHaveCount(0);
 await expect(page.locator('.overview-route-bundle')).toHaveCount(0);
 await page.locator('#overviewHostSearch').fill('proxmox');
 await expect(page.locator('#overviewHosts [data-host-id]')).toHaveCount(0);
 expect(await sshAttempts(page)).toEqual([]);
});
