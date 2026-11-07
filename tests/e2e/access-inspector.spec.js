const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts} = require('./helpers');
const path = require('node:path');

test('network overview remains contained across sizes and themes with screenshots', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await installSshConnectTrap(page);
    await page.evaluate(() => {
        const base = ProfileManager.profiles.find(p => p.id === 'password-review');
        const jump = JumpHostManager.jumpHosts[0];
        const names = ['Nextcloud','Docker','Proxmox','NAS','Backup','Monitoring'];
        ProfileManager.setProfiles(names.map((name,i) => ({...base,id:'preview-'+i,name,host:name.toLowerCase()+'.example',group:i<3?'Homelab':'Infrastruktur',jump_host_id:i>2?jump.id:null})));
        jump.name = 'bastion';
        window.dispatchEvent(new Event('jump-host-list-change'));
        i18n.setLanguage('de');
        document.body.dataset.theme='glass';
    });
    await page.setViewportSize({width:1920,height:1080});
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(6);
    await page.screenshot({path:path.resolve('plans/access-network-desktop.png'),animations:'disabled'});
    await page.locator('#overviewSearch').fill('bastion');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(3);
    await expect(page.locator('#overviewHostList [data-host-id="preview-4"]')).toContainText('bastion');
    await page.screenshot({path:path.resolve('plans/access-details-desktop.png'),animations:'disabled'});
    for (const width of [3440,1920,1280,1024,768,390]) {
        await page.setViewportSize({width,height:900});
        for (const theme of ['glass','werkbank','retro','noir','paper','solar','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']) {
            await page.evaluate(theme => {document.body.dataset.theme=theme;},theme);
            expect(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth)).toBe(true);
            expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth<=el.clientWidth+1)).toBe(true);
            await expect(page.locator('#overviewHostList [data-host-id="preview-4"]')).toBeVisible();
        }
    }
    await page.evaluate(() => {document.body.dataset.theme='glass';});
    await page.locator('#overviewHostList [data-host-id="preview-4"] .od-connect').scrollIntoViewIfNeeded();
    await page.locator('#overviewHostList [data-host-id="preview-4"] .od-connect').focus();
    await page.screenshot({path:path.resolve('plans/access-details-mobile.png'),animations:'disabled'});
    await page.locator('#overviewSearch').press('Escape');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(6);
    expect(await sshAttempts(page)).toEqual([]);
});
