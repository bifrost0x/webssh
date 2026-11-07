const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts} = require('./helpers');
const path = require('node:path');

test('host inspection preserves inventory and supports access, files and safe connection review', async ({page}) => {
    await page.setViewportSize({width: 1600, height: 1000});
    await login(page, 'e2e_admin', {workspace: false});
    await installSshConnectTrap(page);
    await page.locator('#overviewHostSearch').fill('Password review');
    await page.getByRole('button', {name:'Connection details: Password review',exact:true}).click();
    await expect(page.locator('.overview-access-inspector')).toBeVisible();
    await expect(page.locator('.overview-path-stops')).toContainText('WebSSH server');
    await expect(page.locator('.overview-path-stops li')).toHaveCount(2);
    expect(await sshAttempts(page)).toEqual([]);
    await page.getByRole('button', {name:'Open files',exact:true}).click();
    await expect(page.locator('#fmQcProfile')).toHaveValue('password-review');
    await page.keyboard.press('Escape');
    await page.locator('#overviewNavBtn').click();
    await page.locator('#overviewHostSearch').fill('Key jump host');
    await page.getByRole('button', {name:'Connection details: Key jump host',exact:true}).click();
    await expect(page.locator('.overview-path-stops li')).toHaveCount(3);
    await expect(page.locator('.overview-access-inspector')).toContainText('E2E key jump host');
    await page.getByRole('button', {name:'Edit access',exact:true}).click();
    await expect(page.locator('#profileManagementModal')).toBeVisible();
    await page.locator('#overviewNavBtn').click();
    await page.locator('#overviewHostSearch').fill('Missing jump host');
    await page.getByRole('button', {name:'Connection details: Missing jump host',exact:true}).click();
    await expect(page.getByRole('button', {name:'Check & connect',exact:true})).toBeDisabled();
    await expect(page.locator('.overview-access-error')).toBeVisible();
    await page.locator('#overviewHostSearch').fill('Password review');
    await page.getByRole('button', {name:'Connection details: Password review',exact:true}).click();
    await page.getByRole('button', {name:'Check & connect',exact:true}).click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#hostInput')).toHaveValue('password.local');
    expect(await sshAttempts(page)).toEqual([]);
});

test('network and inspector remain contained across sizes and themes with screenshots', async ({page}) => {
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
    await expect(page.locator('#overviewHosts .overview-compact-row')).toHaveCount(6);
    await page.screenshot({path:path.resolve('plans/access-network-desktop.png'),animations:'disabled'});
    await page.locator('[data-host-id="preview-4"]').click();
    await expect(page.locator('#overviewHosts .overview-compact-row')).toHaveCount(6);
    await expect(page.locator('.overview-access-inspector')).toContainText('bastion');
    const panel = await page.locator('.overview-access-inspector').boundingBox();
    const network = await page.locator('#overviewHosts .overview-compact-list').boundingBox();
    expect(panel.x).toBeGreaterThanOrEqual(network.x + network.width);
    await page.screenshot({path:path.resolve('plans/access-details-desktop.png'),animations:'disabled'});
    for (const width of [3440,1920,1280,1024,768,390]) {
        await page.setViewportSize({width,height:900});
        for (const theme of ['glass','werkbank','retro','noir','paper','solar','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']) {
            await page.evaluate(theme => {document.body.dataset.theme=theme;},theme);
            expect(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth)).toBe(true);
            await expect(page.locator('.overview-access-inspector')).toBeVisible();
        }
    }
    await page.evaluate(() => {document.body.dataset.theme='glass';});
    await page.locator('.overview-access-inspector').scrollIntoViewIfNeeded();
    await page.locator('#overviewAccessTitle').focus();
    await page.screenshot({path:path.resolve('plans/access-details-mobile.png'),animations:'disabled'});
    await page.keyboard.press('Escape');
    await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
    expect(await sshAttempts(page)).toEqual([]);
});
