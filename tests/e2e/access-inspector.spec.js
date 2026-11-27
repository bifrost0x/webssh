const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts} = require('./helpers');

test('network overview remains contained across sizes and themes with screenshots', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await installSshConnectTrap(page);
    await page.evaluate(async () => {
        const base = ProfileManager.profiles.find(p => p.id === 'password-review');
        const jump = JumpHostManager.jumpHosts[0];
        const names = ['Nextcloud','Docker','Proxmox','NAS','Backup','Monitoring'];
        ProfileManager.setProfiles(names.map((name,i) => ({...base,id:'preview-'+i,name,host:name.toLowerCase()+'.example',group:i<3?'Homelab':'Infrastruktur',jump_host_id:i>2?jump.id:null})));
        jump.name = 'bastion';
        window.dispatchEvent(new Event('jump-host-list-change'));
        await i18n.setLanguage('de');
        document.body.dataset.theme='glass';
    });
    await page.setViewportSize({width:1920,height:1080});
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(6);
    await page.screenshot({path:test.info().outputPath('access-network-desktop.png'),animations:'disabled'});
    await page.locator('#overviewSearch').fill('bastion');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(3);
    await expect(page.locator('#overviewHostList [data-host-id="preview-4"]')).toContainText('bastion');
    await page.screenshot({path:test.info().outputPath('access-details-desktop.png'),animations:'disabled'});
    const themes = ['glass','werkbank','retro','noir','paper','solar','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian'];
    for (const width of [3440,1920,1280,1024,768,390]) {
        await page.setViewportSize({width,height:900});
        // All themes of one width in a single synchronous pass: reading the
        // sizes forces layout after each theme change, so every theme is
        // measured as rendered without a round trip per check.
        const failures = await page.evaluate(({width, themes}) => {
            // Same rule as Playwright's toBeVisible (computeBox in the
            // injected script): display:contents defers to the children,
            // otherwise checkVisibility() (display:none or
            // content-visibility on the element or an ancestor),
            // visibility exactly "visible" and a non-empty bounding box.
            // Opacity does not count, as in Playwright.
            const textVisible = node => {
                const range = document.createRange();
                range.selectNode(node);
                const rect = range.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            const visible = el => {
                const style = getComputedStyle(el);
                if (style.display === 'contents') {
                    return [...el.childNodes].some(child => child.nodeType === Node.ELEMENT_NODE ? visible(child)
                        : child.nodeType === Node.TEXT_NODE && textVisible(child));
                }
                if (!el.checkVisibility() || style.visibility !== 'visible') return false;
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            const failures = [];
            for (const theme of themes) {
                document.body.dataset.theme = theme;
                const at = `width ${width}, theme ${theme}`;
                const root = document.documentElement;
                if (root.scrollWidth > innerWidth) failures.push(`${at}: page scrollWidth ${root.scrollWidth} > ${innerWidth}`);
                const overview = document.querySelector('#connectionOverview');
                if (!overview) failures.push(`${at}: #connectionOverview missing`);
                else if (overview.scrollWidth > overview.clientWidth + 1) {
                    failures.push(`${at}: #connectionOverview scrollWidth ${overview.scrollWidth} > ${overview.clientWidth + 1}`);
                }
                const hosts = document.querySelectorAll('#overviewHostList [data-host-id="preview-4"]');
                if (hosts.length !== 1) failures.push(`${at}: ${hosts.length} host cards preview-4, expected 1`);
                else if (!visible(hosts[0])) failures.push(`${at}: host card preview-4 not visible`);
            }
            return failures;
        }, {width, themes});
        expect(failures).toEqual([]);
    }
    await page.evaluate(() => {document.body.dataset.theme='glass';});
    await page.locator('#overviewHostList [data-host-id="preview-4"] .od-connect').scrollIntoViewIfNeeded();
    await page.locator('#overviewHostList [data-host-id="preview-4"] .od-connect').focus();
    await page.screenshot({path:test.info().outputPath('access-details-mobile.png'),animations:'disabled'});
    await page.locator('#overviewSearch').press('Escape');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(6);
    expect(await sshAttempts(page)).toEqual([]);
});
