const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');
const fs = require('node:fs');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

async function headerGeometry(page) {
    return page.locator('.header-content, .brand-wordmark, .global-nav-item').evaluateAll(items => items.map(item => {
        const {x, y, width, height} = item.getBoundingClientRect();
        return {x, y, width, height, labels:[...item.querySelectorAll('span:not(.material-icons)')].map(label => getComputedStyle(label).display)};
    }));
}

for (const width of [1440, 3200]) {
    test(`applying presets preserves the header and an existing terminal at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:1000});
        await login(page);
        await page.evaluate(() => { document.body.dataset.theme='glass'; TerminalManager.applyThemeToAll(); });
        await installSshConnectTrap(page);
        await page.locator('#workspaceLayoutPicker > summary').click();
        await page.locator('.split-btn[data-layout="1"]').click();
        await page.route('**/api/account/workspace-presets', route => route.fulfill({json:{presets:[
            {id:'two-panes',name:'Two panes',layout:2,profile_ids:[]},
            {id:'four-panes',name:'Four panes',layout:4,profile_ids:[]}
        ]}}));
        await page.evaluate(() => {
            const original = window.socket.emit.bind(window.socket);
            window.__presetSessionEvents = [];
            window.socket.emit = (event, payload, ...rest) => {
                if (payload?.session_id === 'preset-existing') {
                    window.__presetSessionEvents.push(event);
                    return window.socket;
                }
                return original(event, payload, ...rest);
            };
            window.socket.listeners('ssh_connected').forEach(listener => listener({
                session_id:'preset-existing', host:'lab.example', port:22, username:'ops', client_request_id:'reconnect_preset-existing'
            }));
            TerminalManager.writeOutput('preset-existing', 'ops@lab:~$ ');
        });
        await expect(page.locator('#terminal-preset-existing')).toBeVisible();
        const before = await headerGeometry(page);
        fs.mkdirSync('plans/workspace-fixes', {recursive:true});
        await page.screenshot({path:`plans/workspace-fixes/before-${width}.png`});
        for (const name of ['Two panes', 'Four panes']) {
            await page.locator('#workspaceLayoutPicker > summary').click();
            if (name === 'Two panes') await page.screenshot({path:`plans/workspace-fixes/layout-menu-${width}.png`});
            await page.locator('#workspacePresetsBtn').click();
            const dialog = page.getByRole('dialog', {name:'Workspace presets', exact:true});
            await dialog.locator('section').filter({has:page.getByRole('heading', {name, exact:true})})
                .getByRole('button', {name:'Apply layout and choose connections', exact:true}).click();
            await dialog.getByRole('button', {name:'Close', exact:true}).click();
            await expect(page.locator('#workspaceLayoutPicker > summary')).toBeFocused();
            await expect(page.locator('#terminal-preset-existing')).toBeVisible();
            await page.screenshot({path:`plans/workspace-fixes/${name.replace(' ', '-')}-${width}.png`});
            expect(await headerGeometry(page)).toEqual(before);
            expect(await page.evaluate(() => SessionManager.paneAssignments[0])).toBe('preset-existing');
            expect(await page.evaluate(() => window.__presetSessionEvents.includes('ssh_disconnect'))).toBe(false);
            expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
        }
    });
}

test('backup guidance is translated and recovery works in the settings center', async ({page}) => {
    await login(page);
    await page.goto('/settings#backup');
    await page.evaluate(() => { document.body.dataset.theme='glass'; });
    const coverage = page.locator('.backup-coverage');
    await expect(coverage).toBeVisible();
    await expect(coverage).not.toContainText('customer.');
    await expect(coverage.locator('details')).not.toHaveAttribute('open','');
    for (const language of ['en','de','fr','es','vi','zh']) {
        await page.evaluate(lang => window.i18n.setLanguage(lang), language);
        await expect(coverage).not.toContainText('customer.');
        await coverage.locator('[data-recovery-check]').click();
        const dialog = page.getByRole('dialog');
        await expect(dialog.locator('.customer-checklist > li')).toHaveCount(4);
        await expect(dialog).not.toContainText('customer.');
        await page.keyboard.press('Escape');
        await expect(coverage.locator('[data-recovery-check]')).toBeFocused();
    }
    await page.evaluate(() => window.i18n.setLanguage('en'));
    fs.mkdirSync('plans/workspace-fixes', {recursive:true});
    for (const width of [1440,390]) {
        await page.setViewportSize({width,height:1000});
        await coverage.scrollIntoViewIfNeeded();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await page.screenshot({path:`plans/workspace-fixes/backup-${width}.png`,fullPage:true});
        await coverage.locator('summary').click();
        await expect(coverage.locator('[data-i18n="customer.excluded"]')).toBeVisible();
        expect(await coverage.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        await page.screenshot({path:`plans/workspace-fixes/backup-details-${width}.png`,fullPage:true});
        await coverage.locator('summary').click();
    }
});
