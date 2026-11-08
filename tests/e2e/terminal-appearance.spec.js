const {test, expect} = require('playwright/test');
const {login, openWorkspace, assertNoExternalRequests} = require('./helpers');

test('overview defers terminal fonts until the appearance preview opens', async ({page}) => {
    const fonts = [];
    page.on('request', request => {
        if (request.url().includes('/static/vendor/terminal-fonts/') && request.url().includes('.woff2')) fonts.push(request.url());
    });
    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('#overviewHostList .od-host .od-connect').first()).toBeVisible();
    // Include the load event and a paint after all DOMContentLoaded consumers.
    await page.waitForLoadState('load');
    await page.evaluate(() => new Promise(requestAnimationFrame));
    expect(fonts).toEqual([]);
    await openWorkspace(page);
    await page.locator('#terminalAppearanceBtn').click();
    await expect.poll(() => fonts.some(url => url.includes('NerdSymbols-Regular.woff2'))).toBe(true);
    await expect.poll(() => page.evaluate(() => (
        document.fonts.check('14px "WebSSH Nerd Symbols"', '\uf07b')
    ))).toBe(true);
    await assertNoExternalRequests(page);
});

test('restored terminals load their saved fonts on demand without losing output', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    try {
        await page.evaluate(async () => {
            const response = await fetch('/api/account/preferences', {
                method: 'POST', headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content,
                },
                body: JSON.stringify({terminal_appearance: {font_family: 'WebSSH Hack'}}),
            });
            if (!response.ok) throw new Error('Fixture preferences failed');
            const seeded = await new Promise(resolve => window.socket.emit('e2e_workspace_restore', {count: 1}, resolve));
            if (!seeded.ok) throw new Error('Fixture restoration failed');
        });
        await page.reload();
        await expect.poll(() => page.evaluate(() => Object.values(TerminalManager.terminals).length)).toBe(1);
        await expect.poll(() => page.evaluate(() => Object.values(TerminalManager.terminals)[0]?.options.fontFamily))
            .toBe('"WebSSH Hack", "WebSSH Nerd Symbols", monospace');
        await expect.poll(() => page.evaluate(() => {
            const buffer = Object.values(TerminalManager.terminals)[0].buffer.active;
            return Array.from({length: buffer.length}, (_, index) => buffer.getLine(index)?.translateToString(true)).join('');
        })).toContain('restore fixture ready');
        await assertNoExternalRequests(page);
    } finally {
        await page.evaluate(async () => {
            await new Promise(resolve => window.socket.emit('e2e_workspace_restore', {count: 0}, resolve));
            await fetch('/api/account/preferences', {
                method: 'POST', headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content,
                },
                body: JSON.stringify({terminal_appearance: {}}),
            });
        });
    }
});

test('appearance fonts survive preview rebuilds, resizing and reopening without request loops', async ({page}) => {
    const fonts = [];
    page.on('request', request => {
        if (request.url().includes('/static/vendor/terminal-fonts/') && request.url().includes('.woff2')) fonts.push(request.url());
    });
    await login(page);
    const modal = page.locator('#terminalAppearanceModal');
    for (const family of ['WebSSH Hack', 'WebSSH Fira Mono']) {
        await page.setViewportSize({width: 1440, height: 900});
        await page.locator('#terminalAppearanceBtn').click();
        await page.locator(`[name="terminalFontPreset"][value="${family}"]`).check();
        for (const width of [1440, 380, 1920]) {
            await page.setViewportSize({width, height: 900});
            await page.evaluate(theme => applyTheme(theme), width === 380 ? 'paper' : width === 1920 ? 'obsidian' : 'glass');
            await expect(modal).toBeVisible();
            await expect.poll(() => page.evaluate(selected => (
                document.fonts.check(`400 14px "${selected}"`, 'M')
                && document.fonts.check(`700 14px "${selected}"`, 'M')
                && document.fonts.check('14px "WebSSH Nerd Symbols"', '\uf07b')
            ), family)).toBe(true);
            await expect(page.locator('#terminalAppearancePreview .xterm-rows')).toHaveCSS('font-family', new RegExp(family));
            await expect(page.locator('#terminalAppearancePreview .xterm-rows')).toContainText('projects/');
            if (width !== 1440) await page.screenshot({path: test.info().outputPath(`font-preview-${width}.png`)});
        }
        await modal.locator('[data-close-terminal-appearance]').first().click();
        await expect(modal).not.toBeVisible();
    }
    // Closing a preview must not save the draft or repeatedly fetch cached fonts.
    expect(await page.evaluate(() => TerminalAppearance.getPreferences().font_family)).toBeUndefined();
    expect(fonts.length).toBe(new Set(fonts).size);
    await assertNoExternalRequests(page);
});
