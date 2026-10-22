const {test, expect} = require('playwright/test');
const {login, openWorkspace, assertNoExternalRequests} = require('./helpers');

test('overview defers terminal fonts until the appearance preview opens', async ({page}) => {
    const fonts = [];
    page.on('request', request => {
        if (request.url().includes('/static/vendor/terminal-fonts/') && request.url().includes('.woff2')) fonts.push(request.url());
    });
    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('#overviewHosts [data-host-id]').first()).toBeVisible();
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
    assertNoExternalRequests(page);
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
        assertNoExternalRequests(page);
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
