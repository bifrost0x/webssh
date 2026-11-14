const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

async function setup(page) {
    await login(page);
    await page.evaluate(() => {
        const emit = window.socket.emit.bind(window.socket);
        window.__terminalInputs = [];
        window.socket.emit = (event, payload, ...rest) => {
            if (payload?.session_id?.startsWith('safe-')) {
                if (event === 'ssh_input') window.__terminalInputs.push(payload);
                rest.find(value => typeof value === 'function')?.({success: true});
                return window.socket;
            }
            return emit(event, payload, ...rest);
        };
    });
    await connect(page, 'safe-one', 'alpha.example');
}
async function connect(page, id, host) {
    await page.evaluate(({id, host}) => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({session_id: id, host,
            port: 22, username: 'ops', client_request_id: `reconnect_${id}`}));
    }, {id, host});
    await expect(page.locator(`#tab-${id}`)).toBeVisible();
}
async function nativePaste(page, text, selector = '#terminal-safe-one .xterm-helper-textarea') {
    await page.locator(selector).evaluate((element, text) => {
        const clipboardData = new DataTransfer();
        clipboardData.setData('text/plain', text);
        element.dispatchEvent(new ClipboardEvent('paste', {bubbles: true, cancelable: true, clipboardData}));
    }, text);
}
async function inputs(page) { return page.evaluate(() => window.__terminalInputs); }

test('native terminal paste previews unsafe text and cancellation sends nothing', async ({page}) => {
    await setup(page);
    await nativePaste(page, 'echo safe\necho <img src=x>\u001b[31m\n');
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await expect(page.locator('#terminalPastePreview')).toContainText('[ESC]');
    await expect(page.locator('#terminalPastePreview img')).toHaveCount(0);
    expect(await inputs(page)).toEqual([]);
    await page.locator('#terminalPasteCancel').click();
    expect(await inputs(page)).toEqual([]);
});

test('safe single-line paste stays fast and confirmed paste preserves bracketed mode', async ({page}) => {
    await setup(page);
    await nativePaste(page, 'pwd');
    expect((await inputs(page)).map(item => item.data)).toEqual(['pwd']);
    await page.evaluate(() => new Promise(resolve => TerminalManager.terminals['safe-one'].write('\u001b[?2004h', resolve)));
    await nativePaste(page, 'one\r\ntwo\n');
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await page.locator('#terminalPasteTrim').check();
    await page.locator('#terminalPasteConfirm').click();
    expect((await inputs(page)).map(item => item.data)).toEqual(['pwd', '\u001b[200~one\rtwo\u001b[201~']);
});

test('switching away and back cancels pending paste instead of retargeting', async ({page}) => {
    await setup(page);
    await connect(page, 'safe-two', 'beta.example');
    await page.evaluate(() => SessionManager.switchSession('safe-one'));
    await nativePaste(page, 'first\nsecond');
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await page.evaluate(() => {SessionManager.switchSession('safe-two'); SessionManager.switchSession('safe-one');});
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    expect(await inputs(page)).toEqual([]);
});

test('broadcast selects concrete recipients and never includes a newly opened session', async ({page}) => {
    await setup(page);
    await page.locator('#broadcastToggleBtn').click();
    await expect(page.locator('#broadcastRecipientDialog')).toBeVisible();
    await expect(page.locator('#broadcastRecipientList')).toContainText('ops@alpha.example:22');
    await page.locator('#broadcastRecipientList input').first().check();
    await page.locator('#broadcastRecipientApply').click();
    await connect(page, 'safe-two', 'beta.example');
    await page.locator('#broadcastInput').fill('whoami');
    await page.locator('#broadcastSendBtn').click();
    await expect.poll(async () => (await inputs(page)).length).toBe(1);
    expect(await inputs(page)).toEqual([expect.objectContaining({session_id: 'safe-one', data: 'whoami\r'})]);
    await page.evaluate(() => SessionManager.updateSessionStatus('safe-one', 'disconnected'));
    await expect(page.locator('#broadcastSendBtn')).toBeDisabled();
    await expect(page.locator('#broadcastSelectionStatus')).toContainText('changed');
});

test('palette clipboard paste is guarded and an outstanding read cannot follow a session switch', async ({page}) => {
    await setup(page);
    await connect(page, 'safe-two', 'beta.example');
    await page.evaluate(() => {
        SessionManager.switchSession('safe-one');
        Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
            readText: () => new Promise(resolve => {window.__resolveClipboard = resolve;})
        }});
    });
    await page.locator('#shellSearchBtn').click();
    await page.locator('#commandPaletteInput').fill('Paste Clipboard');
    await page.locator('[data-palette-id="paste-clipboard"]').click();
    await expect.poll(() => page.evaluate(() => typeof window.__resolveClipboard)).toBe('function');
    await page.evaluate(() => {
        SessionManager.switchSession('safe-two');
        SessionManager.switchSession('safe-one');
        window.__resolveClipboard('one\ntwo');
    });
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    expect(await inputs(page)).toEqual([]);
    await page.locator('#shellSearchBtn').click();
    await page.locator('#commandPaletteInput').fill('Paste Clipboard');
    await page.locator('[data-palette-id="paste-clipboard"]').click();
    await page.evaluate(() => window.__resolveClipboard('one\ntwo'));
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await page.locator('#terminalPasteConfirm').click();
    expect((await inputs(page)).map(item => item.data)).toEqual(['one\rtwo']);
});

test('disconnect cancels paste and cannot revive it after reconnect', async ({page}) => {
    await setup(page);
    await nativePaste(page, 'one\ntwo');
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await page.evaluate(() => SessionManager.updateSessionStatus('safe-one', 'disconnected'));
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    await page.evaluate(() => SessionManager.updateSessionStatus('safe-one', 'connected'));
    expect(await inputs(page)).toEqual([]);
});

test('mobile command-field paste previews original line breaks before browser sanitization', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await setup(page);
    await page.locator('#mobileCommandToggle').click();
    await nativePaste(page, 'one\ntwo\n', '#mobileInput');
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    expect(await inputs(page)).toEqual([]);
    await page.locator('#terminalPasteCancel').click();
    await nativePaste(page, 'one\ntwo\n', '#mobileInput');
    await page.locator('#terminalPasteTrim').check();
    await page.locator('#terminalPasteConfirm').click();
    expect((await inputs(page)).map(item => item.data)).toEqual(['one\rtwo']);
});

for (const viewport of [{width:1440, height:960}, {width:390, height:844}]) {
    test(`terminal safety fits ${viewport.width}px with identical recipient endpoints`, async ({page}) => {
        await page.setViewportSize(viewport);
        await setup(page);
        await connect(page, 'safe-two', 'alpha.example');
        await page.evaluate(() => {SessionManager.switchSession('safe-one'); window.i18n.setLanguage('de');});
        await page.evaluate(() => BroadcastInput.show());
        const dialog = page.locator('#broadcastRecipientDialog');
        await expect(dialog).toBeVisible();
        await expect(dialog.locator('input[type=checkbox]')).toHaveCount(2);
        const labels = await dialog.locator('.terminal-recipient').allTextContents();
        expect(labels[0]).toContain('safe-one');
        expect(labels[1]).toContain('safe-two');
        const fs = require('node:fs');
        fs.mkdirSync('plans/terminal-controls', {recursive:true});
        await page.screenshot({path:`plans/terminal-controls/broadcast-${viewport.width}.png`, animations:'disabled'});
        let rect = await dialog.boundingBox();
        expect(rect.x).toBeGreaterThanOrEqual(0);
        expect(rect.x + rect.width).toBeLessThanOrEqual(viewport.width);
        await page.locator('#broadcastRecipientCancel').click();
        await nativePaste(page, 'printf "Example output"\nwhoami\u001b[31m\n');
        await expect(page.locator('#terminalPasteDialog')).toBeVisible();
        await page.screenshot({path:`plans/terminal-controls/paste-${viewport.width}.png`, animations:'disabled'});
        rect = await page.locator('#terminalPasteDialog').boundingBox();
        expect(rect.x).toBeGreaterThanOrEqual(0);
        expect(rect.x + rect.width).toBeLessThanOrEqual(viewport.width);
        expect(rect.y + rect.height).toBeLessThanOrEqual(viewport.height);
        await page.keyboard.press('Escape');
        await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
        expect(await inputs(page)).toEqual([]);
    });
}

async function selectBroadcastRecipients(page) {
    await page.locator('#broadcastToggleBtn').click();
    for (const checkbox of await page.locator('#broadcastRecipientList input').all()) await checkbox.check();
    await page.locator('#broadcastRecipientApply').click();
}

test('native multiline broadcast paste preserves its draft and reviews all recipients before send', async ({page}) => {
    await setup(page);
    await connect(page, 'safe-two', 'beta.example');
    await selectBroadcastRecipients(page);
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.evaluate(() => navigator.clipboard.writeText('printf first\nprintf second\n'));
    await page.locator('#broadcastInput').focus();
    await page.keyboard.press('Control+v');
    await expect(page.locator('#broadcastInput')).toHaveValue('printf first\nprintf second\n');
    expect(await inputs(page)).toEqual([]);
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    await page.locator('#broadcastSendBtn').click();
    await expect(page.locator('#terminalPasteTitle')).toHaveText('Review broadcast input');
    await expect(page.locator('#terminalPasteTarget')).toContainText('ops@alpha.example:22');
    await expect(page.locator('#terminalPasteTarget')).toContainText('ops@beta.example:22');
    await expect(page.locator('#terminalPasteConfirm')).toHaveText('Send to selected');
    await page.locator('#terminalPasteCancel').click();
    await expect(page.locator('#broadcastInput')).toHaveValue('printf first\nprintf second\n');
    expect(await inputs(page)).toEqual([]);
    await page.locator('#broadcastSendBtn').click();
    await page.locator('#terminalPasteTrim').check();
    await page.locator('#terminalPasteConfirm').click();
    await expect.poll(async () => (await inputs(page)).length).toBe(2);
    expect(await inputs(page)).toEqual([
        expect.objectContaining({session_id:'safe-one', data:'printf first\rprintf second\r'}),
        expect.objectContaining({session_id:'safe-two', data:'printf first\rprintf second\r'}),
    ]);
    await expect(page.locator('#broadcastInput')).toHaveValue('');
});

test('broadcast control paste and recipient changes cancel without sending or clearing the draft', async ({page}) => {
    await setup(page);
    await connect(page, 'safe-two', 'beta.example');
    await selectBroadcastRecipients(page);
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.evaluate(() => navigator.clipboard.writeText('printf test\u001b[31m'));
    await page.locator('#broadcastInput').focus();
    await page.keyboard.press('Control+v');
    await expect(page.locator('#broadcastInput')).toHaveValue('printf test\u001b[31m');
    await page.locator('#broadcastSendBtn').click();
    await expect(page.locator('#terminalPastePreview')).toContainText('[ESC]');
    await page.evaluate(() => BroadcastInput.selectRecipients(['safe-one']));
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    expect(await inputs(page)).toEqual([]);
    await expect(page.locator('#broadcastInput')).toHaveValue('printf test\u001b[31m');
    await page.locator('#broadcastSendBtn').click();
    await expect(page.locator('#terminalPasteDialog')).toBeVisible();
    await page.evaluate(() => {
        SessionManager.updateSessionStatus('safe-one', 'disconnected');
        SessionManager.updateSessionStatus('safe-one', 'connected');
    });
    await expect(page.locator('#terminalPasteDialog')).not.toBeVisible();
    expect(await inputs(page)).toEqual([]);
    await expect(page.locator('#broadcastInput')).toHaveValue('printf test\u001b[31m');
});
