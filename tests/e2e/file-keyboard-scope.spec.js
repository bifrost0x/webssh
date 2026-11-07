const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
for (const width of [390, 1536]) test(`file shortcuts stay inside the focused file area at ${width}`, async ({page}) => {
    await page.setViewportSize({width,height:900});
    await login(page);
    await page.evaluate(() => sftpFileManager.open());
    await page.evaluate(() => {
        window.fileShortcutCalls = [];
        const manager = sftpFileManager;
        for (const action of ['renameSelected','deleteSelected','createNewFolder','executeTransfer','selectAll']) {
            manager[action] = () => window.fileShortcutCalls.push(action);
        }
        const outside = document.createElement('div');
        outside.id = 'outsideFileFocus'; outside.tabIndex = 0;
        document.body.append(outside); outside.focus();
    });
    for (const key of ['F2','Delete','F7','F5','Control+a']) await page.keyboard.press(key);
    expect(await page.evaluate(() => window.fileShortcutCalls)).toEqual([]);
    // The same shortcuts must still work inside the file list.
    await page.locator('#fmLeftList').evaluate(el => {el.tabIndex = 0; el.focus();});
    for (const key of ['F2','Delete','F7','F5','Control+a']) await page.keyboard.press(key);
    expect(await page.evaluate(() => window.fileShortcutCalls)).toEqual(['renameSelected','deleteSelected','createNewFolder','executeTransfer','selectAll']);
    await page.evaluate(() => {
        window.fileShortcutCalls = [];
        window.openDefaultConnectionModal();
        const title = document.getElementById('connectionModalTitle'); title.tabIndex = -1; title.focus();
    });
    for (const key of ['F2','Delete','F7']) await page.keyboard.press(key);
    expect(await page.evaluate(() => window.fileShortcutCalls)).toEqual([]);
});

test('resizing the right notes tool preserves text and returns focus to its launcher', async ({page}, testInfo) => {
    await page.setViewportSize({width:1536,height:900});
    await login(page);
    await page.evaluate(() => {
        const emit = socket.emit.bind(socket);
        socket.emit = (event, payload, ack) => {
            if (event === 'save_notepad') { queueMicrotask(() => ack({success:true})); return socket; }
            return emit(event,payload,ack);
        };
        workspaceLayoutController.openContext('notes','user');
    });
    await page.locator('#sessionNotepad').fill('Retain this note across the breakpoint');
    await page.setViewportSize({width:390,height:850});
    await expect(page.locator('#contextWorkspaceLauncher')).toBeFocused();
    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();
    await page.locator('#contextWorkspaceLauncher').click();
    await expect(page.locator('#sessionNotepad')).toBeVisible();
    await expect(page.locator('#sessionNotepad')).toHaveValue('Retain this note across the breakpoint');
    await expect(page.locator('#notepadSaveStatus')).toHaveText('Saved');
    await page.screenshot({path:testInfo.outputPath('notes-reopened-mobile.png'), animations:'disabled'});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
