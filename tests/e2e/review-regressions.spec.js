const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('Quick Connect accepts IPv6 and dotted usernames with localized validation', async ({page}) => {
    await login(page);
    await page.locator('.profile-launcher-new').click();
    await page.locator('#hostInput').fill('2001:db8::10');
    await page.locator('#usernameInput').fill('first.last');
    await expect(page.locator('#hostInput')).not.toHaveClass(/is-invalid/);
    await expect(page.locator('#usernameInput')).not.toHaveClass(/is-invalid/);
    await page.evaluate(() => i18n.setLanguage('de'));
    await page.locator('#hostInput').fill(':::');
    await expect(page.locator('#hostHint')).toHaveText('Hostname oder IPv4-/IPv6-Adresse eingeben.');
});

test('German settings navigation stays within the sidebar at intermediate widths', async ({page}, testInfo) => {
    await login(page);
    await page.goto('/settings#preferences');
    await page.locator('#settingsLanguageSelect').selectOption('de');
    await page.evaluate(() => document.fonts.ready);
    for (const width of [900, 768, 601, 1024]) {
        await page.setViewportSize({width, height: 800});
        const geometry = await page.evaluate(() => {
            const sidebar = document.querySelector('.admin-navigation').getBoundingClientRect();
            return Array.from(document.querySelectorAll('.settings-center-navigation .admin-tab'))
                .map(button => ({right: button.getBoundingClientRect().right, limit: sidebar.right,
                    scroll: button.scrollWidth, width: button.clientWidth}));
        });
        if (width === 900) await page.screenshot({path: testInfo.outputPath('settings-de-900.png')});
        for (const button of geometry) {
            expect(button.right).toBeLessThanOrEqual(button.limit);
            expect(button.scroll).toBeLessThanOrEqual(button.width + 1);
        }
    }
});

test('notes confirm real persistence and remain unsaved while offline', async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await expect(page.locator('#sessionNotepad')).toBeVisible();
    await page.locator('#sessionNotepad').fill('Review note persisted');
    await expect(page.locator('#notepadSaveStatus')).toHaveText('Saved');
    await page.reload();
    await expect(page.locator('#sessionNotepad')).toHaveValue('Review note persisted');
    await page.evaluate(() => window.socket.disconnect());
    await page.locator('#sessionNotepad').fill('Offline review edit');
    await expect(page.locator('#notepadSaveStatus')).toHaveText('Offline — not saved');
    await page.evaluate(() => window.socket.connect());
    await expect(page.locator('#notepadSaveStatus')).toHaveText('Saved');
    await page.reload();
    await expect(page.locator('#sessionNotepad')).toHaveValue('Offline review edit');
});

test('terminal drop prompts once and binds the target before any upload', async ({page}) => {
    await login(page);
    await page.evaluate(() => {
        const sessions = {
            first: {id: 'first', username: 'alice', host: 'first.example', connected: true},
            active: {id: 'active', username: 'bob', host: 'active.example', connected: true},
        };
        SessionManager.getAllSessions = () => Object.values(sessions);
        SessionManager.getWorkspaceSession = () => 'active';
        SessionManager.getSession = id => sessions[id];
        window.__reviewUploads = [];
        FileTransferManager.uploadFile = (...args) => window.__reviewUploads.push(args);
        const transfer = new DataTransfer();
        transfer.items.add(new File(['review'], 'note.txt', {type: 'text/plain'}));
        document.querySelector('#workspace').dispatchEvent(new DragEvent('drop', {bubbles: true, dataTransfer: transfer}));
    });
    await expect(page.locator('#dropUploadModal')).toBeVisible();
    await expect(page.locator('#dropUploadTarget')).toHaveText('bob@active.example:22');
    expect(await page.evaluate(() => window.__reviewUploads.length)).toBe(0);
    await page.locator('#dropUploadPath').fill('/chosen');
    await page.evaluate(() => { SessionManager.getWorkspaceSession = () => 'first'; });
    await page.locator('#dropUploadForm button[type="submit"]').click();
    expect(await page.evaluate(() => window.__reviewUploads.map(([source, file, path]) => ({source, name: file.name, path}))))
        .toEqual([{source: 'sftp-session:active', name: 'note.txt', path: '/chosen/note.txt'}]);
});
