const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test('command editor backdrop keeps the draft when discard is declined', async ({page}) => {
    await page.evaluate(() => {
        window.FilePreview.close();
        window.CommandWorkspace.open('library');
    });
    await page.locator('#addCommandBtn').click();
    await page.locator('#commandFormName').fill('Preserve backdrop draft');
    await page.locator('#commandFormModal').click({position: {x: 2, y: 2}});
    const confirmation = page.locator('.command-set-confirm-dialog');
    await expect(confirmation).toBeVisible();
    await confirmation.getByRole('button', {name: 'Keep editing', exact: true}).click();
    await expect(page.locator('#commandFormModal')).toBeVisible();
    await expect(page.locator('#commandFormName')).toHaveValue('Preserve backdrop draft');
});

test('late ordinary quick connection preserves a newer dialog', async ({page}) => {
    await page.evaluate(() => window.FilePreview.close());
    await page.locator('#fileTransferBtn').click();
    await page.evaluate(() => {
        const manager = window.getSFTPFileManager();
        window.__quickRequests = [];
        window.__quickDisconnects = [];
        const emit = manager.socket.emit.bind(manager.socket);
        manager.socket.emit = (event, data, ...args) => {
            if (event === 'quick_connect') {
                window.__quickRequests.push({host: data.host, client_request_id: data.client_request_id});
                return manager.socket;
            }
            if (event === 'quick_disconnect') {
                window.__quickDisconnects.push(data.connection_id);
                return manager.socket;
            }
            return data === undefined ? emit(event, ...args) : emit(event, data, ...args);
        };
        manager.pendingQuickConnectPane = 'left';
        manager.openQuickConnect();
    });
    await page.locator('#fmQcHost').fill('first.example.test');
    await page.locator('#fmQcUsername').fill('deploy');
    await page.locator('#fmQcPassword').fill('fixture-password');
    await page.locator('#fmQcConnectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__quickRequests.length)).toBe(1);
    await page.evaluate(() => {
        const manager = window.getSFTPFileManager();
        manager.closeQuickConnect();
        manager.pendingQuickConnectPane = 'right';
        manager.openQuickConnect();
    });
    await page.locator('#fmQcHost').fill('second.example.test');
    await page.evaluate(() => window.getSFTPFileManager().handleQuickConnectSuccess({
        connection_id: 'late-fixture', host: 'first.example.test', port: 22, username: 'deploy',
        client_request_id: window.__quickRequests[0].client_request_id,
    }));
    await expect(page.locator('#fmQcHost')).toBeVisible();
    await expect(page.locator('#fmQcHost')).toHaveValue('second.example.test');
    expect(await page.evaluate(() => window.__quickDisconnects)).toContain('late-fixture');
});

for (const trigger of ['Escape', 'backdrop']) {
    test(`keep-editing decision survives ${trigger}`, async ({page}) => {
        await page.locator('#editorContent').fill('keep this unsaved draft');
        page.once('dialog', dialog => dialog.dismiss());
        if (trigger === 'Escape') await page.keyboard.press('Escape');
        else await page.locator('#filePreviewModal').click({position: {x: 2, y: 2}});
        await expect(page.locator('#filePreviewModal')).toBeVisible();
        await expect(page.locator('#editorContent')).toHaveValue('keep this unsaved draft');
    });
}

test.beforeEach(async ({ page }) => {
    await login(page);
    await page.evaluate(() => {
        const source = { sourceId: 'sftp-session:review-fixture', endpoint: 'review@example.test:22' };
        window.getSFTPFileManager().buildSourceCatalog = () => [{ items: [source] }];
        window.__reviewSaves = [];
        const emit = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ...args) => {
            if (event === 'preview_file') {
                queueMicrotask(() => window.FilePreview.handlePreviewData({
                    ...data, filename: 'review.txt', content: 'café\nold\n', size: 10,
                }));
                return window.socket;
            }
            if (event === 'open_file_for_edit') {
                queueMicrotask(() => window.FilePreview.handleEditData({
                    ...data, content: 'café\nold\n', revision: 'original-revision',
                    encoding: 'latin-1', newline: 'crlf', original_bytes: 'Y2Fm6Q0Kb2xkCg==',
                }));
                return window.socket;
            }
            if (event === 'save_file') {
                window.__reviewSaves.push(structuredClone(data));
                return window.socket;
            }
            return data === undefined ? emit(event, ...args) : emit(event, data, ...args);
        };
        window.FilePreview.open(source.sourceId, '/etc/review.txt', 'review.txt');
    });
    await page.locator('#previewEditBtn').click();
    await expect(page.locator('#editorContent')).toHaveValue('café\nold\n');
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});
