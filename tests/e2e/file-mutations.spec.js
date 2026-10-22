const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

async function workspace(page, kind = 'sftp', chmod = true) {
    await login(page);
    await page.evaluate(({kind, chmod}) => {
        openFileManager();
        const manager = window.sftpFileManager;
        manager.closeSourceLauncher();
        window.__mutationEvents = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, payload, ...rest) => {
            if (['create_file', 'get_file_permissions', 'set_file_permissions'].includes(event)) {
                window.__mutationEvents.push({event, payload});
                if (event === 'get_file_permissions') queueMicrotask(() => {
                    window.socket.listeners('file_permissions').forEach(listener => listener({ ...payload, operation: event, mode: '600', special_bits: 0, object_type: 'file', metadata_token: 'test-token' }));
                });
                return window.socket;
            }
            return original(event, payload, ...rest);
        };
        Object.assign(manager.panes.left, manager.createEmptyPaneState(), {
            source: { sourceId: `${kind === 'sftp' ? 'sftp-session' : 'smb-quick'}:mutation-test`, kind, label: 'Test source', capabilities: ['list', 'create-file', ...(kind === 'sftp' && chmod ? ['chmod'] : [])], access: {} },
            path: '/', files: [{ name: 'existing.txt', is_dir: false, mode: 33152, size: 3 }],
        });
        manager.setActivePane('left');
        manager.renderPane('left');
        manager.updateWorkspaceActions();
    }, {kind, chmod});
}

test('disabled chmod remains discoverable through operator setup help', async ({ page }) => {
    await workspace(page, 'sftp', false);
    await expect(page.locator('#fmLeftPane [data-pane-action="permissions"]')).toBeHidden();
    const help = page.locator('.fm-permissions-help');
    await expect(help).toBeVisible();
    expect(await help.evaluate(element => Boolean(element.closest('.fm-workspace-controls')))).toBe(true);
    expect(await page.locator('#fmModalTitle').evaluate(element => element.getBoundingClientRect().height)).toBeLessThanOrEqual(1);
    await test.info().attach('chmod-help-desktop-collapsed', { body: await page.screenshot({ path: test.info().outputPath('desktop-collapsed.png') }), contentType: 'image/png' });
    const panesTop = await page.locator('.fm-panes').evaluate(element => element.getBoundingClientRect().top);
    await help.locator('summary').click();
    expect(await page.locator('.fm-panes').evaluate(element => element.getBoundingClientRect().top)).toBe(panesTop);
    await test.info().attach('chmod-help-desktop-expanded', { body: await page.screenshot({ path: test.info().outputPath('desktop-expanded.png') }), contentType: 'image/png' });
    await expect(help).toContainText('SFTP_CHMOD_ENABLED=true');
    await expect(help).toContainText('operator');
    await expect(help).toContainText('lsetstat@openssh.com');
    await expect(help).toContainText('SMB');
    expect(await page.evaluate(() => window.__mutationEvents.length)).toBe(0);
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await help.locator('div').evaluate(element => {
        const bounds = element.getBoundingClientRect();
        return bounds.left >= 0 && bounds.right <= innerWidth && element.scrollWidth <= element.clientWidth + 1;
    })).toBe(true);
    await test.info().attach('chmod-help-mobile-expanded', { body: await page.screenshot({ path: test.info().outputPath('mobile-expanded.png') }), contentType: 'image/png' });
    await page.evaluate(() => i18n.setLanguage('de'));
    await expect(help.locator('summary [data-i18n]')).toHaveText('chmod aktivieren');
    await expect(help).toContainText('Betreiber');
    await expect(page.locator('#fmLeftPane [data-pane-action="permissions"]')).toBeHidden();
    await page.keyboard.press('Escape');
    await expect(help).not.toHaveAttribute('open');
    await assertNoExternalRequests(page);
});

test('new file validates the name, prevents duplicate requests and closes with Escape', async ({ page }) => {
    await workspace(page);
    await page.locator('#fmLeftPane [data-pane-action="newfile"]').click();
    const dialog = page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: 'New file', exact: true }) });
    await expect(dialog).toBeVisible();
    const create = dialog.getByRole('button', { name: 'Create file', exact: true });
    await dialog.locator('[name="filename"]').fill('../bad');
    await expect(create).toBeDisabled();
    await dialog.locator('[name="filename"]').fill('Überblick.txt');
    await create.click();
    await expect(create).toBeDisabled();
    expect(await page.evaluate(() => window.__mutationEvents.filter(value => value.event === 'create_file').length)).toBe(1);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await assertNoExternalRequests(page);
});

test('permission dialog binds the inspected metadata and sends only a deliberate change', async ({ page }) => {
    await workspace(page);
    await page.locator('#fmLeftList .fm-file-item').first().click();
    await page.locator('#fmLeftPane [data-pane-action="permissions"]').click();
    const dialog = page.locator('dialog.fm-mutation-dialog');
    await expect(dialog.locator('[name="mode"]')).toHaveValue('600');
    const apply = dialog.getByRole('button', { name: 'Apply permissions' });
    await expect(apply).toBeDisabled();
    await dialog.locator('[name="mode"]').fill('640');
    await apply.click();
    const sent = await page.evaluate(() => window.__mutationEvents.find(value => value.event === 'set_file_permissions'));
    expect(sent.payload).toMatchObject({ source_id: 'sftp-session:mutation-test', path: '/existing.txt', mode: '640', expected_metadata: 'test-token' });
    await expect(apply).toBeDisabled();
    await page.evaluate(payload => window.socket.listeners('error').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', code: 'OUTCOME_UNKNOWN', error: 'Result unknown. Refresh before taking further action.' })), sent.payload);
    await expect(dialog.getByRole('status')).toContainText('Result unknown');
    await expect(apply).toBeDisabled();
});

test('SMB has new-file support without a Unix permission action', async ({ page }) => {
    await workspace(page, 'smb');
    await expect(page.locator('#fmLeftPane [data-pane-action="newfile"]')).toBeEnabled();
    await expect(page.locator('#fmLeftPane [data-pane-action="permissions"]')).toBeHidden();
});

test('mobile file creation is reachable from the action sheet', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await workspace(page);
    await page.evaluate(() => window.sftpFileManager.showActionSheet('left', null));
    await page.locator('#fmActionSheet [data-action="newfile"]').click();
    await expect(page.locator('dialog.fm-mutation-dialog')).toBeVisible();
    expect(await page.locator('dialog.fm-mutation-dialog').evaluate(element => element.getBoundingClientRect().width <= innerWidth)).toBe(true);
});
