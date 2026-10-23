const { test, expect } = require('playwright/test');
const { login } = require('../e2e/helpers');

// Requires the disposable Paramiko/OpenSSH lab and SFTP_CHMOD_ENABLED=true.
test('real browser creates, changes permissions, edits and reopens a remote file', async ({ page }) => {
    await login(page);
    await page.evaluate(async () => {
        const socket = window.io({ forceNew: true, auth: { wire_revision: 2 } });
        window.liveMutationSocket = socket;
        socket.on('ssh_output', (_data, acknowledge) => acknowledge?.());
        socket.on('ssh_host_key', prompt => {
            if (prompt.host !== '127.0.0.1' || prompt.port !== 2223) throw new Error('Unexpected lab host');
            socket.emit('ssh_host_key_decision', { prompt_id: prompt.prompt_id, client_request_id: prompt.client_request_id, accepted: true });
        });
        const connected = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('Lab SSH connection timed out')), 15000);
            socket.once('ssh_error', data => { clearTimeout(timer); reject(new Error(data.error)); });
            socket.once('ssh_connected', data => { clearTimeout(timer); resolve(data); });
            socket.emit('ssh_connect', { host: '127.0.0.1', port: 2223, username: 'testuser', password: 'Paramiko5-Test-Only!', client_request_id: 'live-mutations' });
        });
        openFileManager();
        const manager = window.sftpFileManager;
        manager.closeSourceLauncher();
        window.liveMutationSession = connected.session_id;
        manager.availableSessions.push({ ...connected, connected: true });
        await manager.openWorkspaceSource('left', manager.normalizeSourceDescriptor(connected.file_source));
        await manager.navigatePaneTo('left', '/tmp');
    });
    await expect(page.locator('#fmLeftPane [data-pane-action="newfile"]')).toBeEnabled();
    const name = `browser-mutations-${Date.now()}.txt`;
    try {
        await page.locator('#fmLeftPane [data-pane-action="newfile"]').click();
        let dialog = page.locator('dialog.fm-mutation-dialog');
        await dialog.locator('[name="filename"]').fill(name);
        await dialog.getByRole('button', { name: 'Create file', exact: true }).click();
        await expect(dialog).toHaveCount(0);
        await page.locator('#fmLeftList .fm-file-item').filter({ hasText: name }).click();
        await page.locator('#fmLeftPane [data-pane-action="permissions"]').click();
        dialog = page.locator('dialog.fm-permission-job-dialog');
        await expect(dialog.locator('[name="recursive"]')).not.toBeChecked();
        await page.screenshot({ path: test.info().outputPath('browser-live-desktop.png') });
        await dialog.locator('[name="file_mode"]').fill('750');
        await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
        await expect(dialog.locator('.fm-job-current')).toContainText('600');
        await expect(dialog.locator('.fm-job-plan')).toContainText('750');
        await dialog.getByRole('button', { name: 'Apply permissions' }).click();
        await expect(dialog.getByRole('status')).toContainText('completed');
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await page.evaluate(name => window.FilePreview.openForEditing(`sftp-session:${window.liveMutationSession}`, `/tmp/${name}`, name), name);
        await expect(page.locator('#editorContent')).toBeVisible();
        await page.locator('#editorContent').fill('verified through the real browser\n');
        await page.locator('#editorSaveBtn').click();
        await page.locator('#editorCommitBtn').click();
        await expect(page.locator('#fileEditor')).toBeHidden();
        await page.evaluate(name => window.FilePreview.openForEditing(`sftp-session:${window.liveMutationSession}`, `/tmp/${name}`, name), name);
        await expect(page.locator('#editorContent')).toHaveValue('verified through the real browser\n');
        await page.evaluate(() => window.FilePreview.close());
        await page.locator('#fmLeftList .fm-file-item').filter({ hasText: name }).click();
        await page.locator('#fmLeftPane [data-pane-action="permissions"]').click();
        dialog = page.locator('dialog.fm-permission-job-dialog');
        await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
        await expect(dialog.locator('.fm-job-current')).toContainText('750');
        await expect(dialog.locator('[name="recursive"]')).not.toBeChecked();
        await page.setViewportSize({ width: 390, height: 844 });
        await page.screenshot({ path: test.info().outputPath('browser-live-mobile.png') });
    } finally {
        if (!page.isClosed()) await page.evaluate(name => {
            window.sftpFileManager.mutationDialog?.close();
            window.socket.emit('delete_file', { source_id: `sftp-session:${window.liveMutationSession}`, path: `/tmp/${name}`, request_id: 'live-cleanup' });
            window.liveMutationSocket.disconnect();
        }, name).catch(() => {});
    }
});
