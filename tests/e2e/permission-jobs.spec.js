const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

async function setup(page, { hold = false, count = 24 } = {}) {
    await login(page);
    await page.evaluate(({ hold, count }) => {
        openFileManager();
        const manager = window.sftpFileManager;
        manager.closeSourceLauncher();
        window.__permissionJobEvents = [];
        window.__permissionJobReplies = [];
        window.__holdPermissionJobs = hold;
        const emit = window.socket.emit.bind(window.socket);
        window.__replyPermissionJob = (request, fields = {}) => {
            const reply = { ...request.payload, operation: request.event, job_id: 'preview-job', state: request.event === 'prepare_file_permissions' ? 'ready' : request.event === 'cancel_file_permissions_job' ? 'cancelled' : 'running', files: count - 1, directories: 1, skipped: 2, changed: 0, processed: 0, total: count, current_modes: { files: { '600': count - 1 }, directories: { '700': 1 } }, ...fields };
            window.__permissionJobReplies.push(reply);
            window.socket.listeners('file_permissions_job').forEach(listener => listener(reply));
        };
        window.socket.emit = (event, payload, ...rest) => {
            if (['prepare_file_permissions', 'get_file_permissions_job', 'apply_file_permissions_job', 'cancel_file_permissions_job'].includes(event)) {
                const request = { event, payload };
                window.__permissionJobEvents.push(request);
                if (!window.__holdPermissionJobs) queueMicrotask(() => window.__replyPermissionJob(request));
                return window.socket;
            }
            return emit(event, payload, ...rest);
        };
        Object.assign(manager.panes.left, manager.createEmptyPaneState(), {
            source: { sourceId: 'sftp-session:permissions-test', kind: 'sftp', label: 'Test source', capabilities: ['list', 'chmod'], access: {} },
            path: '/work', files: Array.from({ length: count }, (_, index) => ({ name: index ? `file-${index}.txt` : 'folder', is_dir: index === 0 })),
            selected: new Set(Array.from({ length: count }, (_, index) => index)),
        });
        manager.setActivePane('left');
        manager.renderPane('left');
        manager.updateWorkspaceActions();
        manager.changePermissions('left');
    }, { hold, count });
    return page.locator('dialog.fm-permission-job-dialog');
}

async function events(page, operation) {
    return page.evaluate(operation => window.__permissionJobEvents.filter(request => request.event === operation), operation);
}

test('recursive permission preview keeps file and folder modes separate and needs deliberate apply', async ({ page }) => {
    const dialog = await setup(page);
    await expect(dialog.locator('[name="recursive"]')).not.toBeChecked();
    await expect(dialog.locator('[name="file_mode"]')).toHaveValue('644');
    await expect(dialog.locator('[name="directory_mode"]')).toHaveValue('755');
    await dialog.locator('[name="file_mode"]').fill('640');
    await dialog.locator('[name="directory_mode"]').fill('750');
    await dialog.locator('[name="recursive"]').check();
    await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
    await expect(dialog.locator('.fm-job-counts')).toContainText('Files: 23');
    await expect(dialog.locator('.fm-job-counts')).toContainText('Skipped links: 2');
    await expect(dialog.locator('.fm-job-current')).toContainText('600');
    await expect(dialog.locator('.fm-job-current')).toContainText('700');
    await expect(dialog.locator('.fm-job-plan')).toContainText('640');
    await expect(dialog.locator('.fm-job-plan')).toContainText('750');
    const prepared = await events(page, 'prepare_file_permissions');
    expect(prepared).toHaveLength(1);
    expect(prepared[0].payload.paths).toHaveLength(24);
    expect(prepared[0].payload).toMatchObject({ recursive: true, file_mode: '640', directory_mode: '750' });
    expect(await events(page, 'apply_file_permissions_job')).toHaveLength(0);
    await expect(dialog.locator('[name="file_mode"]')).toBeDisabled();
    await test.info().attach('recursive-permissions-desktop', { body: await page.screenshot({ path: test.info().outputPath('permissions-desktop.png') }), contentType: 'image/png' });
    await dialog.getByRole('button', { name: 'Apply permissions', exact: true }).click();
    const writes = await events(page, 'apply_file_permissions_job');
    expect(writes).toHaveLength(1);
    expect(Object.keys(writes[0].payload).sort()).toEqual(['job_id', 'request_id', 'source_id']);
    await expect(dialog.getByRole('button', { name: 'Preview changes', exact: true })).toBeDisabled();
    await page.evaluate(() => {
        const request = window.__permissionJobEvents.find(value => value.event === 'apply_file_permissions_job');
        window.sftpFileManager.mutationDialog.pending = true;
        const id = window.sftpFileManager.registerOperationRequest(request.payload.source_id, 'get_file_permissions_job');
        window.sftpFileManager.pendingOperationRequests.get(id).permissionJobDialog = window.sftpFileManager.mutationDialog;
        window.__replyPermissionJob({ event: 'get_file_permissions_job', payload: { ...request.payload, request_id: id } }, { state: 'completed', changed: 24, processed: 24 });
    });
    await expect(dialog.getByRole('status')).toContainText('completed');
    await assertNoExternalRequests(page);
});

test('permission lockout warning requires explicit acknowledgment and preview changes cancel the old plan', async ({ page }) => {
    const dialog = await setup(page);
    await dialog.locator('[name="directory_mode"]').fill('600');
    await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
    const apply = dialog.getByRole('button', { name: 'Apply permissions', exact: true });
    await expect(apply).toBeDisabled();
    await expect(dialog.locator('.fm-job-ack')).toBeVisible();
    await dialog.locator('[name="acknowledge"]').check();
    await expect(apply).toBeEnabled();
    await dialog.getByRole('button', { name: 'Change settings', exact: true }).click();
    await expect(dialog.locator('[name="directory_mode"]')).toBeEnabled();
    expect(await events(page, 'cancel_file_permissions_job')).toHaveLength(1);
    expect(await events(page, 'apply_file_permissions_job')).toHaveLength(0);
    await expect(dialog.locator('[name="acknowledge"]')).not.toBeChecked();
});

for (const reason of ['close', 'navigation']) {
    test(`permission preview cancels its owned job after ${reason}, including a late prepare response`, async ({ page }) => {
        const dialog = await setup(page, { hold: true });
        await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
        await page.evaluate(reason => {
            const manager = window.sftpFileManager;
            if (reason === 'close') manager.mutationDialog.close();
            else manager.panes.left.mutationViewVersion = (manager.panes.left.mutationViewVersion || 0) + 1;
            window.__replyPermissionJob(window.__permissionJobEvents[0]);
        }, reason);
        await expect.poll(async () => (await events(page, 'cancel_file_permissions_job')).length).toBe(1);
        expect(await events(page, 'apply_file_permissions_job')).toHaveLength(0);
    });
}

test('permission response from another source cannot enable apply and disconnect never replays a write', async ({ page }) => {
    const dialog = await setup(page, { hold: true });
    await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
    await page.evaluate(() => window.__replyPermissionJob(window.__permissionJobEvents[0], { source_id: 'sftp-session:foreign' }));
    await expect(dialog.getByRole('button', { name: 'Preview changes', exact: true })).toBeDisabled();
    await page.evaluate(() => window.__replyPermissionJob(window.__permissionJobEvents[0]));
    await dialog.getByRole('button', { name: 'Apply permissions', exact: true }).click();
    await page.evaluate(() => window.socket.listeners('disconnect').forEach(listener => listener('transport close')));
    await expect(dialog.getByRole('status')).toContainText('unknown');
    await expect(dialog.locator('[type="submit"]')).toBeDisabled();
    expect(await events(page, 'apply_file_permissions_job')).toHaveLength(1);
});

test('permissions dialog is usable at 360px and keeps review and confirmation in the viewport', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    const dialog = await setup(page);
    await dialog.locator('[name="recursive"]').check();
    await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
    await expect(dialog.getByRole('button', { name: 'Apply permissions', exact: true })).toBeEnabled();
    expect(await dialog.evaluate(element => { const bounds = element.getBoundingClientRect(); return bounds.left >= 0 && bounds.right <= innerWidth && bounds.top >= 0 && bounds.bottom <= innerHeight && element.scrollWidth <= element.clientWidth + 1; })).toBe(true);
    await expect(dialog.locator('.fm-job-preview')).toBeInViewport();
    await test.info().attach('recursive-permissions-360', { body: await page.screenshot({ path: test.info().outputPath('permissions-360.png') }), contentType: 'image/png' });
    await dialog.getByRole('button', { name: 'Apply permissions', exact: true }).click();
    expect(await events(page, 'apply_file_permissions_job')).toHaveLength(1);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    expect(await events(page, 'cancel_file_permissions_job')).toHaveLength(1);
    await assertNoExternalRequests(page);
});


test('stopping a running job retains confirmed partial results and never retries apply', async ({ page }) => {
    const dialog = await setup(page);
    await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
    await dialog.getByRole('button', { name: 'Apply permissions', exact: true }).click();
    await expect(dialog.getByRole('button', { name: 'Stop remaining work', exact: true })).toBeEnabled();
    await page.evaluate(() => { window.__holdPermissionJobs = true; });
    await dialog.getByRole('button', { name: 'Stop remaining work', exact: true }).click();
    await page.evaluate(() => {
        const request = window.__permissionJobEvents.find(value => value.event === 'cancel_file_permissions_job');
        window.__replyPermissionJob(request, { state: 'cancelled', changed: 3, processed: 5 });
    });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('status')).toContainText('Cancelled');
    await expect(dialog.locator('.fm-job-counts')).toContainText('Changed: 3 / 24');
    await expect(dialog.locator('.fm-job-partial')).toContainText('Changes already completed remain');
    await expect(dialog.locator('[type="submit"]')).toBeDisabled();
    expect(await events(page, 'apply_file_permissions_job')).toHaveLength(1);
});

for (const order of ['close-first', 'complete-first']) {
    test(`permission completion refreshes the bound source once with ${order} and ignores foreign replies`, async ({ page }) => {
        const dialog = await setup(page);
        await dialog.getByRole('button', { name: 'Preview changes', exact: true }).click();
        await page.evaluate(() => {
            window.__holdPermissionJobs = true;
            window.__permissionRefreshes = [];
            window.sftpFileManager.refreshSource = source => window.__permissionRefreshes.push(source);
        });
        await dialog.getByRole('button', { name: 'Apply permissions', exact: true }).click();
        await page.evaluate(order => {
            const request = window.__permissionJobEvents.find(value => value.event === 'apply_file_permissions_job');
            const manager = window.sftpFileManager;
            if (order === 'close-first') manager.mutationDialog.close();
            window.__replyPermissionJob(request, { state: 'completed', changed: 24, processed: 24, source_id: 'sftp-session:foreign' });
            if (window.__permissionRefreshes.length) throw new Error('A foreign-source reply refreshed the bound source');
            window.__replyPermissionJob(request, { state: 'completed', changed: 24, processed: 24 });
            if (order === 'complete-first') manager.mutationDialog.close();
            window.__replyPermissionJob(request, { state: 'completed', changed: 24, processed: 24 });
        }, order);
        await expect(dialog).toHaveCount(0);
        expect(await page.evaluate(() => window.__permissionRefreshes)).toEqual(['sftp-session:permissions-test']);
        expect(await events(page, 'apply_file_permissions_job')).toHaveLength(1);
    });
}
