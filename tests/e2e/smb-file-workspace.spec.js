const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({ viewport: { width: 1440, height: 1024 }, trace: 'off' });

async function enableSmbTestDouble(page, {
    connect = true,
    failFirstAuthentication = true,
    access = {
        list: 'granted',
        create_file: 'granted',
        create_directory: 'granted',
        delete_children: 'granted',
    },
} = {}) {
    await login(page);
    await page.evaluate(({ shouldConnect, shouldFailFirstAuthentication, rootAccess }) => {
        openFileManager();
        const manager = window.sftpFileManager;
        manager.smbEnabled = true;
        manager.smbSourceDialog.enabled = true;
        const launcher = document.getElementById('fmNewSmbSource');
        launcher.disabled = false;
        launcher.removeAttribute('aria-disabled');
        launcher.querySelector('[data-i18n="fm.workspace.smbSecure"]').classList.remove('hidden');
        launcher.querySelector('[data-i18n="fm.workspace.disabledByAdmin"]').classList.add('hidden');
        manager.openSourceLauncher('left');

        const originalEmit = window.socket.emit.bind(window.socket);
        window.__smbTest = {
            connectCount: 0,
            passwordWasPresent: false,
            cancelRequestId: null,
            connectRequestId: null,
            savedPayload: null,
            savedShares: [],
            rootAccess,
        };
        const notify = (event, payload) => queueMicrotask(() => {
            window.socket.listeners(event).forEach(listener => listener(payload));
        });
        window.socket.emit = function smbWorkspaceTestEmit(event, payload, ...rest) {
            if (event === 'smb_quick_connect') {
                window.__smbTest.connectCount += 1;
                window.__smbTest.passwordWasPresent = typeof payload.password === 'string'
                    && payload.password.length > 0;
                window.__smbTest.connectRequestId = payload.request_id;
                if (shouldConnect) {
                    if (shouldFailFirstAuthentication && window.__smbTest.connectCount === 1) {
                        notify('smb_quick_connect_error', {
                            request_id: payload.request_id,
                            code: 'AUTHENTICATION_REQUIRED',
                        });
                    } else {
                        notify('smb_quick_connect_success', {
                            request_id: payload.request_id,
                            file_source: {
                                source_id: 'smb-quick:e2eowned',
                                kind: 'smb',
                                label: 'nas.example / Docs',
                                endpoint: 'nas.example:445 / Docs',
                                protocol: 'SMB 3.1.1',
                                capabilities: [
                                    'list', 'read', 'write', 'mkdir', 'rename',
                                    'delete', 'preview', 'edit', 'recursive',
                                    'remote-transfer',
                                ],
                                ephemeral: true,
                                security: {
                                    encrypted: true,
                                    signed: true,
                                    secure_negotiate: true,
                                },
                                access: rootAccess,
                            },
                        });
                    }
                }
                return window.socket;
            }
            if (event === 'smb_quick_connect_cancel') {
                window.__smbTest.cancelRequestId = payload.request_id;
                return window.socket;
            }
            if (event === 'save_smb_share') {
                window.__smbTest.savedPayload = { ...payload };
                const now = new Date().toISOString();
                const existing = window.__smbTest.savedShares.find(
                    share => share.id === payload.id
                );
                const share = {
                    id: payload.id || 'smb-e2e-saved-1',
                    name: payload.name,
                    host: payload.host,
                    share: payload.share,
                    domain: payload.domain,
                    username: payload.username,
                    created_at: existing?.created_at || now,
                    updated_at: now,
                };
                window.__smbTest.savedShares = [
                    ...window.__smbTest.savedShares.filter(
                        item => item.id !== share.id
                    ),
                    share,
                ];
                notify('smb_share_saved', {
                    request_id: payload.request_id,
                    success: true,
                    share,
                });
                notify('smb_shares_list', {
                    smb_shares: [...window.__smbTest.savedShares],
                });
                return window.socket;
            }
            if (event === 'delete_smb_share') {
                window.__smbTest.savedShares = window.__smbTest.savedShares.filter(
                    item => item.id !== payload.share_id
                );
                notify('smb_share_deleted', {
                    request_id: payload.request_id,
                    success: true,
                    share_id: payload.share_id,
                });
                notify('smb_shares_list', {
                    smb_shares: [...window.__smbTest.savedShares],
                });
                return window.socket;
            }
            if (event === 'get_home_directory' && payload.source_id === 'smb-quick:e2eowned') {
                notify('home_directory', {
                    source_id: payload.source_id,
                    request_id: payload.request_id,
                    path: '/',
                });
                return window.socket;
            }
            if (event === 'list_directory' && payload.source_id === 'smb-quick:e2eowned') {
                notify('directory_listing', {
                    source_id: payload.source_id,
                    request_id: payload.request_id,
                    path: payload.remote_path,
                    files: [{
                        name: 'report.txt', path: '/report.txt', size: 12,
                        is_dir: false, is_symlink: false, modified: 1786598100,
                    }],
                });
                return window.socket;
            }
            return payload === undefined
                ? originalEmit(event, ...rest)
                : originalEmit(event, payload, ...rest);
        };
    }, {
        shouldConnect: connect,
        shouldFailFirstAuthentication: failFirstAuthentication,
        rootAccess: access,
    });
}

test('disabled SMB control cannot open a dialog or emit a connect event', async ({ page }) => {
    await login(page);
    await page.evaluate(() => {
        window.__disabledSmbEmits = 0;
        const originalEmit = window.socket.emit.bind(window.socket);
        window.socket.emit = function disabledSmbGuard(event, ...args) {
            if (event === 'smb_quick_connect') window.__disabledSmbEmits += 1;
            return originalEmit(event, ...args);
        };
        openFileManager();
    });

    await expect(page.locator('#fmNewSmbSource')).toBeDisabled();
    expect(await page.evaluate(() => window.sftpFileManager.openSMBSourceDialog())).toBe(false);
    await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
    expect(await page.evaluate(() => window.__disabledSmbEmits)).toBe(0);
    await assertNoExternalRequests(page);
});

test('SMB dialog clears credentials, recovers from auth failure and opens an encrypted source', async ({ page }) => {
    await enableSmbTestDouble(page);
    await page.locator('#fmNewSmbSource').click();

    await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await expect(page.locator('[data-i18n="smb.usernameHint"]')).toHaveText(
        'Use alice@example.com or a DNS domain with username alice.',
    );
    const signInHelp = page.locator('[data-i18n="smb.signInHelp"]');
    await expect(signInHelp).toHaveAttribute(
        'href',
        'https://github.com/bifrost0x/webssh/wiki/SFTP-File-Workspace-and-Transfers',
    );
    await expect(signInHelp).toHaveAttribute('rel', 'noopener noreferrer');
    await expect(page.locator('#smbSourceHost')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#smbSourceShare')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#smbSourceDomain')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#smbSourceUsername')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(signInHelp).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#smbSourcePassword')).toBeFocused();
    await page.locator('#smbSourceHost').fill('nas.example');
    await page.locator('#smbSourceShare').fill('Docs');
    await page.locator('#smbSourceDomain').fill('LAB');
    await page.locator('#smbSourceUsername').fill('alice');
    await page.locator('#smbSourcePassword').fill(`runtime-${Date.now()}-${Math.random()}`);
    await page.locator('#smbSourceConnect').click();

    await expect(page.locator('#smbSourcePassword')).toHaveValue('');
    await expect(page.locator('#smbSourceStatus')).toContainText('Authentication failed');
    await expect(page.locator('#smbSourcePassword')).toBeFocused();
    await page.locator('#smbSourcePassword').fill(`retry-${Date.now()}-${Math.random()}`);
    await page.locator('#smbSourceConnect').click();

    await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
    await expect(page.locator('#fmLeftTabs')).toContainText('nas.example / Docs');
    await expect(page.locator('#fmLeftBadge')).toContainText('nas.example:445 / Docs');
    await expect(page.locator('#fmLeftIdentity')).toContainText('Write access at share root');
    await expect(page.locator('#fmLeftList')).toContainText('report.txt');
    const state = await page.evaluate(() => ({
        test: window.__smbTest,
        password: document.getElementById('smbSourcePassword').value,
        localStorage: Object.values(localStorage),
        sessionStorage: Object.values(sessionStorage),
    }));
    expect(state.test.connectCount).toBe(2);
    expect(state.test.passwordWasPresent).toBe(true);
    expect(state.password).toBe('');
    expect([...state.localStorage, ...state.sessionStorage].join(' ')).not.toContain('retry-');
    await assertNoExternalRequests(page);
});

test('read-only SMB access is visible and disables root mutations', async ({ page }) => {
    await enableSmbTestDouble(page, {
        failFirstAuthentication: false,
        access: {
            list: 'granted',
            create_file: 'denied',
            create_directory: 'denied',
            delete_children: 'denied',
        },
    });
    await page.locator('#fmNewSmbSource').click();
    await page.locator('#smbSourceHost').fill('nas.example');
    await page.locator('#smbSourceShare').fill('ReadOnly');
    await page.locator('#smbSourceUsername').fill('alice');
    await page.locator('#smbSourcePassword').fill('browser-only-secret');
    await page.locator('#smbSourceConnect').click();

    expect(await page.evaluate(() => (
        ({
            input: window.__smbTest.rootAccess,
            normalized: window.sftpFileManager.panes.left.source.access,
        })
    ))).toEqual({
        input: {
            list: 'granted',
            create_file: 'denied',
            create_directory: 'denied',
            delete_children: 'denied',
        },
        normalized: {
            list: 'granted',
            createFile: 'denied',
            createDirectory: 'denied',
            deleteChildren: 'denied',
        },
    });
    await expect(page.locator('#fmLeftIdentity')).toContainText('Read-only at share root');
    await expect(page.locator('#fmNewFolder')).toBeDisabled();
    await expect(page.locator('#fmEmbeddedUpload')).toBeDisabled();
    await assertNoExternalRequests(page);
});

test('saved SMB shares persist without passwords and reopen from the source launcher', async ({ page }) => {
    await enableSmbTestDouble(page, { connect: false });
    await page.locator('#fmNewSmbSource').click();
    await page.locator('#smbSourceHost').fill('nas.example');
    await page.locator('#smbSourceShare').fill('Docs');
    await page.locator('#smbSourceDomain').fill('LAB');
    await page.locator('#smbSourceUsername').fill('alice');
    await page.locator('#smbSourcePassword').fill('browser-only-secret');
    await page.locator('#smbSourceName').fill('Team files');
    await page.locator('#smbSourceSave').click();

    await expect(page.locator('#smbSourceSaved')).toContainText('Team files');
    const saved = await page.evaluate(() => ({
        payload: window.__smbTest.savedPayload,
        shares: window.sftpFileManager.savedSmbShares,
        password: document.getElementById('smbSourcePassword').value,
    }));
    expect(saved.payload).toEqual({
        request_id: expect.stringMatching(/^[A-Za-z0-9:._-]+$/),
        name: 'Team files',
        host: 'nas.example',
        share: 'Docs',
        domain: 'LAB',
        username: 'alice',
    });
    expect(JSON.stringify(saved.shares)).not.toContain('browser-only-secret');
    expect(saved.password).toBe('browser-only-secret');

    await page.locator('#smbSourceSaved').selectOption('');
    const savedId = saved.shares[0].id;
    await page.locator('#smbSourceSaved').selectOption(savedId);
    await expect(page.locator('#smbSourcePassword')).toHaveValue('');
    await expect(page.locator('#smbSourcePassword')).toBeFocused();
    await page.keyboard.press('Escape');

    await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
    const savedRow = page.locator(`[data-source-key="smb-saved:${savedId}"]`);
    await expect(savedRow).toContainText('Team files');
    await savedRow.click();
    await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
    await expect(page.locator('#smbSourceHost')).toHaveValue('nas.example');
    await expect(page.locator('#smbSourcePassword')).toHaveValue('');
    await expect(page.locator('#smbSourcePassword')).toBeFocused();

    page.once('dialog', dialog => dialog.accept());
    await page.locator('#smbSourceDeleteSaved').click();
    await expect(page.locator('#smbSourceSaved')).not.toContainText('Team files');
    await assertNoExternalRequests(page);
});

test('SMB editor remembers recoverable-swap consent for the current connection', async ({ page }) => {
    await login(page);

    const state = await page.evaluate(() => {
        const preview = window.FilePreview;
        const originalEmit = window.socket.emit.bind(window.socket);
        const emitted = [];
        let confirmations = 0;
        window.confirm = () => {
            confirmations += 1;
            return true;
        };
        window.socket.emit = function editorConsentTest(event, payload, ...rest) {
            if (event === 'save_file') {
                emitted.push({ ...payload });
                return window.socket;
            }
            return originalEmit(event, payload, ...rest);
        };

        preview.currentSourceId = 'smb-quick:e2eowned';
        preview.currentPath = '/report.txt';
        preview.editMode = true;
        preview.editRevision = 'a'.repeat(64);
        preview.dirty = true;
        document.getElementById('editorContent').value = 'updated';
        preview.saveEdit();
        preview.handleSocketError({
            operation: 'save_file',
            source_id: 'smb-quick:e2eowned',
            request_id: preview.currentSaveRequestId,
            path: '/report.txt',
            error: 'This SMB account cannot replace the file atomically.',
            code: 'SMB_RECOVERABLE_REPLACE_REQUIRED',
            revision: 'a'.repeat(64),
        });
        preview.saveEdit();

        return {
            emitted,
            confirmations,
            status: document.getElementById('editorStatus').textContent,
        };
    });

    expect(state.confirmations).toBe(1);
    expect(state.emitted).toHaveLength(3);
    expect(state.emitted[0]).toMatchObject({
        expected_revision: 'a'.repeat(64),
        replace_strategy: 'atomic',
    });
    expect(state.emitted[1]).toMatchObject({
        expected_revision: 'a'.repeat(64),
        replace_strategy: 'recoverable_swap',
    });
    expect(state.emitted[1]).not.toHaveProperty('allow_non_atomic');
    expect(state.emitted[2]).toMatchObject({
        expected_revision: 'a'.repeat(64),
        replace_strategy: 'recoverable_swap',
    });
    expect(state.status).toBe('Saving...');
    await assertNoExternalRequests(page);
});

test('SMB editor keeps dirty content and names safe recovery artifacts', async ({ page }) => {
    await login(page);

    const state = await page.evaluate(() => {
        const preview = window.FilePreview;
        preview.currentSourceId = 'smb-quick:e2eowned';
        preview.currentPath = '/report.txt';
        preview.currentSaveRequestId = 'save:recovery:1';
        preview.editMode = true;
        preview.dirty = true;
        preview.handleSocketError({
            operation: 'save_file',
            source_id: 'smb-quick:e2eowned',
            request_id: 'save:recovery:1',
            path: '/report.txt',
            error: 'Manual recovery is required.',
            code: 'SMB_RECOVERY_REQUIRED',
            recovery_leaves: [
                '.report.txt.webssh-write-safe.tmp',
                '.report.txt.webssh-recovery-safe.bak',
            ],
        });
        return {
            dirty: preview.dirty,
            status: document.getElementById('editorStatus').textContent,
        };
    });

    expect(state.dirty).toBe(true);
    expect(state.status).toContain('.report.txt.webssh-write-safe.tmp');
    expect(state.status).toContain('.report.txt.webssh-recovery-safe.bak');
    await assertNoExternalRequests(page);
});

test('mobile Escape cancels the exact pending attempt, clears password and returns focus', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await enableSmbTestDouble(page, { connect: false });
    await page.locator('#fmNewSmbSource').click();
    await page.locator('#smbSourceHost').fill('nas.example');
    await page.locator('#smbSourceShare').fill('Docs');
    await page.locator('#smbSourceUsername').fill('alice');
    await page.locator('#smbSourcePassword').fill(`runtime-${Date.now()}-${Math.random()}`);
    await page.locator('#smbSourceConnect').click();
    await page.keyboard.press('Escape');

    await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
    await expect(page.locator('#smbSourcePassword')).toHaveValue('');
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    const ids = await page.evaluate(() => ({
        connect: window.__smbTest.connectRequestId,
        cancel: window.__smbTest.cancelRequestId,
    }));
    expect(ids.cancel).toBe(ids.connect);
    await assertNoExternalRequests(page);
});

test('SMB dialog remains contained across desktop, tablet and mobile viewports', async ({ page }) => {
    await enableSmbTestDouble(page, { connect: false });
    const viewports = [
        { width: 1440, height: 1024 },
        { width: 900, height: 900 },
        { width: 768, height: 1024 },
        { width: 390, height: 844 },
    ];

    for (const viewport of viewports) {
        await page.setViewportSize(viewport);
        await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
        await page.locator('#fmNewSmbSource').click();
        await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
        const geometry = await page.evaluate(() => {
            const shell = document.querySelector('.smb-source-shell');
            const footer = document.querySelector('.smb-source-actions');
            footer.scrollIntoView({ block: 'end' });
            const shellBox = shell.getBoundingClientRect();
            const footerBox = footer.getBoundingClientRect();
            return {
                documentWidth: document.documentElement.scrollWidth,
                viewportWidth: window.innerWidth,
                left: shellBox.left,
                right: shellBox.right,
                top: shellBox.top,
                bottom: shellBox.bottom,
                footerBottom: footerBox.bottom,
                viewportHeight: window.innerHeight,
            };
        });
        expect(geometry.documentWidth).toBeLessThanOrEqual(geometry.viewportWidth);
        expect(geometry.left).toBeGreaterThanOrEqual(0);
        expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth);
        expect(geometry.top).toBeGreaterThanOrEqual(0);
        expect(geometry.bottom).toBeLessThanOrEqual(geometry.viewportHeight);
        expect(geometry.footerBottom).toBeLessThanOrEqual(geometry.viewportHeight);
        await page.keyboard.press('Escape');
        await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
    }

    await assertNoExternalRequests(page);
});
