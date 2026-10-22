const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

async function workspace(page, kind = 'sftp', chmod = true, enabled = false) {
    await page.addInitScript(value => {
        document.addEventListener('DOMContentLoaded', () => { document.body.dataset.sftpChmodEnabled = String(value); });
    }, enabled);
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

for (const kind of ['sftp', 'smb']) {
    for (const order of ['preview-first', 'edit-first']) {
        test(`new ${kind} file stays in the editor with ${order} responses`, async ({ page }) => {
            try {
                await page.setViewportSize({ width: kind === 'sftp' ? 1536 : 390, height: 960 });
                await workspace(page, kind, false);
                await page.evaluate(() => {
                    window.__previewRequests = [];
                    const emit = window.socket.emit.bind(window.socket);
                    window.socket.emit = (event, payload, ...rest) => {
                        if (['preview_file', 'open_file_for_edit'].includes(event)) {
                            window.__previewRequests.push({ event, payload: structuredClone(payload) });
                            return window.socket;
                        }
                        if (event === 'list_directory' && payload.source_id.endsWith(':mutation-test')) {
                            queueMicrotask(() => window.socket.listeners('directory_listing').forEach(listener => listener({
                                ...payload, path: payload.remote_path, files: [{ name: 'new.txt', is_dir: false, size: 0 }],
                            })));
                            return window.socket;
                        }
                        return emit(event, payload, ...rest);
                    };
                });
                await page.locator('#fmLeftPane [data-pane-action="newfile"]').click();
                const dialog = page.locator('dialog.fm-mutation-dialog');
                await dialog.locator('[name="filename"]').fill('new.txt');
                await dialog.locator('[name="edit"]').check();
                await dialog.getByRole('button', { name: 'Create file', exact: true }).click();
                await page.evaluate(() => {
                    const created = window.__mutationEvents.find(item => item.event === 'create_file').payload;
                    window.socket.listeners('file_created').forEach(listener => listener({
                        ...created, operation: 'create_file', path: '/new.txt', size: 0,
                    }));
                });
                await expect(dialog).toHaveCount(0);
                await expect.poll(() => page.evaluate(() => window.__previewRequests.map(item => item.event)))
                    .toEqual(['preview_file', 'open_file_for_edit']);
                const respond = async event => page.evaluate(eventName => {
                    const request = window.__previewRequests.find(item => item.event === eventName).payload;
                    const response = eventName === 'preview_file'
                        ? { ...request, filename: 'new.txt', content: '', size: 0, truncated: false, is_binary: false }
                        : { ...request, content: '', revision: 'new-file-revision', encoding: 'utf-8', newline: 'lf' };
                    const responseEvent = eventName === 'preview_file' ? 'preview_data' : 'edit_data';
                    window.socket.listeners(responseEvent).forEach(listener => listener(response));
                }, event);
                if (order === 'preview-first') {
                    await respond('preview_file');
                    await expect(page.locator('#previewContent')).toBeVisible();
                    await respond('open_file_for_edit');
                } else {
                    await respond('open_file_for_edit');
                }
                await expect(page.locator('#fileEditor')).toBeVisible();
                await page.locator('#editorContent').fill('unsaved draft');
                if (order === 'edit-first') await respond('preview_file');

                await expect(page.locator('#editorContent')).toHaveValue('unsaved draft');
                for (const id of ['previewContent', 'previewLoading', 'previewError', 'previewImage', 'previewBinary',
                    'previewTruncated', 'previewEditBtn', 'previewCopyBtn', 'previewDownloadBtn', 'previewRefreshBtn']) {
                    await expect(page.locator(`#${id}`)).toBeHidden();
                }
                expect(await page.evaluate(() => ({ revision: window.FilePreview.editRevision, dirty: window.FilePreview.dirty })))
                    .toEqual({ revision: 'new-file-revision', dirty: true });
                page.once('dialog', confirmation => confirmation.accept());
                await page.locator('#editorCancelBtn').click();
                await expect(page.locator('#fileEditor')).toBeHidden();
                await expect(page.locator('#previewContent')).toBeVisible();
                await expect(page.locator('#previewCode')).toHaveText('');
                await expect(page.locator('#previewEditBtn')).toBeVisible();
                await expect(page.locator('#previewCopyBtn')).toBeEnabled();
                expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'create_file').length)).toBe(1);
                expect(await page.evaluate(() => window.__previewRequests.length)).toBe(2);
            } finally {
                await assertNoExternalRequests(page);
            }
        });
    }
}


test('enabled instance hides chmod setup help for capable SFTP, unsupported SMB and no source', async ({ page }) => {
    await workspace(page, 'sftp', true, true);
    const help = page.locator('.fm-permissions-help');
    await expect(help).toBeHidden();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.panes.left.source = { sourceId: 'smb-quick:unsupported', kind: 'smb', capabilities: ['list'] };
        manager.updateWorkspaceActions();
    });
    await expect(help).toBeHidden();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.panes.left.source = null;
        manager.updateWorkspaceActions();
    });
    await expect(help).toBeHidden();
});

async function multiSelection(page, options = {}) {
    await workspace(page);
    await page.evaluate(({ mixed = false, failInspect = false, symlink = false }) => {
        const manager = window.sftpFileManager;
        const state = manager.panes.left;
        state.files = [{ name: 'first.txt', is_dir: false }, { name: 'second', is_dir: true }, { name: 'last.txt', is_dir: false }];
        state.selected = new Set([0, 1, 2]);
        manager.renderPane('left');
        manager.updateWorkspaceActions();
        window.__permissionClock = 100;
        window.__metadataReplies = [];
        window.__metadataReads = {};
        window.socket.emit = (event, payload) => {
            if (['get_file_permissions', 'set_file_permissions'].includes(event)) {
                window.__mutationEvents.push({ event, payload });
                if (event === 'get_file_permissions') queueMicrotask(() => {
                    if (symlink && payload.path.endsWith('/second')) {
                        window.socket.listeners('error').forEach(listener => listener({ ...payload, operation: event, code: 'UNSUPPORTED_OPERATION', error: 'This file operation is not supported.' }));
                        return;
                    }
                    const mode = mixed && payload.path.endsWith('/second') ? '750' : '600';
                    const read = window.__metadataReads[payload.path] = (window.__metadataReads[payload.path] || 0) + 1;
                    const digest = window.__metadataDigestOverride || (state.files.findIndex(file => payload.path.endsWith(`/${file.name}`)) + 1).toString(16).padStart(64, '0');
                    const reply = {
                        ...payload, operation: event, mode, object_type: payload.path.endsWith('/second') ? 'directory' : 'file',
                        special_bits: failInspect && payload.path.endsWith('/second') ? 0o1000 : 0,
                        metadata_token: `${window.__permissionClock + read}.${digest}.${'a'.repeat(64)}`,
                    };
                    window.__metadataReplies.push(reply);
                    if (window.__holdRechecks && read > 1) return;
                    window.socket.listeners('file_permissions').forEach(listener => listener(reply));
                });
            }
            return window.socket;
        };
    }, options);
    await page.locator('#fmLeftPane [data-pane-action="permissions"]').click();
    const dialog = page.locator('dialog.fm-mutation-dialog');
    await expect.poll(() => page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'get_file_permissions').length)).toBe(options.failInspect || options.symlink ? 2 : 3);
    return dialog;
}

test('bulk chmod inspects all targets, applies serially and stops after a metadata conflict', async ({ page }) => {
    const dialog = await multiSelection(page, { mixed: true });
    const apply = dialog.getByRole('button', { name: 'Apply permissions' });
    await expect(dialog.locator('[name="mode"]')).toHaveValue('');
    await expect(apply).toBeDisabled();
    await dialog.locator('[name="mode"]').fill('750');
    await apply.click();
    await expect(apply).toBeDisabled();
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(1);
    await page.evaluate(() => {
        const payload = window.__mutationEvents.find(item => item.event === 'set_file_permissions').payload;
        const replies = window.__metadataReplies.filter(reply => reply.path === payload.path);
        if (replies.length !== 2 || replies[0].metadata_token === replies[1].metadata_token || payload.expected_metadata !== replies[1].metadata_token) throw new Error('SET must use the freshly inspected token after the same digest was confirmed');
        window.socket.listeners('file_permissions_changed').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', mode: '750' }));
    });
    // The matching directory needs no write. The next changed file is the only next request.
    await expect.poll(() => page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(2);
    await page.evaluate(() => {
        const payload = window.__mutationEvents.filter(item => item.event === 'set_file_permissions')[1].payload;
        window.socket.listeners('error').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', code: 'METADATA_CHANGED', error: 'Metadata changed.' }));
    });
    await expect(dialog.getByRole('status')).toContainText('Stopped');
    await expect(dialog.locator('.fm-mutation-results')).toContainText('Changed');
    await expect(dialog.locator('.fm-mutation-results')).toContainText('Failed');
    await expect(apply).toBeDisabled();
});

test('unsupported metadata blocks the whole selection before any write', async ({ page }) => {
    const dialog = await multiSelection(page, { failInspect: true });
    await expect(dialog.getByRole('status')).toContainText('Stopped');
    await expect(dialog.getByRole('button', { name: 'Apply permissions' })).toBeDisabled();
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(0);
});

test('closing bulk chmod leaves remaining items unsent even after a late success', async ({ page }) => {
    const dialog = await multiSelection(page);
    await expect(dialog.locator('[name="mode"]')).toHaveValue('600');
    await dialog.locator('[name="mode"]').fill('750');
    await dialog.getByRole('button', { name: 'Apply permissions' }).click();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await page.evaluate(() => {
        const payload = window.__mutationEvents.find(item => item.event === 'set_file_permissions').payload;
        window.socket.listeners('file_permissions_changed').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', mode: '750' }));
    });
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(1);
});


for (const reason of ['disconnect', 'stale']) {
    test(`bulk chmod stops unsent remainder after ${reason} during a pending write`, async ({ page }) => {
        const dialog = await multiSelection(page);
        await dialog.locator('[name="mode"]').fill('750');
        await dialog.getByRole('button', { name: 'Apply permissions' }).click();
        await page.evaluate(reason => {
            const manager = window.sftpFileManager;
            if (reason === 'disconnect') window.socket.listeners('disconnect').forEach(listener => listener('transport close'));
            else manager.panes.left.mutationViewVersion = (manager.panes.left.mutationViewVersion || 0) + 1;
            const payload = window.__mutationEvents.find(item => item.event === 'set_file_permissions').payload;
            window.socket.listeners('file_permissions_changed').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', mode: '750' }));
        }, reason);
        await expect(dialog.locator('[data-outcome="not-sent"]')).toHaveCount(2);
        await expect(dialog.locator('[data-outcome="completed"]')).toHaveCount(1);
        expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(1);
    });
}

test('bulk chmod rejects a symlink during inspection without writing', async ({ page }) => {
    const dialog = await multiSelection(page, { symlink: true });
    await expect(dialog.locator('[data-outcome="failed"]')).toHaveCount(1);
    await expect(dialog.getByRole('button', { name: 'Apply permissions' })).toBeDisabled();
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(0);
});

test('bulk chmod warns before removing directory traversal in a mixed selection', async ({ page }) => {
    const dialog = await multiSelection(page);
    await dialog.locator('[name="mode"]').fill('640');
    page.once('dialog', confirmation => confirmation.dismiss());
    await dialog.getByRole('button', { name: 'Apply permissions' }).click();
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(0);
    page.once('dialog', confirmation => confirmation.accept());
    await dialog.getByRole('button', { name: 'Apply permissions' }).click();
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(1);
});

test('bulk chmod enforces the 20 item limit on desktop, mobile and context actions', async ({ page }) => {
    await workspace(page);
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        const state = manager.panes.left;
        state.files = Array.from({ length: 21 }, (_, index) => ({ name: `${index}.txt`, is_dir: false }));
        state.selected = new Set(state.files.map((_, index) => index));
        manager.renderPane('left');
        manager.updateWorkspaceActions();
    });
    const action = page.locator('#fmLeftPane [data-pane-action="permissions"]');
    await expect(action).toBeDisabled();
    await expect(action).toHaveAttribute('title', /20/);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => window.sftpFileManager.showActionSheet('left', 0));
    await expect(page.locator('#fmActionSheet [data-action="permissions"]')).toBeDisabled();
    await page.evaluate(() => window.sftpFileManager.handleContextAction('permissions', 'left', 0));
    await expect(page.locator('dialog.fm-mutation-dialog')).toHaveCount(0);
    expect(await page.evaluate(() => window.__mutationEvents.length)).toBe(0);
    // A valid selection remains available, while SMB is never eligible.
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.panes.left.selected.delete(20);
        manager.updateWorkspaceActions();
    });
    await expect(action).toBeEnabled();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.panes.left.source = { sourceId: 'smb-quick:test', kind: 'smb', capabilities: ['list'] };
        manager.changePermissions('left');
        manager.updateWorkspaceActions();
    });
    await expect(action).toBeHidden();
    expect(await page.evaluate(() => window.__mutationEvents.length)).toBe(0);
});


test('bulk chmod renews an aged inspection only after confirming the unchanged complete fingerprint', async ({ page }) => {
    const dialog = await multiSelection(page);
    await page.evaluate(() => { window.__permissionClock += 120; });
    await dialog.locator('[name="mode"]').fill('750');
    await dialog.getByRole('button', { name: 'Apply permissions' }).click();
    const sequence = await page.evaluate(() => {
        const set = window.__mutationEvents.find(item => item.event === 'set_file_permissions');
        const replies = window.__metadataReplies.filter(reply => reply.path === set.payload.path);
        return { events: window.__mutationEvents.map(item => `${item.event}:${item.payload.path}`),
            first: replies[0].metadata_token, fresh: replies[1].metadata_token, used: set.payload.expected_metadata };
    });
    expect(sequence.events.slice(0, 5)).toEqual([
        'get_file_permissions:/first.txt', 'get_file_permissions:/second', 'get_file_permissions:/last.txt',
        'get_file_permissions:/first.txt', 'set_file_permissions:/first.txt',
    ]);
    expect(Number(sequence.fresh.split('.')[0]) - Number(sequence.first.split('.')[0])).toBeGreaterThan(60);
    expect(sequence.fresh.split('.')[1]).toBe(sequence.first.split('.')[1]);
    expect(sequence.used).toBe(sequence.fresh);
});

test('bulk chmod detects a changed complete fingerprint before issuing any write', async ({ page }) => {
    const dialog = await multiSelection(page);
    await page.evaluate(() => { window.__metadataDigestOverride = 'f'.repeat(64); });
    await dialog.locator('[name="mode"]').fill('750');
    await dialog.getByRole('button', { name: 'Apply permissions' }).click();
    await expect(dialog.locator('[data-outcome="failed"]')).toHaveCount(1);
    await expect(dialog.locator('[data-outcome="not-sent"]')).toHaveCount(2);
    await expect(dialog.getByRole('status')).toContainText(/metadata changed/i);
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(0);
    expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'get_file_permissions').length)).toBe(4);
});


for (const reason of ['closed', 'stale', 'disconnect']) {
    test(`a late per-item recheck cannot issue chmod after ${reason}`, async ({ page }) => {
        const dialog = await multiSelection(page);
        await page.evaluate(() => { window.__holdRechecks = true; });
        await dialog.locator('[name="mode"]').fill('750');
        await dialog.getByRole('button', { name: 'Apply permissions' }).click();
        await expect.poll(() => page.evaluate(() => window.__metadataReplies.length)).toBe(4);
        if (reason === 'closed') await page.keyboard.press('Escape');
        await page.evaluate(reason => {
            const manager = window.sftpFileManager;
            if (reason === 'stale') manager.panes.left.mutationViewVersion = (manager.panes.left.mutationViewVersion || 0) + 1;
            if (reason === 'disconnect') window.socket.listeners('disconnect').forEach(listener => listener('transport close'));
            const reply = window.__metadataReplies[3];
            window.socket.listeners('file_permissions').forEach(listener => listener(reply));
        }, reason);
        expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(0);
        expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'get_file_permissions').length)).toBe(4);
        if (reason === 'closed') await expect(dialog).toHaveCount(0);
        else await expect(dialog.locator('[data-outcome="not-sent"]')).toHaveCount(3);
    });
}

for (const reason of ['closed', 'disconnect']) {
    test(`completed chmod refreshes once after ${reason} and a late next-item inspection`, async ({ page }) => {
        const dialog = await multiSelection(page);
        await dialog.locator('[name="mode"]').fill('750');
        await dialog.getByRole('button', { name: 'Apply permissions' }).click();
        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            window.__refreshCount = 0;
            manager.refreshSource = () => { window.__refreshCount++; };
            window.__holdRechecks = true;
            const payload = window.__mutationEvents.find(item => item.event === 'set_file_permissions').payload;
            window.socket.listeners('file_permissions_changed').forEach(listener => listener({ ...payload, operation: 'set_file_permissions', mode: '750' }));
        });
        await expect.poll(() => page.evaluate(() => window.__metadataReplies.length)).toBe(5);
        if (reason === 'closed') await page.keyboard.press('Escape');
        else await page.evaluate(() => window.socket.listeners('disconnect').forEach(listener => listener('transport close')));
        expect(await page.evaluate(() => window.__refreshCount)).toBe(0);
        await page.evaluate(() => {
            const reply = window.__metadataReplies[4];
            window.socket.listeners('file_permissions').forEach(listener => listener(reply));
        });
        expect(await page.evaluate(() => window.__refreshCount)).toBe(1);
        expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'set_file_permissions').length)).toBe(1);
        expect(await page.evaluate(() => window.__mutationEvents.filter(item => item.event === 'get_file_permissions').length)).toBe(5);
    });
}
