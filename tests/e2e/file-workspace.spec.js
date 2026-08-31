const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({ viewport: { width: 1536, height: 960 } });

async function openWorkspaceWithSources(page) {
    await login(page);
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__fileWorkspaceEvents = [];
        window.socket.emit = function captureWorkspaceEvent(event, ...args) {
            const payload = args[0];
            const acknowledgement = args.find(value => typeof value === 'function');
            const sourceIds = [payload?.source_id, payload?.destination_source_id];
            if (sourceIds.some(value => String(value || '').includes(':workspace-'))) {
                window.__fileWorkspaceEvents.push({ event, payload });
                if (typeof acknowledgement === 'function') {
                    acknowledgement({
                        success: true,
                        transfer_id: 'workspace-transfer',
                        source_id: payload.source_id,
                        destination_source_id: payload.destination_source_id,
                        old_path: payload.old_path,
                        new_path: payload.new_path,
                        request_id: payload.request_id,
                    });
                }
                return window.socket;
            }
            return originalEmit(event, ...args);
        };
        openFileManager();
        window.sftpFileManager.availableSessions = [
            {
                id: 'workspace-source', displayName: 'prod-web-01', username: 'ops',
                host: 'edge.example', port: 22, connected: true,
                file_source: {
                    source_id: 'sftp-session:workspace-source', kind: 'sftp',
                    label: 'prod-web-01', endpoint: 'edge.example:22', protocol: 'SFTP',
                    capabilities: ['list', 'read', 'write', 'mkdir', 'rename', 'delete', 'preview', 'edit', 'recursive', 'remote-transfer'],
                    ephemeral: false, security: { host_key_verified: true },
                },
            },
            {
                id: 'workspace-target', displayName: 'release archive', username: 'backup',
                host: 'archive.example', port: 22, connected: true,
                file_source: {
                    source_id: 'sftp-session:workspace-target', kind: 'sftp',
                    label: 'release archive', endpoint: 'archive.example:22', protocol: 'SFTP',
                    capabilities: ['list', 'read', 'write', 'mkdir', 'rename', 'delete', 'preview', 'edit', 'recursive', 'remote-transfer'],
                    ephemeral: false, security: { host_key_verified: true },
                },
            },
        ];
        window.sftpFileManager.renderSourceLauncher();
        window.sftpFileManager.openSourceLauncher('left');
    });
}

test('source-first workspace preserves panes and exposes only functional SFTP actions', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-mode/);
    await expect(page.locator('#fmOpenSource')).toHaveCount(0);
    await expect(page.locator('#fmQueue')).toHaveClass(/collapsed/);
    await expect(page.locator('#fmQueueHeader')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#fmQueueList')).toBeHidden();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncherTitle')).toHaveText('Open source');
    await expect(page.locator('[data-source-target="left"]')).toHaveAttribute('aria-label', 'Open source');
    await expect(page.locator('#fmLeftIdentity .fm-pane-label')).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => {
        const panel = document.querySelector('.fm-source-launcher-panel')?.getBoundingClientRect();
        if (!panel) return false;
        const launcher = document.querySelector('#fmSourceLauncher')?.getBoundingClientRect();
        if (!launcher) return false;
        const workspaceCenterX = launcher.left + (launcher.width / 2);
        const workspaceCenterY = launcher.top + (launcher.height / 2);
        const panelCenter = panel.left + (panel.width / 2);
        const panelMiddle = panel.top + (panel.height / 2);
        return Math.abs(panelCenter - workspaceCenterX) <= 2
            && Math.abs(panelMiddle - workspaceCenterY) <= 2;
    })).toBe(true);
    await expect(page.locator('#fmSourceGroups .fm-source-group')).toHaveCount(2);
    await expect(page.locator('#fm-source-group-active')).toContainText('Active SSH sessions');
    await expect(page.locator('#fm-source-group-saved')).toContainText('Saved SSH hosts');
    await expect(page.locator('#fm-source-group-active + .fm-source-group-items .fm-source-row')).toHaveCount(2);
    await expect(page.locator('#fm-source-group-saved + .fm-source-group-items .fm-source-row').first()).toBeVisible();
    await expect(page.locator('[data-source-key="smb:coming-soon"]')).toHaveCount(0);
    await expect(page.locator('[data-source-key="browser-local"]')).toHaveCount(0);
    await expect(page.locator('.fm-source-secondary-groups')).toHaveCount(0);
    await expect(page.locator('#fmNewSftpSource')).toBeEnabled();
    await expect(page.locator('#fmNewSmbSource')).toBeDisabled();
    await expect(page.locator('#fmNewSmbSource')).toContainText('Disabled by administrator');
    await expect(page.locator('#fmSourceSearch')).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#fmSourceLauncherClose')).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#fmNewSftpSource')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#fmSourceLauncherClose')).toBeFocused();
    await page.locator('#fmSourceSearch').focus();
    await expect.poll(() => page.evaluate(() => {
        const sourceRows = Array.from(document.querySelectorAll('#fm-source-group-active + .fm-source-group-items .fm-source-row'));
        const actionsTop = document.querySelector('.fm-source-launcher-actions')?.getBoundingClientRect().top || 0;
        const sourceRowsFit = sourceRows.length === 2
            && sourceRows.every(row => row.getBoundingClientRect().bottom <= actionsTop);
        const sourceContentFits = sourceRows.every(row => {
            const bounds = row.getBoundingClientRect();
            return Array.from(row.children).every(child => {
                const childBounds = child.getBoundingClientRect();
                return childBounds.right <= bounds.right && childBounds.bottom <= bounds.bottom;
            });
        });
        return sourceRowsFit && sourceContentFits;
    })).toBe(true);

    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await expect(page.locator('#fmLeftTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmLeftTabs')).toContainText('prod-web-01');
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);

    await page.locator('#fmLayoutSplit').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-split/);
    await page.locator('[data-source-target="right"]').click();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncherPane')).toHaveText('Right side');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await expect(page.locator('#fmRightTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmRightTabs')).toContainText('release archive');
    await expect(page.locator('[data-source-target="left"]')).toHaveAttribute('aria-label', 'Open source: Left side');
    await expect(page.locator('[data-source-target="right"]')).toHaveAttribute('aria-label', 'Open source: Right side');

    await page.locator('#fmQueueHeader').click();
    await expect(page.locator('#fmQueue')).not.toHaveClass(/collapsed/);
    await expect(page.locator('#fmQueueHeader')).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#fmQueueToggle')).toHaveText('expand_less');
    await expect(page.locator('#fmQueueList')).toBeVisible();
    await page.locator('#fmQueueHeader').click();
    await expect(page.locator('#fmQueue')).toHaveClass(/collapsed/);
    await expect(page.locator('#fmQueueHeader')).toHaveAttribute('aria-expanded', 'false');

    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            autoHomeEligible: false,
            pendingHomeRequestId: null,
            path: '/srv/source',
            files: [{ name: 'release.tar.gz', is_dir: false, size: 1024, mode: 0o100640, modified: 1786598100 }],
            selected: new Set([0]),
        });
        Object.assign(manager.panes.right, {
            loading: false,
            autoHomeEligible: false,
            pendingHomeRequestId: null,
            path: '/srv/archive',
            files: [],
            selected: new Set(),
        });
        manager.renderPane('left');
        manager.renderPane('right');
    });
    await expect(page.locator('#fmTransferBetween')).toBeVisible();
    await expect(page.locator('#fmTransferBetween')).toBeEnabled();
    await expect(page.locator('.fm-transfer-rail .fm-transfer-direction')).toHaveCount(1);
    await expect(page.locator('#fmTransferHint')).toContainText('1 selected');
    await page.locator('#fmTransferBetween').click();
    await expect.poll(() => page.evaluate(() => (
        window.__fileWorkspaceEvents.some(item => item.event === 'transfer_server_to_server')
    ))).toBe(true);

    await page.locator('#fmLayoutSingle').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-single/);
    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#sftpFileManager')).not.toHaveClass(/show/);
    await page.evaluate(() => openFileManager());
    await expect(page.locator('#fmLeftTabs')).toContainText('prod-web-01');
    await expect(page.locator('#fmRightTabs')).toContainText('release archive');
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);

    const events = await page.evaluate(() => window.__fileWorkspaceEvents.map(item => item.event));
    expect(events).toContain('get_home_directory');
    expect(events).toContain('list_directory');
    await assertNoExternalRequests(page);
});

test('saved key profile stays selected when keys arrive after profiles', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.closeSourceLauncher();
        const socket = window.socket;
        const originalEmit = socket.emit;
        const originalOnce = socket.once;
        const callbacks = {};
        socket.emit = function captureLists(event, ...args) {
            if (event === 'list_profiles' || event === 'list_keys') return socket;
            return originalEmit.call(socket, event, ...args);
        };
        socket.once = function captureListCallbacks(event, callback) {
            if (event === 'profiles_list' || event === 'keys_list') {
                callbacks[event] = callback;
                return socket;
            }
            return originalOnce.call(socket, event, callback);
        };

        manager.openQuickConnect('race-profile');
        callbacks.profiles_list({
            profiles: [{
                id: 'race-profile',
                name: 'Key profile',
                host: 'key.example',
                port: 22,
                username: 'deploy',
                key_id: 'race-key',
            }],
        });
        callbacks.keys_list({
            keys: [{ id: 'race-key', name: 'Deployment key', type: 'ed25519' }],
        });

        socket.emit = originalEmit;
        socket.once = originalOnce;
    });

    await expect(page.locator('input[name="fmQcAuth"][value="key"]')).toBeChecked();
    await expect(page.locator('#fmQcKeySelect')).toHaveValue('race-key');
    await assertNoExternalRequests(page);
});

test('empty panes guide source selection and mobile split keeps both panes reachable', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await page.locator('#fmSourceLauncherClose').click();
    const leftEmptyAction = page.locator('#fmLeftList').getByRole('button', { name: 'Open source' });
    await expect(leftEmptyAction).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => {
        const action = document.querySelector('#fmLeftList .fm-empty-source-cta');
        const list = document.querySelector('#fmLeftList');
        if (!action || !list) return false;
        const actionBounds = action.getBoundingClientRect();
        const listBounds = list.getBoundingClientRect();
        return actionBounds.top >= listBounds.top && actionBounds.bottom <= listBounds.bottom;
    })).toBe(true);
    await page.setViewportSize({ width: 1536, height: 960 });
    await leftEmptyAction.click();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);

    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('#fmLayoutSplit').click();
    await page.locator('[data-source-target="right"]').click();
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await page.setViewportSize({ width: 390, height: 844 });

    const mobilePaneTabs = page.locator('#fmPaneTabs');
    await expect(mobilePaneTabs).toBeVisible();
    await expect(mobilePaneTabs.getByRole('tab', { name: 'Left side' })).toBeVisible();
    await expect(mobilePaneTabs.getByRole('tab', { name: 'Right side' })).toBeVisible();
    await expect(page.locator('#fmLeftPane')).toBeHidden();
    await expect(page.locator('#fmRightPane')).toBeVisible();

    await mobilePaneTabs.getByRole('tab', { name: 'Left side' }).click();
    await expect(page.locator('#fmLeftPane')).toBeVisible();
    await expect(page.locator('#fmRightPane')).toBeHidden();
    await assertNoExternalRequests(page);
});

test('file checkboxes support additive selection and select all', async ({ page }) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            path: '/srv/source',
            files: [
                { name: 'one.txt', is_dir: false, size: 10, mode: 0o100640, modified: 1786598100 },
                { name: 'two.txt', is_dir: false, size: 20, mode: 0o100640, modified: 1786598100 },
                { name: 'archive', is_dir: true, size: 0, mode: 0o40750, modified: 1786598100 },
            ],
            selected: new Set(),
            lastSelected: -1,
        });
        manager.renderPane('left');
    });

    await page.locator('#fmLeftList .fm-file-item[data-index="0"] .fm-file-checkbox').click();
    await page.locator('#fmLeftList .fm-file-item[data-index="1"] .fm-file-checkbox').click();
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(2);
    await expect(page.locator('[data-pane-toolbar="left"] [data-pane-action="delete"]')).toBeEnabled();
    await expect(page.locator('[data-pane-toolbar="left"] [data-pane-action="preview"]')).toBeDisabled();

    const selectAll = page.locator('[data-pane-select-all="left"]');
    await selectAll.check();
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(3);
    await expect(selectAll).toBeChecked();

    await selectAll.uncheck();
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(0);
    await expect(page.locator('[data-pane-toolbar="left"] [data-pane-action="delete"]')).toBeDisabled();

    const firstCheckbox = page.locator('#fmLeftList .fm-file-item[data-index="0"] .fm-file-checkbox');
    const secondCheckbox = page.locator('#fmLeftList .fm-file-item[data-index="1"] .fm-file-checkbox');
    await firstCheckbox.focus();
    await page.keyboard.press('Enter');
    await expect(firstCheckbox).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(1);

    await page.keyboard.press('Tab');
    await expect(secondCheckbox).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(secondCheckbox).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(2);
    await assertNoExternalRequests(page);
});

test('same-pane drag moves the selection into a folder without a Move toolbar action', async ({ page }) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            autoHomeEligible: false,
            pendingHomeRequestId: null,
            path: '/srv/source',
            files: [
                {
                    name: 'report.txt', is_dir: false, size: 12,
                    mode: 0o100640, modified: 1786598100,
                },
                {
                    name: 'archive', is_dir: true, size: 0,
                    mode: 0o40750, modified: 1786598100,
                },
            ],
            selected: new Set(),
        });
        manager.renderPane('left');
    });

    await expect(page.locator('[data-pane-action="move"]')).toHaveCount(0);
    const source = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
    const target = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
    await source.dragTo(target);
    await expect.poll(() => page.evaluate(() => (
        window.__fileWorkspaceEvents.find(item => item.event === 'rename_file')?.payload
    ))).toMatchObject({
        old_path: '/srv/source/report.txt',
        new_path: '/srv/source/archive/report.txt',
    });
    await expect(page.locator('.fm-directory-drop-target')).toHaveCount(0);
    await assertNoExternalRequests(page);
});

test('splitting two single-view tabs distributes them across both file areas', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('[data-source-target="left"]').click();
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await expect(page.locator('#fmLeftTabs .fm-source-tab')).toHaveCount(2);

    await page.locator('#fmLayoutSplit').click();

    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await expect(page.locator('#fmLeftTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmLeftTabs')).toContainText('prod-web-01');
    await expect(page.locator('#fmRightTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmRightTabs')).toContainText('release archive');
    await expect(page.locator('#fmLeftIdentity .fm-pane-label')).toHaveText('Left side');
    await expect(page.locator('#fmRightIdentity .fm-pane-label')).toHaveText('Right side');
    await assertNoExternalRequests(page);
});

test.describe('mobile touch File Manager', () => {
    test.use({
        viewport: { width: 390, height: 844 },
        hasTouch: true,
        isMobile: true,
    });

    test('opens folders, selects files, scrolls, and exposes long-press actions', async ({ page }) => {
        await openWorkspaceWithSources(page);
        await page.locator('[data-source-key="sftp-session:workspace-source"]').tap();
        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            Object.assign(manager.panes.left, {
                loading: false,
                error: null,
                autoHomeEligible: false,
                pendingHomeRequestId: null,
                path: '/srv/source',
                files: [
                    { name: 'archive', is_dir: true, size: 0 },
                    ...Array.from({ length: 30 }, (_, index) => ({
                        name: `report-${String(index).padStart(2, '0')}.txt`,
                        is_dir: false,
                        size: 12 + index,
                    })),
                ],
                selected: new Set(),
                lastSelected: -1,
            });
            manager.renderPane('left');
        });

        const folder = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
        await expect(folder).toHaveAttribute('draggable', 'false');
        await folder.tap();
        await expect.poll(() => page.evaluate(
            () => window.sftpFileManager.panes.left.path,
        )).toBe('/srv/source/archive');
        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            Object.assign(manager.panes.left, {
                loading: false,
                pendingDirectoryRequestId: null,
                pendingDirectoryPath: null,
                files: [],
            });
            manager.updatePathInput('left', manager.panes.left.path);
            manager.renderPane('left');
        });

        const parent = page.locator('#fmLeftList .fm-file-item[data-type="parent"]');
        await parent.tap();
        await expect.poll(() => page.evaluate(
            () => window.sftpFileManager.panes.left.path,
        )).toBe('/srv/source');

        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            Object.assign(manager.panes.left, {
                loading: false,
                pendingDirectoryRequestId: null,
                pendingDirectoryPath: null,
                files: [
                    { name: 'archive', is_dir: true, size: 0 },
                    ...Array.from({ length: 30 }, (_, index) => ({
                        name: `report-${String(index).padStart(2, '0')}.txt`,
                        is_dir: false,
                        size: 12 + index,
                    })),
                ],
            });
            manager.updatePathInput('left', manager.panes.left.path);
            manager.renderPane('left');
        });
        const file = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
        const scrollLayout = await page.evaluate(() => {
            const modalBody = document.querySelector('#sftpFileManager .modal-body');
            const listElement = document.getElementById('fmLeftList');
            return {
                modalBodyOverflowY: getComputedStyle(modalBody).overflowY,
                listOverflowY: getComputedStyle(listElement).overflowY,
                listTouchAction: getComputedStyle(listElement).touchAction,
                listClientHeight: listElement.clientHeight,
                listScrollHeight: listElement.scrollHeight,
            };
        });
        expect(scrollLayout.modalBodyOverflowY).toBe('hidden');
        expect(scrollLayout.listOverflowY).toBe('auto');
        expect(scrollLayout.listScrollHeight).toBeGreaterThan(scrollLayout.listClientHeight);

        await file.tap();
        await expect(file).toHaveClass(/selected/);
        await file.locator('.fm-file-checkbox').tap();
        await expect(file).not.toHaveClass(/selected/);

        const list = page.locator('#fmLeftList');
        const listBox = await list.boundingBox();
        const client = await page.context().newCDPSession(page);
        const x = listBox.x + (listBox.width / 2);
        const startY = listBox.y + Math.min(listBox.height - 24, 300);
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchStart',
            touchPoints: [{ x, y: startY }],
        });
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchMove',
            touchPoints: [{ x: x + 24, y: startY - 2 }],
        });
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchMove',
            touchPoints: [{ x: x + 22, y: startY - 90 }],
        });
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchMove',
            touchPoints: [{ x: x + 18, y: startY - 180 }],
        });
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchEnd',
            touchPoints: [],
        });
        await expect.poll(() => list.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
        expect(scrollLayout.listTouchAction).toBe('manipulation');

        const longPressFile = page.locator('#fmLeftList .fm-file-item[data-index="15"]');
        await longPressFile.scrollIntoViewIfNeeded();
        await page.waitForTimeout(300);
        const longPressFileBox = await longPressFile.boundingBox();
        const fileX = longPressFileBox.x + (longPressFileBox.width / 2);
        const fileY = longPressFileBox.y + (longPressFileBox.height / 2);
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchStart',
            touchPoints: [{ x: fileX, y: fileY }],
        });
        await page.waitForTimeout(550);
        await client.send('Input.dispatchTouchEvent', {
            type: 'touchEnd',
            touchPoints: [],
        });
        await expect(page.locator('#fmActionSheet')).toHaveClass(/visible/);
        await expect(page.locator('#fmActionSheet')).toHaveAttribute('aria-hidden', 'false');
        await expect(page.locator('#fmActionSheet [data-action="open"]')).toBeEnabled();
        await expect(page.locator('#fmActionSheet [data-action="download"]')).toBeEnabled();
        await expect(page.locator('#fmActionSheet [data-action="transfer"]')).toBeDisabled();
        await page.locator('#fmActionSheet [data-action="cancel"]').tap();
        await expect(page.locator('#fmActionSheet')).not.toHaveClass(/visible/);
        await expect(page.locator('#fmActionSheet')).toHaveAttribute('aria-hidden', 'true');
        await expect(longPressFile.locator('.fm-file-checkbox')).toBeFocused();
        await assertNoExternalRequests(page);
    });
});
