const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({ viewport: { width: 1536, height: 960 } });

test('compact file header keeps both layouts and permissions help directly clickable', async ({page}) => {
    await login(page);
    await page.locator('#fileTransferBtn').click();
    for (const language of ['en', 'de']) {
        await page.evaluate(language => window.i18n.setLanguage(language), language);
        for (const width of [320, 390, 767]) {
            await page.setViewportSize({width, height:740});
            for (const selector of ['#fmLayoutSingle', '#fmLayoutSplit', '.fm-permissions-help summary']) {
                const target = page.locator(selector);
                await expect(target).toBeInViewport();
                expect(await target.evaluate(el => {
                    const r = el.getBoundingClientRect();
                    return {reachable: el.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)), width:r.width, height:r.height};
                })).toEqual({reachable:true,width:expect.any(Number),height:expect.any(Number)});
            }
            await page.locator('#fmLayoutSplit').click();
            await expect(page.locator('#fmPaneTabs')).toBeVisible();
            await page.locator('.fm-permissions-help summary').click();
            await expect(page.locator('.fm-permissions-help')).toHaveAttribute('open','');
            await page.locator('.fm-permissions-help summary').click();
            await page.locator('#fmLayoutSingle').click();
            await expect(page.locator('#fmPaneTabs')).toBeHidden();
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        }
    }
});

async function chooseSource(page, pane) {
    const emptyAction = page.locator(`#fm${pane === 'left' ? 'Left' : 'Right'}List .fm-empty-source-cta`);
    await (await emptyAction.isVisible() ? emptyAction : page.locator(`[data-source-target="${pane}"]`)).click();
}

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
                if (event === 'list_directory') {
                    const listings = {
                        '/srv/source': [
                            { name: 'archive', is_dir: true, size: 0 },
                            { name: 'notes.txt', is_dir: false, size: 12 },
                        ],
                        '/srv/source/archive': [],
                    };
                    queueMicrotask(() => window.socket.listeners('directory_listing').forEach(
                        listener => listener({
                            source_id: payload.source_id,
                            path: payload.remote_path,
                            files: listings[payload.remote_path] || [],
                            request_id: payload.request_id,
                        }),
                    ));
                    return window.socket;
                }
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

test('file actions wait for a confirmed listing and recover after retry', async ({page}) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.evaluate(() => {
        const sessions = SessionManager.getAllSessions.bind(SessionManager);
        SessionManager.getAllSessions = () => [...sessions(), ...sftpFileManager.availableSessions];
        sftpFileManager.navigatePaneTo('left', '/srv/source');
    });
    await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(3);
    const upload = page.locator('#fmLeftPane [data-pane-action="upload"]');
    await expect(upload).toBeEnabled();
    await page.evaluate(() => {
        sftpFileManager.panes.left.loading = true;
        sftpFileManager.renderPane('left');
    });
    await expect(upload).toBeDisabled();
    await expect(page.locator('#fmLeftList')).toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('#fmLeftCount')).toHaveText('Loading...');
    await expect(page.locator('#fmLeftSelected')).toHaveText('');
    await page.evaluate(() => {
        Object.assign(sftpFileManager.panes.left, {loading: false, error: 'Temporary directory failure'});
        sftpFileManager.renderPane('left');
    });
    await expect(upload).toBeDisabled();
    await expect(page.locator('#fmLeftCount')).toHaveText('');
    await expect(page.locator('#fmLeftSelected')).toHaveText('');
    await page.locator('#fmLeftList .fm-error-retry').click();
    await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(3);
    await expect(upload).toBeEnabled();
});

test('compact file toolbar actions retain accessible names', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();

    const toolbar = page.locator('#fmLeftPane .fm-pane-toolbar');
    await expect(toolbar.locator('.fm-action-menu-more > summary')).toHaveAccessibleName('More…');
    for (const theme of ['glass', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian']) {
        await page.evaluate(value => applyTheme(value), theme);
        const ratio = await toolbar.locator('.fm-action-menu-new > summary').evaluate(el => {
            const luminance = color => color.match(/[\d.]+/g).slice(0, 3)
                .map(Number).map(v => v / 255)
                .map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4)
                .reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
            const style = getComputedStyle(el);
            const fg = luminance(style.color), bg = luminance(style.backgroundColor);
            return (Math.max(fg, bg) + .05) / (Math.min(fg, bg) + .05);
        });
        expect(ratio, `${theme} New menu contrast`).toBeGreaterThanOrEqual(4.5);
    }
    for (const [action, name] of Object.entries({
        newfolder: 'New Folder', upload: 'Upload', download: 'Download',
        preview: 'Preview', rename: 'Rename', move: 'Move…', delete: 'Delete',
    })) {
        await expect(toolbar.locator(`[data-pane-action="${action}"]`))
            .toHaveAttribute('aria-label', name);
    }
});

test('mobile split sources use the full width when changing sides', async ({page}) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('#fmLayoutSplit').click();
    await chooseSource(page, 'right');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    for (const width of [320, 390, 767, 800, 1280, 390]) {
        await page.setViewportSize({width,height:740});
        if (width >= 768) {
            await expect(page.locator('#fmLeftPane')).toBeVisible();
            await expect(page.locator('#fmRightPane')).toBeVisible();
            await expect(page.locator('#fmPaneTabs')).toBeHidden();
            const left = await page.locator('#fmLeftPane').boundingBox();
            const right = await page.locator('#fmRightPane').boundingBox();
            expect(right.x).toBeGreaterThanOrEqual(left.x + left.width);
            for (const side of ["Left", "Right"]) {
                const list = await page.locator(`#fm${side}List`).boundingBox();
                expect(list.height).toBeGreaterThan(140);
            }
            continue;
        }
        for (const side of ['Left', 'Right']) {
            await page.locator('#fmPaneTabs').getByRole('tab',{name:`${side} side`,exact:true}).click();
            const pane = page.locator(`#fm${side}Pane`);
            const paneBox = await pane.boundingBox();
            const gridBox = await page.locator('#sftpFileManager .fm-panes').boundingBox();
            expect(Math.abs(paneBox.width-gridBox.width)).toBeLessThanOrEqual(1);
            await expect(pane.locator('.fm-path-input')).toBeVisible();
            await expect(pane.locator('[data-pane-action="upload"]')).toBeEnabled();
            expect(await pane.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
        }
    }
});

test('split file toolbars expose every action without horizontal scrolling', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('#fmLayoutSplit').click();
    await chooseSource(page, 'right');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();

    for (const side of ['Left', 'Right']) {
        const toolbar = page.locator(`#fm${side}Pane .fm-pane-toolbar`);
        await expect(toolbar.locator('[data-pane-action]')).toHaveCount(9);
        expect(await toolbar.evaluate(element => element.scrollWidth <= element.clientWidth + 1))
            .toBe(true);
        await toolbar.locator('.fm-action-menu-more > summary').click();
        await expect(toolbar.locator('[data-pane-action="delete"]')).toBeInViewport();
        await toolbar.locator('.fm-action-menu-more > summary').click();
    }
    await page.screenshot({path:testInfo.outputPath('files-split-1280.png'), animations:'disabled'});
});

test.describe('touch file workspace', () => {
    test.use({ hasTouch: true });

    test('split file toolbar actions retain mobile touch targets', async ({ page }) => {
        await page.setViewportSize({ width: 1280, height: 720 });
        await openWorkspaceWithSources(page);
        await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
        await page.locator('#fmLayoutSplit').click();
        await chooseSource(page, 'right');
        await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
        for (const [viewportWidth, sides] of [
            [390, ['Left']],
            [900, ['Left', 'Right']],
        ]) {
            await page.setViewportSize({ width: viewportWidth, height: 844 });
            for (const side of sides) {
                if (viewportWidth < 768) await page.locator('#fmPaneTabs').getByRole('tab', {name: `${side} side`}).click();
                const widths = await page.locator(
                    `#fm${side}Pane .fm-pane-toolbar > button:not([hidden]), #fm${side}Pane .fm-pane-toolbar > details > summary`,
                ).evaluateAll(buttons => buttons.map(button => button.getBoundingClientRect().width));
                expect(widths).toHaveLength(5);
                expect(Math.min(...widths), `${viewportWidth}px ${side}: ${widths.join(', ')}`)
                    .toBeGreaterThanOrEqual(44);
            }
        }
    });
});

for (const kind of ['sftp', 'smb']) {
    test(`${kind} filenames preserve text, checkbox attributes and sorted selection`, async ({ page }) => {
        await openWorkspaceWithSources(page);
        // Ordinary punctuation and entity-like text, without executable markup.
        const filename = 'Über "quotes" and \'apostrophes\' & <notes> &quot;.txt';
        await page.evaluate(({ kind, filename }) => {
            const manager = window.sftpFileManager;
            manager.closeSourceLauncher();
            const sourceId = kind === 'sftp'
                ? 'sftp-session:workspace-source'
                : `smb-quick:${'a'.repeat(32)}`;
            Object.assign(manager.panes.left, manager.createEmptyPaneState(), {
                source: {
                    sourceId, kind, label: 'Punctuation files',
                    capabilities: ['list', 'read'], security: {}, access: {},
                },
                path: '/',
                files: [
                    { name: filename, is_dir: false, size: 12 },
                    { name: 'Folder', is_dir: true, size: 0 },
                    { name: 'alpha.txt', is_dir: false, size: 1 },
                ],
            });
            manager.renderPane('left');
        }, { kind, filename });

        const rows = page.locator('#fmLeftList .fm-file-item');
        await expect(rows).toHaveCount(3);
        await expect(rows.first().locator('.fm-file-name')).toHaveText('Folder');
        const row = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
        await expect(row.locator('.fm-file-name')).toHaveText(filename);
        const checkbox = row.getByRole('checkbox');
        await expect(checkbox).toHaveAttribute('aria-label', `Select: ${filename}`);
        expect(await checkbox.evaluate(element => element.getAttributeNames().sort())).toEqual([
            'aria-checked', 'aria-label', 'class', 'role', 'tabindex', 'type',
        ]);
        await checkbox.click();
        await expect(checkbox).toHaveAttribute('aria-checked', 'true');
        expect(await page.evaluate(() => [...window.sftpFileManager.panes.left.selected])).toEqual([0]);
        await checkbox.click();
        await expect(checkbox).toHaveAttribute('aria-checked', 'false');
        await assertNoExternalRequests(page);
    });
}

test('single-pane files fill a medium viewport and support keyboard navigation', async ({ page }) => {
    await page.setViewportSize({ width: 876, height: 778 });
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    const geometry = await page.evaluate(() => {
        const panes = document.querySelector('.fm-panes').getBoundingClientRect();
        const pane = document.getElementById('fmLeftPane').getBoundingClientRect();
        return {
            panesHeight: Math.round(panes.height),
            paneHeight: Math.round(pane.height),
            rows: getComputedStyle(document.querySelector('.fm-panes')).gridTemplateRows,
        };
    });
    expect(geometry.paneHeight).toBeGreaterThanOrEqual(geometry.panesHeight - 2);
    expect(geometry.rows.trim().split(/\s+/)).toHaveLength(1);

    await page.evaluate(() => {
        Object.assign(window.sftpFileManager.panes.left, {
            loading: false,
            path: '/srv/source',
            files: [
                { name: 'archive', is_dir: true, size: 0 },
                { name: 'notes.txt', is_dir: false, size: 12 },
            ],
            focusedIndex: null,
        });
        window.sftpFileManager.renderPane('left');
    });

    const first = page.locator('#fmLeftList .fm-file-item').first();
    const second = page.locator('#fmLeftList .fm-file-item').nth(1);
    await first.focus();
    await page.keyboard.press('ArrowDown');
    await expect(second).toBeFocused();
    await page.keyboard.press('Space');
    await expect(second).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Home');
    await expect(first).toBeFocused();
    await page.keyboard.press('End');
    await expect(page.locator('#fmLeftList .fm-file-item').last()).toBeFocused();
});

test('source-first workspace preserves panes and exposes only functional SFTP actions', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-mode/);
    await expect(page.locator('#fmOpenSource')).toHaveCount(0);
    await expect(page.locator('#fmQueue')).toHaveClass(/collapsed/);
    await expect(page.locator('#fmQueueHeader')).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#fmQueueList')).toBeHidden();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncherTitle')).toHaveText('Choose connection');
    await expect(page.locator('[data-source-target="left"]')).toHaveAttribute('aria-label', 'Choose connection');
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
    await expect(page.locator('#fmSourceGroups .fm-source-group')).toHaveCount(7);
    await expect(page.locator('#fm-source-group-active')).toContainText('Active SSH sessions');
    await expect(page.locator('#fm-source-group-saved-0')).toContainText('Favorites');
    await expect(page.locator('#fm-source-group-active + .fm-source-group-items .fm-source-row')).toHaveCount(2);
    await expect(page.locator('#fm-source-group-saved-0 + .fm-source-group-items .fm-source-row').first()).toBeVisible();
    await expect(page.locator('[data-source-key="smb:coming-soon"]')).toHaveCount(0);
    await expect(page.locator('[data-source-key="browser-local"]')).toHaveCount(0);
    await expect(page.locator('.fm-source-secondary-groups')).toHaveCount(0);
    await expect(page.locator('#fmNewSftpSource')).toBeEnabled();
    await expect(page.locator('#fmNewSmbSource')).toBeDisabled();
    await expect(page.locator('#fmNewSmbSource')).toContainText('Disabled by administrator');
    await expect(page.locator('#fmSourceSearch')).toBeFocused();
    const sourceSearchFocus = await page.locator('.fm-source-search').evaluate(label => {
        const input = label.querySelector('input');
        const labelStyle = getComputedStyle(label);
        const inputStyle = getComputedStyle(input);
        const labelBounds = label.getBoundingClientRect();
        const inputBounds = input.getBoundingClientRect();
        return {
            labelOutline: labelStyle.outlineStyle,
            inputOutline: inputStyle.outlineStyle,
            labelLeft: Math.round(labelBounds.left),
            labelRight: Math.round(labelBounds.right),
            inputLeft: Math.round(inputBounds.left),
            inputRight: Math.round(inputBounds.right),
        };
    });
    expect(sourceSearchFocus.labelOutline).toBe('solid');
    expect(sourceSearchFocus.inputOutline).toBe('none');
    expect(sourceSearchFocus.labelLeft).toBeLessThan(sourceSearchFocus.inputLeft);
    expect(sourceSearchFocus.labelRight).toBeGreaterThanOrEqual(sourceSearchFocus.inputRight);
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
    await chooseSource(page, 'right');
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncherPane')).toHaveText('Right side');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await expect(page.locator('#fmRightTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmRightTabs')).toContainText('release archive');
    await expect(page.locator('[data-source-target="left"]')).toHaveAttribute('aria-label', 'Choose connection: Left side');
    await expect(page.locator('[data-source-target="right"]')).toHaveAttribute('aria-label', 'Choose connection: Right side');

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
    await expect.poll(() => page.evaluate(() => (
        window.sftpFileManager.transferExecutionInProgress
    ))).toBe(true);
    await expect(page.locator('#fmTransferBetween')).toBeVisible();
    await expect(page.locator('#fmTransferBetween')).toBeEnabled();

    await page.locator('#fmTransferBetween').click();
    await expect.poll(() => page.evaluate(() => (
        window.sftpFileManager.transferQueue.map(transfer => transfer.status)
    ))).toEqual(['active', 'pending']);

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

test('late key listing preserves edited file connection details', async ({ page }) => {
    await openWorkspaceWithSources(page);
    await expect.poll(() => page.evaluate(() => Array.isArray(sftpFileManager.qcProfiles))).toBe(true);
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.closeSourceLauncher();
        const socket = window.socket;
        const emit = socket.emit;
        const once = socket.once;
        const callbacks = {};
        socket.emit = function(event, ...args) {
            return ['list_profiles', 'list_keys'].includes(event) ? socket : emit.call(socket, event, ...args);
        };
        socket.once = function(event, callback) {
            if (['profiles_list', 'keys_list'].includes(event)) {
                callbacks[event] = callback;
                return socket;
            }
            return once.call(socket, event, callback);
        };
        manager.openQuickConnect('late-profile');
        callbacks.profiles_list({profiles: [{id: 'late-profile', name: 'Saved host', host: 'original.example', username: 'original', key_id: 'late-key'}]});
        window.deliverFileKeys = () => callbacks.keys_list({keys: [{id: 'late-key', name: 'Saved key', type: 'ed25519'}]});
        socket.emit = emit;
        socket.once = once;
    });
    await page.locator('#fmQcHost').fill('edited.example');
    await page.locator('#fmQcUsername').fill('edited-user');
    await page.locator('input[name="fmQcAuth"][value="password"]').check();
    await page.locator('#fmQcPassword').fill('temporary-test-password');
    await page.evaluate(() => window.deliverFileKeys());
    await expect(page.locator('#fmQcHost')).toHaveValue('edited.example');
    await expect(page.locator('#fmQcUsername')).toHaveValue('edited-user');
    await expect(page.locator('input[name="fmQcAuth"][value="password"]')).toBeChecked();
    await expect(page.locator('#fmQcPassword')).toHaveValue('temporary-test-password');
});

test('empty panes guide source selection and mobile split keeps both panes reachable', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await page.locator('#fmSourceLauncherClose').click();
    const leftEmptyAction = page.locator('#fmLeftList').getByRole('button', { name: 'Choose connection' });
    await expect(leftEmptyAction).toBeVisible();
    await expect(page.locator('#fmLeftPane .fm-pane-nav')).toBeHidden();
    await expect(page.locator('#fmLeftPane .fm-pane-toolbar')).toBeHidden();
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
    await chooseSource(page, 'right');
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

    const firstRow = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
    const secondRow = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
    const firstCheckbox = firstRow.locator('.fm-file-checkbox');
    const secondCheckbox = secondRow.locator('.fm-file-checkbox');
    await firstRow.focus();
    await page.keyboard.press('Space');
    await expect(firstCheckbox).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(1);

    await page.keyboard.press('ArrowDown');
    await expect(secondRow).toBeFocused();
    await page.keyboard.press('Space');
    await expect(secondCheckbox).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#fmLeftList .fm-file-item.selected')).toHaveCount(2);
    await assertNoExternalRequests(page);
});

test('same-pane drag remains available beside the Move picker action', async ({ page }) => {
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

    await page.locator('#fmLeftPane .fm-action-menu-more > summary').click();
    const move = page.locator('[data-pane-toolbar="left"] [data-pane-action="move"]');
    await expect(move).toBeVisible();
    await expect(move).toBeDisabled();
    const source = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
    const target = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
    await source.click();
    await expect(move).toBeEnabled();
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

test('Move picker browses folders on the same source and uses correlated rename', async ({ page }) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            error: null,
            autoHomeEligible: false,
            pendingHomeRequestId: null,
            homePath: '/srv',
            path: '/srv/source',
            files: [
                { name: 'report.txt', is_dir: false, size: 12 },
                { name: 'archive', is_dir: true, size: 0 },
            ],
            selected: new Set([0]),
        });
        manager.renderPane('left');
    });

    await page.locator('#fmLeftPane .fm-action-menu-more > summary').click();
    const move = page.locator('[data-pane-toolbar="left"] [data-pane-action="move"]');
    await expect(move).toBeEnabled();
    await move.click();

    const picker = page.locator('.fm-move-picker');
    await expect(picker).toBeVisible();
    await expect(picker).toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('[data-move-picker-path]')).toHaveText('/srv/source');
    await expect(page.locator('[data-move-picker-confirm]')).toBeDisabled();
    await expect(page.locator('[data-move-picker-list]')).toContainText('archive');
    await expect(page.locator('[data-move-picker-list]')).not.toContainText('notes.txt');

    await page.locator('.fm-move-picker-directory', { hasText: 'archive' }).click();
    await expect(page.locator('[data-move-picker-path]')).toHaveText('/srv/source/archive');
    await expect(page.locator('[data-move-picker-confirm]')).toBeEnabled();
    await expect(page.locator('[data-move-picker-confirm]')).toBeFocused();
    await page.locator('[data-move-picker-confirm]').click();

    await expect(picker).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => (
        window.__fileWorkspaceEvents.find(item => (
            item.event === 'rename_file'
            && item.payload.old_path === '/srv/source/report.txt'
        ))?.payload
    ))).toMatchObject({
        source_id: 'sftp-session:workspace-source',
        old_path: '/srv/source/report.txt',
        new_path: '/srv/source/archive/report.txt',
    });
    await expect.poll(() => page.evaluate(() => (
        window.sftpFileManager.transferExecutionInProgress
    ))).toBe(false);
    await assertNoExternalRequests(page);
});

test('splitting two single-view tabs distributes them across both file areas', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await chooseSource(page, 'left');
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

    test('opens folders, selects files, scrolls, and exposes long-press actions', async ({ page, browserName }) => {
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
        const client = browserName === 'chromium' ? await page.context().newCDPSession(page) : null;
        const x = listBox.x + (listBox.width / 2);
        const startY = listBox.y + Math.min(listBox.height - 24, 300);
        if (client) {
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
        } else {
            // Playwright exposes native swipe injection only through Chromium CDP.
            // Exercise browser scrolling and touch movement cancellation
            // independently in the other engines; mobile WebKit has no wheel API.
            await file.dispatchEvent('pointerdown', {pointerType:'touch',pointerId:7,clientX:x,clientY:startY});
            await file.dispatchEvent('pointermove', {pointerType:'touch',pointerId:7,clientX:x+24,clientY:startY-90});
            await page.mouse.move(x,startY);
            if (browserName === 'webkit') {
                await file.focus();
                await page.keyboard.press('End');
            } else await page.mouse.wheel(0,180);
            // Movement must cancel the 500 ms long-press even while held.
            await page.waitForTimeout(550);
            await file.dispatchEvent('pointerup', {pointerType:'touch',pointerId:7,clientX:x+24,clientY:startY-90});
            await expect(page.locator('#fmActionSheet')).not.toHaveClass(/visible/);
        }
        await expect.poll(() => list.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
        expect(scrollLayout.listTouchAction).toBe('manipulation');

        const longPressFile = page.locator('#fmLeftList .fm-file-item[data-index="15"]');
        await longPressFile.scrollIntoViewIfNeeded();
        await page.waitForTimeout(300);
        const longPressFileBox = await longPressFile.boundingBox();
        const fileX = longPressFileBox.x + (longPressFileBox.width / 2);
        const fileY = longPressFileBox.y + (longPressFileBox.height / 2);
        if (client) await client.send('Input.dispatchTouchEvent', {
            type: 'touchStart',
            touchPoints: [{ x: fileX, y: fileY }],
        });
        else await longPressFile.dispatchEvent('pointerdown', {pointerType:'touch',pointerId:8,clientX:fileX,clientY:fileY});
        // Hold until the browser has handled its long-press timer. A fixed
        // wall-clock sleep can release the pointer before a busy renderer runs it.
        await expect(page.locator('#fmActionSheet')).toHaveClass(/visible/);
        if (client) await client.send('Input.dispatchTouchEvent', {
            type: 'touchEnd',
            touchPoints: [],
        });
        else await longPressFile.dispatchEvent('pointerup', {pointerType:'touch',pointerId:8,clientX:fileX,clientY:fileY});
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

test('keyboard focus and actions follow the same pane in split files', async ({page}) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('#fmLayoutSplit').click();
    await chooseSource(page, 'right');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await page.evaluate(() => {
        sftpFileManager.navigatePaneTo('left', '/srv/source');
        sftpFileManager.navigatePaneTo('right', '/srv/source');
    });
    const left = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
    const right = page.locator('#fmRightList .fm-file-item[data-index="1"]');
    await expect(left).toBeVisible();await expect(right).toBeVisible();
    await left.focus();
    await expect.poll(()=>page.evaluate(()=>sftpFileManager.activePane)).toBe('left');
    await page.keyboard.press('Tab');
    await expect.poll(()=>page.evaluate(()=>document.activeElement.closest('.fm-pane')?.id)).toBe('fmRightPane');
    await expect.poll(()=>page.evaluate(()=>sftpFileManager.activePane)).toBe('right');
    await right.focus();await page.keyboard.press('Space');
    await expect(right).toHaveAttribute('aria-selected','true');
    await expect(left).toHaveAttribute('aria-selected','false');
    await page.keyboard.press('Shift+Tab');
    await expect.poll(()=>page.evaluate(()=>document.activeElement.closest('.fm-pane')?.id)).toBe('fmLeftPane');
    await page.locator('#fmRightPath').focus();
    await expect.poll(()=>page.evaluate(()=>sftpFileManager.activePane)).toBe('right');
});
test('file lists keep working space and reachable actions across viewport sizes', async ({page}, testInfo) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.evaluate(() => {
        const state=sftpFileManager.panes.left;
        state.files=Array.from({length:45},(_,i)=>({name:`Report-${String(i).padStart(2,'0')}-with-a-long-descriptive-name.txt`,is_dir:false,size:4096}));
        state.path='/srv/reports';state.loading=false;sftpFileManager.renderPane('left');
    });
    for (const size of [{width:360,height:529},{width:390,height:844},{width:768,height:1024},{width:1280,height:720},{width:3440,height:1440}]) {
        await page.setViewportSize(size);
        const list=page.locator('#fmLeftList');
        await page.screenshot({path:testInfo.outputPath(`files-${size.width}.png`),animations:'disabled'});
        const box=await list.boundingBox();
        expect(box.height,`file list height at ${size.width}px`).toBeGreaterThanOrEqual(120);
        expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
        await list.locator('.fm-file-item').first().focus();await page.keyboard.press('End');
        await expect(list.locator('.fm-file-item').last()).toBeFocused();
        await expect(list.locator('.fm-file-item').last()).toBeInViewport();
        await page.locator('#fmLeftPane .fm-action-menu-more > summary').click();
        await expect(page.locator('#fmLeftPane [data-pane-action="delete"]')).toBeInViewport();
        await page.locator('#fmLeftPane .fm-action-menu-more > summary').click();
    }
});

test('unavailable file permissions explain the prerequisite with a wiki link',async({page},testInfo)=>{
 await openWorkspaceWithSources(page);
 await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
 await page.locator('#fmLayoutSplit').click();
 const action=page.locator('[data-pane-toolbar="left"] [data-pane-action="permissions"]');
 await page.locator('[data-pane-toolbar="left"] details').filter({has:page.locator('[data-pane-action=permissions]')}).locator('summary').click();
 await expect(action).toBeVisible();await expect(action).toBeDisabled();
 const wrapper=action.locator('..');await wrapper.focus();
 await expect(wrapper.locator('.fm-permission-access-help')).toBeVisible();
 await expect(wrapper.getByRole('link',{name:'Wiki'})).toHaveAttribute('href',/SFTP-File-Workspace-and-Transfers#unix-permissions$/);
 await page.screenshot({path:testInfo.outputPath('permissions-help.png')});
});
