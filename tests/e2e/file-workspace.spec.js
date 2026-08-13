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
            const sessionId = payload?.session_id || payload?.source_session_id || payload?.dest_session_id;
            if (String(sessionId || '').startsWith('workspace-')) {
                window.__fileWorkspaceEvents.push({ event, payload });
                if (typeof acknowledgement === 'function') {
                    acknowledgement({ success: true, transfer_id: 'workspace-transfer' });
                }
                return window.socket;
            }
            return originalEmit(event, ...args);
        };
        openFileManager();
        window.sftpFileManager.availableSessions = [
            { id: 'workspace-source', displayName: 'prod-web-01', username: 'ops', host: 'edge.example', port: 22, connected: true },
            { id: 'workspace-target', displayName: 'release archive', username: 'backup', host: 'archive.example', port: 22, connected: true },
        ];
        window.sftpFileManager.renderSourceLauncher();
    });
}

test('source-first workspace preserves panes and exposes only functional SFTP actions', async ({ page }) => {
    await openWorkspaceWithSources(page);

    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-mode/);
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    const smb = page.locator('[data-source-key="smb:coming-soon"]');
    await expect(smb).toBeDisabled();
    await expect(smb).toContainText('Coming soon');

    await page.locator('[data-source-key="ssh:workspace-source"]').click();
    await expect(page.locator('#fmLeftTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmLeftTabs')).toContainText('prod-web-01');
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);

    await page.locator('#fmLayoutSplit').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-split/);
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncherPane')).toHaveText('Right pane');
    await page.locator('[data-source-key="ssh:workspace-target"]').click();
    await expect(page.locator('#fmRightTabs .fm-source-tab')).toHaveCount(1);
    await expect(page.locator('#fmRightTabs')).toContainText('release archive');

    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            path: '/srv/source',
            files: [{ name: 'release.tar.gz', is_dir: false, size: 1024, mode: 0o100640, modified: 1786598100 }],
            selected: new Set([0]),
        });
        Object.assign(manager.panes.right, {
            loading: false,
            path: '/srv/archive',
            files: [],
            selected: new Set(),
        });
        manager.renderPane('left');
        manager.renderPane('right');
    });
    await expect(page.locator('#fmTransferRight')).toBeEnabled();
    await page.locator('#fmTransferRight').click();
    await expect.poll(() => page.evaluate(() => (
        window.__fileWorkspaceEvents.some(item => item.event === 'transfer_server_to_server')
    ))).toBe(true);

    await page.locator('#fmLayoutSingle').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/fm-workspace-single/);
    await page.locator('#fmClose').click();
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
