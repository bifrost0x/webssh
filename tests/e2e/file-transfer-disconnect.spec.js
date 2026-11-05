const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({ viewport: { width: 1536, height: 960 } });

for (const acknowledged of [true, false]) test(`interrupted copy releases file actions and stops queued writes: ack=${acknowledged}`, async ({page}) => {
    await openWorkspaceWithSources(page);
    await page.locator('[data-source-key="sftp-session:workspace-source"]').click();
    await page.locator('#fmLayoutSplit').click();
    await chooseSource(page, 'right');
    await page.locator('[data-source-key="sftp-session:workspace-target"]').click();
    await page.evaluate(acknowledged => {
        const manager = window.sftpFileManager;
        const emit = manager.socket.emit.bind(manager.socket);
        window.__copyWrites = 0;
        manager.socket.emit = (event, ...args) => {
            if (event === 'transfer_server_to_server') {
                window.__copyWrites += 1;
                const [payload, ack] = args;
                if (acknowledged) ack({success: true, transfer_id: 'interrupted-copy', ...payload});
                return manager.socket;
            }
            return emit(event, ...args);
        };
        Object.assign(manager.panes.left, {loading: false, error: null, path: '/srv/source',
            files: [{name: 'one.txt', size: 12, is_dir: false}, {name: 'two.txt', size: 12, is_dir: false}],
            selected: new Set([0, 1]), autoHomeEligible: false, pendingHomeRequestId: null});
        Object.assign(manager.panes.right, {loading: false, error: null, path: '/srv/archive', files: [], selected: new Set(), autoHomeEligible: false, pendingHomeRequestId: null});
        manager.activePane = 'left';
        manager.renderPane('left'); manager.renderPane('right');
    }, acknowledged);
    await page.locator('#fmTransferBetween').click();
    await expect.poll(() => page.evaluate(() => window.__copyWrites)).toBe(1);
    await page.evaluate(() => window.sftpFileManager.socket.disconnect());
    await expect.poll(() => page.evaluate(() => window.sftpFileManager.transferExecutionInProgress)).toBe(false);
    const states = await page.evaluate(() => window.sftpFileManager.transferQueue.map(item => ({status: item.status, code: item.errorCode, retryable: item.retryable})));
    expect(states[0]).toMatchObject({status: 'error', code: 'OUTCOME_UNKNOWN', retryable: false});
    expect(states[1].status).toBe('cancelled');
    expect(await page.evaluate(() => window.__copyWrites)).toBe(1);
    await expect(page.locator('#fmQueueList')).toContainText('could not be confirmed');
    await expect(page.locator('#fmQueueList .fm-transfer-error')).toBeVisible();
    await expect(page.locator('#fmQueueList .fm-transfer-status').first()).toHaveText('Unconfirmed');
    await expect(page.locator('#fmQueueSummary')).toContainText('1 Unconfirmed');
    await expect(page.locator('#fmQueueSummary')).not.toContainText('failed');
    await page.screenshot({path: test.info().outputPath(`interrupted-copy-${acknowledged}.png`)});
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

