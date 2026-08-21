const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('playwright/test');
const {
    assertNoExternalRequests,
    installSshConnectTrap,
    login,
    openKeyManagement,
} = require('./helpers');

const DESKTOP_VIEWPORT = { width: 1920, height: 1080 };
const DESKTOP_DEVICE_SCALE_FACTOR = 4 / 3;
const DESKTOP_CAPTURE_SIZE = { width: 2560, height: 1440 };
const MOBILE_VIEWPORT = { width: 360, height: 640 };
const MOBILE_CAPTURE_SIZE = { width: 1080, height: 1920 };
const ASSET_DIR = path.resolve(__dirname, '..', '..', 'assets');

function captureAssetsEnabled() {
    return process.env.WEBSSH_CAPTURE_ASSETS === '1';
}

function captureOutputPath(testInfo, filename) {
    return captureAssetsEnabled()
        ? path.join(ASSET_DIR, filename)
        : testInfo.outputPath(filename);
}

async function installCaptureNetworkGuard(page) {
    const baseUrl = new URL(process.env.PLAYWRIGHT_TEST_BASE_URL
        || `http://127.0.0.1:${process.env.WEBSSH_E2E_PORT || '4173'}`);
    page.__blockedExternalRequests = [];
    await page.route('**/*', async route => {
        const requestUrl = new URL(route.request().url());
        const isLocalHttp = ['http:', 'https:'].includes(requestUrl.protocol)
            && requestUrl.host === baseUrl.host;
        const isBrowserLocal = ['data:', 'blob:'].includes(requestUrl.protocol);
        if (isLocalHttp || isBrowserLocal) {
            await route.continue();
            return;
        }
        page.__blockedExternalRequests.push(route.request().url());
        await route.abort('blockedbyclient');
    });
}

async function assertCaptureNetworkClean(page) {
    await assertNoExternalRequests(page);
    expect(page.__blockedExternalRequests).toEqual([]);
}

function readPngSize(filePath) {
    const png = fs.readFileSync(filePath);
    return {
        width: png.readUInt32BE(16),
        height: png.readUInt32BE(20),
    };
}

async function captureDesktopStill(page, filename, testInfo) {
    const filePath = captureOutputPath(testInfo, filename);
    await page.screenshot({
        path: filePath,
        animations: 'disabled',
        caret: 'hide',
    });
    expect(readPngSize(filePath)).toEqual(DESKTOP_CAPTURE_SIZE);
}

async function expectCurrentCaptureTerminology(page) {
    await expect(page.getByText('New Connection', { exact: true })).toHaveCount(0);
    await expect(page.getByText('New SSH Connection', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Profiles', { exact: true })).toHaveCount(0);
}

async function sanitizeSeededCatalog(page) {
    await expect.poll(() => page.evaluate(() => ({
        commands: window.CommandLibrary?.commands?.length || 0,
        commandSets: window.CommandSetManager?.commandSets?.length || 0,
        keys: window.ProfileManager?.keys?.length || 0,
    }))).toMatchObject({
        commands: expect.any(Number),
        commandSets: 2,
        keys: 1,
    });
    await page.evaluate(() => {
        const commandNames = {
            'e2e-command': ['Service status', 'systemctl', 'status --no-pager',
                'Review the current service state'],
            'guarded-direct-command': ['Current identity', 'whoami', '',
                'Show the active remote user'],
        };
        const commands = window.CommandLibrary.commands.map(command => {
            const replacement = commandNames[command.id];
            if (!replacement) return command;
            return {
                ...command,
                name: replacement[0],
                command: replacement[1],
                parameters: replacement[2],
                description: replacement[3],
            };
        });
        window.CommandLibrary.setCommands(commands);

        const commandSets = window.CommandSetManager.commandSets.map(commandSet => (
            commandSet.id === 'e2e-command-set'
                ? {
                    ...commandSet,
                    name: 'Baseline diagnostics',
                    description: 'Check uptime, service health, and disk capacity',
                    steps: [
                        { type: 'library', command_id: 'sys-023' },
                        {
                            type: 'library',
                            command_id: 'sys-014',
                            parameters_override: 'webssh',
                        },
                        { type: 'library', command_id: 'sys-016' },
                    ],
                    resolved_command: 'uptime && systemctl status webssh && df -h',
                    resolution_error: null,
                }
                : {
                    ...commandSet,
                    name: 'Access verification',
                    description: 'Verify the remote execution context',
                    steps: [{ type: 'library', command_id: 'user-007' }],
                    resolved_command: 'whoami',
                    resolution_error: null,
                }
        ));
        window.CommandSetManager.setCommandSets(commandSets);

        window.ProfileManager.setKeys(window.ProfileManager.keys.map(key => ({
            ...key,
            name: 'Operations Ed25519',
            uploaded_at: '2026-01-15T10:00:00.000Z',
        })));
        window.JumpHostManager.setJumpHosts(window.JumpHostManager.jumpHosts.map(host => ({
            ...host,
            name: 'Operations bastion',
            host: 'bastion.example',
            username: 'jump',
        })));
        const profileDetails = {
            'password-review': ['Production gateway', 'gateway.example', 'ops'],
            'usable-key': ['Staging cluster', 'staging.example', 'deploy'],
            'key-jump-host': ['Database bastion', 'database.example', 'dba'],
            'post-command-set': ['Production automation', 'edge-01.example', 'ops'],
        };
        const profiles = window.ProfileManager.profiles
            .filter(profile => Object.hasOwn(profileDetails, profile.id))
            .map(profile => {
                const [name, host, username] = profileDetails[profile.id];
                return { ...profile, name, host, username };
            });
        window.ProfileManager.setProfiles(profiles);
        document.querySelector('.account-name').textContent = 'operator';
    });
}

async function seedCommandSetAnimationCatalog(page) {
    await page.evaluate(() => {
        const commandSets = window.CommandSetManager.commandSets.map(commandSet => {
            if (commandSet.id === 'e2e-command-set') {
                return {
                    ...commandSet,
                    name: 'Baseline diagnostics',
                    description: 'Check uptime, service health, and disk capacity',
                    steps: [
                        { type: 'library', command_id: 'sys-023' },
                        {
                            type: 'library',
                            command_id: 'sys-014',
                            parameters_override: 'webssh',
                        },
                    ],
                    resolved_command: 'uptime && systemctl status webssh',
                    resolution_error: null,
                };
            }
            return {
                ...commandSet,
                name: 'Access verification',
                description: 'Confirm the remote execution context',
                steps: [{ type: 'library', command_id: 'user-007' }],
                resolved_command: 'whoami',
                resolution_error: null,
            };
        });
        window.CommandSetManager.setCommandSets(commandSets);
    });
}

async function captureCssFrame(page, frameDirectory, filename) {
    const filePath = path.join(frameDirectory, filename);
    await page.screenshot({
        path: filePath,
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
    });
    expect(readPngSize(filePath)).toEqual(DESKTOP_VIEWPORT);
}

async function seedDemoFileManager(page) {
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        const guardedEvents = new Set([
            'get_home_directory',
            'list_directory',
            'create_directory',
            'delete_item',
            'rename_file',
            'transfer_server_to_server',
            'preview_file',
            'open_file_for_edit',
            'save_file',
            'download_file_binary',
            'ssh_connect',
        ]);
        window.__captureFileManagerSocketEvents = [];
        window.socket.emit = function captureSafeFileManagerEmit(event, ...args) {
            const payload = args[0] || {};
            const captureIds = [
                payload.session_id,
                payload.source_session_id,
                payload.dest_session_id,
                payload.connection_id,
            ];
            if (guardedEvents.has(event)
                    && captureIds.some(value => String(value || '').startsWith('capture-'))) {
                window.__captureFileManagerSocketEvents.push(event);
                return window.socket;
            }
            return originalEmit(event, ...args);
        };

        openFileManager();
        const manager = window.sftpFileManager;
        const demoPanes = {
            left: {
                ...manager.createEmptyPaneState(),
                type: 'ssh',
                sessionId: 'capture-source',
                connectionId: null,
                path: '/srv/webssh/current',
                files: [
                    { name: 'config', is_dir: true, size: 0, permissions: 'drwxr-x---', modified: 1786598100 },
                    { name: 'logs', is_dir: true, size: 0, permissions: 'drwxr-x---', modified: 1786597500 },
                    { name: 'releases', is_dir: true, size: 0, permissions: 'drwxr-xr-x', modified: 1786596900 },
                    { name: 'compose.yaml', is_dir: false, size: 2841, permissions: '-rw-r-----', modified: 1786596300 },
                    { name: 'healthcheck.sh', is_dir: false, size: 912, permissions: '-rwxr-x---', modified: 1786595700 },
                    { name: 'README.md', is_dir: false, size: 4876, permissions: '-rw-r--r--', modified: 1786595100 },
                ],
                selected: new Set([3]),
                lastSelected: 3,
                hostInfo: { username: 'ops', host: 'edge-01.example', port: 22 },
                loading: false,
                loadingTimeout: null,
                error: null,
            },
            right: {
                ...manager.createEmptyPaneState(),
                type: 'ssh',
                sessionId: 'capture-destination',
                connectionId: null,
                path: '/srv/archive/releases',
                files: [
                    { name: 'daily', is_dir: true, size: 0, permissions: 'drwxr-x---' },
                    { name: 'monthly', is_dir: true, size: 0, permissions: 'drwxr-x---' },
                    { name: 'release-1.0.8.tar.gz', is_dir: false, size: 18432000, permissions: '-rw-r-----' },
                    { name: 'release-1.0.9.tar.gz', is_dir: false, size: 19660800, permissions: '-rw-r-----' },
                    { name: 'manifest.sha256', is_dir: false, size: 2048, permissions: '-rw-r--r--' },
                    { name: 'retention-policy.txt', is_dir: false, size: 1337, permissions: '-rw-r--r--' },
                ],
                selected: new Set(),
                lastSelected: -1,
                hostInfo: { username: 'backup', host: 'archive.example', port: 22 },
                loading: false,
                loadingTimeout: null,
                error: null,
            },
        };

        const sources = [
            ['left', 'capture-source', 'prod-web-01', 'edge-01.example:22'],
            ['right', 'capture-destination', 'release archive', 'archive.example:22'],
        ];
        sources.forEach(([pane, sessionId, label, endpoint]) => {
            manager.workspace.openTab(pane, {
                key: `ssh:${sessionId}`,
                type: 'ssh',
                label,
                endpoint,
                protocol: 'SFTP',
                status: 'Connected',
                security: 'SSH host key trusted',
                sessionId,
            }, demoPanes[pane]);
            manager.syncPaneFromWorkspace(pane);
            manager.updatePathInput(pane, demoPanes[pane].path);
            manager.updatePaneBadge(pane);
            manager.renderPane(pane);
        });
        manager.workspace.setLayout('split');
        manager.workspace.setActivePane('left');
        manager.activePane = 'left';
        manager.closeSourceLauncher();
        manager.renderWorkspaceChrome();

        manager.transferQueue = [
            {
                id: 'capture-transfer-complete',
                type: 's2s',
                filename: 'release-1.0.9.tar.gz',
                status: 'complete',
                progress: 100,
            },
            {
                id: 'capture-transfer-active',
                type: 's2s',
                filename: 'release-manifest.json',
                status: 'active',
                progress: 68,
            },
        ];
        document.getElementById('fmQueue').classList.remove('collapsed');
        manager.renderTransferQueue();
    });
}

async function assertFileManagerIsContained(page) {
    await expect.poll(async () => {
        const bounds = await page.locator('#sftpFileManager .modal-content').boundingBox();
        return bounds?.width || 0;
    }).toBeGreaterThan(1300);
    const geometry = await page.locator('#sftpFileManager').evaluate(modal => {
        const bounds = selector => {
            const rect = modal.querySelector(selector).getBoundingClientRect();
            return {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
                width: rect.width,
                height: rect.height,
            };
        };
        return {
            content: bounds('.modal-content'),
            leftPane: bounds('#fmLeftPane'),
            rightPane: bounds('#fmRightPane'),
            leftList: bounds('#fmLeftList'),
            rightList: bounds('#fmRightList'),
            queue: bounds('#fmQueue'),
            viewport: { width: window.innerWidth, height: window.innerHeight },
        };
    });
    expect(geometry.content.width).toBeGreaterThan(1300);
    expect(geometry.content.height).toBeGreaterThan(900);
    expect(geometry.content.left).toBeGreaterThanOrEqual(0);
    expect(geometry.content.top).toBeGreaterThanOrEqual(0);
    expect(geometry.content.right).toBeLessThanOrEqual(geometry.viewport.width);
    expect(geometry.content.bottom).toBeLessThanOrEqual(geometry.viewport.height);
    expect(geometry.leftPane.width).toBeGreaterThan(600);
    expect(geometry.rightPane.width).toBeGreaterThan(600);
    expect(geometry.leftList.height).toBeGreaterThan(400);
    expect(geometry.rightList.height).toBeGreaterThan(400);
    expect(geometry.leftPane.right).toBeLessThanOrEqual(geometry.rightPane.left);
    expect(geometry.queue.top).toBeGreaterThanOrEqual(geometry.leftPane.bottom);
    expect(geometry.queue.top).toBeGreaterThanOrEqual(geometry.rightPane.bottom);
    expect(geometry.queue.bottom).toBeLessThanOrEqual(geometry.content.bottom);
}

async function seedDemoWorkspace(page) {
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__captureWorkspaceOriginalEmit = originalEmit;
        window.socket.emit = function captureSafeEmit(event, ...args) {
            const payload = args[0];
            if (['ssh_input', 'ssh_resize'].includes(event)
                    && String(payload?.session_id || '').startsWith('capture-')) {
                return window.socket;
            }
            return originalEmit(event, ...args);
        };

        const sessions = [
            {
                session_id: 'capture-edge',
                host: 'edge-01.example',
                port: 22,
                username: 'ops',
                display_name: 'Production Edge',
                output: [
                    '\u001b[1;36mDemo session - reserved .example host\u001b[0m',
                    'ops@edge-01:~$ uptime',
                    ' 10:42:18 up 18 days,  3 users,  load average: 0.18, 0.12, 0.09',
                    'ops@edge-01:~$ systemctl --type=service --state=running',
                    'ssh.service        loaded active running  OpenSSH server',
                    'nginx.service      loaded active running  Web gateway',
                ].join('\r\n'),
            },
            {
                session_id: 'capture-build',
                host: 'build.example',
                port: 22,
                username: 'deploy',
                display_name: 'Build Runner',
                output: [
                    '\u001b[1;35mDemo session - reserved .example host\u001b[0m',
                    'deploy@build:~$ docker compose ps',
                    'NAME           STATUS          PORTS',
                    'web            Up 3 days       0.0.0.0:443->443/tcp',
                    'worker         Up 3 days',
                    'deploy@build:~$ git status --short',
                    '\u001b[32mworking tree clean\u001b[0m',
                ].join('\r\n'),
            },
            {
                session_id: 'capture-audit',
                host: 'audit.example',
                port: 2222,
                username: 'security',
                display_name: 'Audit Node',
            },
            {
                session_id: 'capture-database',
                host: 'database.example',
                port: 22,
                username: 'dba',
                display_name: 'Database Bastion',
            },
        ];

        sessions.forEach(session => SessionManager.createSession(session));
        SessionManager.setSplitLayout(2);
        sessions.slice(0, 2).forEach((session, index) => {
            SessionManager.assignSessionToPane(session.session_id, index);
        });
        SessionManager.setActivePane(0);
        window.__captureWorkspaceOutput = Object.fromEntries(
            sessions.slice(0, 2).map(session => [session.session_id, `${session.output}\r\n`]),
        );

        const notepad = document.getElementById('sessionNotepad');
        window.workspaceLayoutController.setNotesOpen(true);
        notepad.value = [
            'Release checklist',
            '',
            '- Review service status',
            '- Verify deployment health',
            '- Archive audit notes',
            '',
            'Reserved demo systems:',
            'edge-01.example',
            'build.example',
        ].join('\n');
    });
    await expect.poll(() => page.evaluate(() => {
        const sessionIds = Object.keys(window.__captureWorkspaceOutput);
        return sessionIds.length === 2 && sessionIds.every(sessionId => {
            const terminalKeys = TerminalManager.sessionTerminals[sessionId] || [];
            return terminalKeys.length > 0 && terminalKeys.every(
                terminalKey => TerminalManager.terminalReady[terminalKey] === true,
            );
        });
    })).toBe(true);
    await page.evaluate(() => {
        Object.entries(window.__captureWorkspaceOutput).forEach(([sessionId, output]) => {
            TerminalManager.writeOutput(sessionId, output);
        });
    });
    await expect(page.locator('#terminalGrid .terminal-pane')).toHaveCount(2);
    await expect(page.locator('#terminalGrid .xterm-screen')).toHaveCount(2);
    await expect(page.locator('#sessionTabs .session-tab')).toHaveCount(4);
    await expect(page.locator('#notepadPanel')).toBeVisible();
    await expect(page.locator('#sessionNotepad')).toHaveValue(/Release checklist/);
    await expect.poll(() => page.evaluate(() => (
        TerminalManager.getTranscript('capture-edge').includes('Demo session')
    ))).toBe(true);
}

async function assertWorkspaceIsContained(page) {
    const geometry = await page.locator('#terminalGrid').evaluate(grid => {
        const gridRect = grid.getBoundingClientRect();
        const panes = [...grid.querySelectorAll('.terminal-pane')].map(pane => {
            const rect = pane.getBoundingClientRect();
            return {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
                width: rect.width,
                height: rect.height,
            };
        });
        const overlaps = [];
        for (let first = 0; first < panes.length; first += 1) {
            for (let second = first + 1; second < panes.length; second += 1) {
                const horizontal = Math.min(panes[first].right, panes[second].right)
                    - Math.max(panes[first].left, panes[second].left);
                const vertical = Math.min(panes[first].bottom, panes[second].bottom)
                    - Math.max(panes[first].top, panes[second].top);
                if (horizontal > 1 && vertical > 1) overlaps.push([first, second]);
            }
        }
        return {
            grid: {
                left: gridRect.left,
                top: gridRect.top,
                right: gridRect.right,
                bottom: gridRect.bottom,
            },
            panes,
            overlaps,
            viewport: { width: window.innerWidth, height: window.innerHeight },
        };
    });
    expect(geometry.panes).toHaveLength(2);
    expect(geometry.overlaps).toEqual([]);
    for (const pane of geometry.panes) {
        expect(pane.width).toBeGreaterThan(600);
        expect(pane.height).toBeGreaterThan(600);
        expect(pane.left).toBeGreaterThanOrEqual(geometry.grid.left - 1);
        expect(pane.top).toBeGreaterThanOrEqual(geometry.grid.top - 1);
        expect(pane.right).toBeLessThanOrEqual(geometry.grid.right + 1);
        expect(pane.bottom).toBeLessThanOrEqual(geometry.grid.bottom + 1);
    }
    expect(geometry.grid.right).toBeLessThanOrEqual(geometry.viewport.width);
    expect(geometry.grid.bottom).toBeLessThanOrEqual(geometry.viewport.height);
}

test.use({
    viewport: DESKTOP_VIEWPORT,
    deviceScaleFactor: DESKTOP_DEVICE_SCALE_FACTOR,
});

test('captures the current Quick Connect surface at Full HD scale without outbound requests', async ({ page }, testInfo) => {
    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);
    await expect(page.locator('#manageProfilesBtn')).toContainText(
        process.env.WEBSSH_CAPTURE_EXPECT_SAVED_CONNECTIONS || 'Hosts',
    );
    await page.locator('#newConnectionBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#connectionModalTitle')).toHaveText(
        process.env.WEBSSH_CAPTURE_EXPECT_QUICK_CONNECT || 'Quick Connect',
    );
    await expect(page.locator('#connectionDetailsCard')).toBeVisible();
    await expect(page.locator('#recentConnectionsCard')).toBeVisible();
    await expect(page.locator('#recentConnectionsEmpty')).toBeVisible();
    await expect(page.locator('#profileSelect')).toHaveCount(0);
    await expect(page.getByText('New Connection', { exact: true })).toHaveCount(0);
    await expect(page.getByText('New SSH Connection', { exact: true })).toHaveCount(0);

    await captureDesktopStill(page, 'connection-panel.png', testInfo);
    await assertCaptureNetworkClean(page);
});

test('captures seeded command and connection option surfaces at Full HD scale', async ({ page }, testInfo) => {
    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);
    await sanitizeSeededCatalog(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);

    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandWorkspaceModal')).toHaveClass(/show/);
    await page.locator('#commandLibraryTab').click();
    await expect(page.locator('#commandLibraryTab')).toHaveText('Command Library');
    await expect(page.locator('#commandsList')).toContainText('Update Package Lists');
    await expect(page.locator('#commandWorkspaceModal')).not.toContainText('E2E');
    await expectCurrentCaptureTerminology(page);
    await captureDesktopStill(page, 'commandlibrary.png', testInfo);

    await page.locator('#closeCommandWorkspaceModal').click();
    await page.locator('#newConnectionBtn').click();
    await page.evaluate(() => window.selectConnectionProfile('post-command-set'));
    await sanitizeSeededCatalog(page);
    await expect(page.locator('#connectionModalTitle')).toHaveText('Quick Connect');
    await expect(page.locator('#hostInput')).toHaveValue('edge-01.example');
    await expect(page.locator('#connectionCommandModeSet')).toHaveAttribute(
        'aria-pressed', 'true',
    );
    await expect(page.locator('#commandSetSelect option:checked')).toHaveText(
        'Baseline diagnostics',
    );
    await expect(page.locator('#connectionModal')).not.toContainText('E2E');
    await expectCurrentCaptureTerminology(page);
    await captureDesktopStill(page, 'connection-options.png', testInfo);

    await assertCaptureNetworkClean(page);
});

test('captures the seeded key management surface at Full HD scale', async ({ page }, testInfo) => {
    await installCaptureNetworkGuard(page);
    await login(page);
    await sanitizeSeededCatalog(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);

    await openKeyManagement(page);
    await expect.poll(() => page.evaluate(() => (
        window.ProfileManager.keys[0]?.name || ''
    ))).toBe('E2E usable key');
    await sanitizeSeededCatalog(page);
    await expect(page.locator('#keyManagementTitle')).toHaveText('Manage SSH Keys');
    await expect(page.locator('#keysList')).toContainText('Operations Ed25519');
    await expect(page.locator('#keyManagementModal')).not.toContainText('E2E');
    await expect(page.locator('#keyManagementModal')).not.toContainText('.local');
    await expect(page.locator('#keyContentInput')).toHaveValue('');
    await expectCurrentCaptureTerminology(page);
    await captureDesktopStill(page, 'keys.png', testInfo);

    await assertCaptureNetworkClean(page);
});

test('captures a populated dual-pane File Manager without remote file actions', async ({ page }, testInfo) => {
    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);
    await sanitizeSeededCatalog(page);
    await seedDemoFileManager(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await expect(page.locator('#fmModalTitle')).toContainText('File Manager');
    await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(7);
    await expect(page.locator('#fmRightList .fm-file-item')).toHaveCount(7);
    await expect(page.locator('#fmLeftList')).toContainText('compose.yaml');
    await expect(page.locator('#fmRightList')).toContainText('manifest.sha256');
    await expect(page.locator('#fmQueueList .fm-transfer-item')).toHaveCount(2);
    await expect(page.locator('#fmQueueList')).toContainText('release-manifest.json');
    await expect(page.locator('#sftpFileManager')).not.toContainText('E2E');
    await expect(page.locator('#sftpFileManager')).not.toContainText('.local');
    await expectCurrentCaptureTerminology(page);
    expect(await page.evaluate(() => window.__captureFileManagerSocketEvents)).toEqual([]);
    await assertFileManagerIsContained(page);
    await captureDesktopStill(page, 'filemanager.png', testInfo);

    expect(await page.evaluate(() => window.__captureFileManagerSocketEvents)).toEqual([]);
    await assertCaptureNetworkClean(page);
});

test('captures six current file preview and editing frames without remote actions', async ({ page }, testInfo) => {
    const frameDirectory = captureAssetsEnabled()
        ? path.resolve(__dirname, '..', '..', '.test-run.tmp', 'file-editing-frames')
        : testInfo.outputPath('file-editing-frames');
    fs.rmSync(frameDirectory, { recursive: true, force: true });
    fs.mkdirSync(frameDirectory, { recursive: true });

    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);
    await sanitizeSeededCatalog(page);
    await seedDemoFileManager(page);

    const initialContent = [
        '# WebSSH operations',
        '',
        'Environment: edge-01.example',
        'Owner: Platform Operations',
        '',
        '## Deployment checklist',
        '- Verify service health',
        '- Review application logs',
        '- Confirm backup completion',
        '',
    ].join('\n');
    const updatedContent = [
        '# WebSSH operations',
        '',
        'Environment: edge-01.example',
        'Owner: Platform Operations',
        '',
        '## Deployment checklist',
        '- Verify service health',
        '- Review application logs',
        '- Confirm backup completion',
        '- Record release validation',
        '',
        'Status: Ready for handoff',
        '',
    ].join('\n');

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await assertFileManagerIsContained(page);
    await captureCssFrame(page, frameDirectory, '01-dual-pane-overview.png');

    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        manager.panes.left.selected = new Set([5]);
        manager.panes.left.lastSelected = 5;
        manager.renderPane('left');
    });
    const selectedReadme = page.locator('#fmLeftList .fm-file-item.selected')
        .filter({ hasText: 'README.md' });
    await expect(selectedReadme).toHaveCount(1);
    await captureCssFrame(page, frameDirectory, '02-readme-selected.png');

    await page.evaluate(content => {
        const preview = window.FilePreview;
        const filePath = '/srv/webssh/current/README.md';
        preview.currentSessionId = 'capture-source';
        preview.currentPath = filePath;
        preview.currentFilename = 'README.md';
        preview.editMode = false;
        preview.dirty = false;
        preview.showLoading();
        window.ModalManager.open(preview.modal);
        document.getElementById('previewFilename').textContent = 'README.md';
        preview.handlePreviewData({
            path: filePath,
            filename: 'README.md',
            content,
            size: new TextEncoder().encode(content).length,
            is_binary: false,
            truncated: false,
            read_size: content.length,
        });
    }, initialContent);
    await expect(page.locator('#filePreviewModal')).toHaveClass(/show/);
    await expect(page.locator('#previewCode')).toContainText('edge-01.example');
    await expect(page.locator('#previewEditBtn')).toBeVisible();
    await captureCssFrame(page, frameDirectory, '03-readme-preview.png');

    await page.evaluate(content => {
        window.FilePreview.handleEditData({
            path: '/srv/webssh/current/README.md',
            content,
            encoding: 'utf-8',
            newline: 'lf',
        });
    }, initialContent);
    await expect(page.locator('#filePreviewModal')).toHaveClass(/editing/);
    await expect(page.locator('#fileEditor')).toBeVisible();
    await expect(page.locator('#editorContent')).toHaveValue(initialContent);

    await page.locator('#editorContent').fill(updatedContent);
    await expect(page.locator('#editorStatus')).toContainText('Unsaved');
    await captureCssFrame(page, frameDirectory, '04-content-edited.png');

    await page.evaluate(content => {
        const preview = window.FilePreview;
        preview.exitEditMode();
        preview.handlePreviewData({
            path: '/srv/webssh/current/README.md',
            filename: 'README.md',
            content,
            size: new TextEncoder().encode(content).length,
            is_binary: false,
            truncated: false,
            read_size: content.length,
        });
        window.showNotification('File saved', 'success', 5000);
    }, updatedContent);
    await expect(page.locator('#filePreviewModal')).not.toHaveClass(/editing/);
    await expect(page.locator('#previewCode')).toContainText('Ready for handoff');
    await expect(page.locator('.notification-success')).toContainText('File saved');
    await captureCssFrame(page, frameDirectory, '05-saved-preview.png');

    await page.evaluate(() => {
        window.FilePreview.close();
        const manager = window.sftpFileManager;
        const readme = manager.panes.left.files.find(file => file.name === 'README.md');
        readme.size = 5234;
        manager.renderPane('left');
        manager.transferQueue = manager.transferQueue.map(transfer => ({
            ...transfer,
            status: 'complete',
            progress: 100,
        }));
        manager.renderTransferQueue();
        window.showNotification('Transfer complete', 'success', 5000);
    });
    await expect(page.locator('#filePreviewModal')).not.toHaveClass(/show/);
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await expect(page.locator('#fmQueueList .fm-transfer-item.complete')).toHaveCount(2);
    await expect(page.getByText('Transfer complete', { exact: true })).toBeVisible();
    await assertFileManagerIsContained(page);
    await captureCssFrame(page, frameDirectory, '06-transfer-complete.png');

    await expect(page.locator('#sftpFileManager')).not.toContainText('E2E');
    await expect(page.locator('#sftpFileManager')).not.toContainText('.local');
    await expect(page.locator('#filePreviewModal')).not.toContainText('E2E');
    await expect(page.locator('#filePreviewModal')).not.toContainText('.local');
    await expectCurrentCaptureTerminology(page);
    expect(await page.evaluate(() => window.__captureFileManagerSocketEvents)).toEqual([]);
    expect(fs.readdirSync(frameDirectory).filter(name => name.endsWith('.png'))).toHaveLength(6);
    await assertCaptureNetworkClean(page);
});

test('captures six current Command Sets animation frames without remote actions', async ({ page }, testInfo) => {
    const frameDirectory = captureAssetsEnabled()
        ? path.resolve(__dirname, '..', '..', '.test-run.tmp', 'command-sets-frames')
        : testInfo.outputPath('command-sets-frames');
    fs.rmSync(frameDirectory, { recursive: true, force: true });
    fs.mkdirSync(frameDirectory, { recursive: true });

    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);
    await sanitizeSeededCatalog(page);
    await seedCommandSetAnimationCatalog(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);
    await expect(page.locator('header.header')).not.toContainText('E2E');
    await expect(page.locator('main')).not.toContainText('E2E');
    await expect(page.locator('header.header')).not.toContainText('.local');
    await expect(page.locator('main')).not.toContainText('.local');
    await captureCssFrame(page, frameDirectory, '01-saved-connections.png');

    await page.locator('#commandLibraryBtn').click();
    await page.locator('#commandSetsTab').click();
    await expect(page.locator('#commandWorkspaceModal')).toHaveClass(/show/);
    await expect(page.locator('#commandSetManagementList')).toContainText('Baseline diagnostics');
    await expect(page.locator('#commandSetManagementList')).toContainText('Access verification');
    await captureCssFrame(page, frameDirectory, '02-command-sets.png');

    const baselineSet = page.locator('#commandSetManagementList .command-set-management-item')
        .filter({ hasText: 'Baseline diagnostics' });
    await baselineSet.locator('[data-command-set-action="edit"]').click();
    await expect(page.locator('#commandSetEditorView')).toBeVisible();
    await expect(page.locator('#commandSetNameInput')).toHaveValue('Baseline diagnostics');
    await expect(page.locator('#commandSetSteps .command-set-step')).toHaveCount(2);
    await expect(page.locator('#commandSetSteps')).toContainText('1. System Uptime');
    await expect(page.locator('#commandSetSteps')).toContainText('2. Service Status');
    await captureCssFrame(page, frameDirectory, '03-baseline-editor.png');

    await page.locator('#commandSetSearchInput').fill('Disk Usage');
    await expect(page.locator('#commandSetLibraryResults')).toContainText('Disk Usage');
    await captureCssFrame(page, frameDirectory, '04-disk-command-filter.png');

    await page.locator('#commandSetLibraryResults .command-set-library-item')
        .filter({ hasText: 'Disk Usage' }).first().click();
    await expect(page.locator('#commandSetSteps .command-set-step')).toHaveCount(3);
    await expect(page.locator('#commandSetSteps')).toContainText('3. Disk Usage');
    await page.evaluate(() => {
        const updated = window.CommandSetManager.commandSets.map(commandSet => (
            commandSet.id === 'e2e-command-set'
                ? {
                    ...commandSet,
                    steps: window.CommandSetManager.draftSteps.map(step => ({ ...step })),
                    resolved_command: 'uptime && systemctl status webssh && df -h',
                }
                : commandSet
        ));
        window.CommandSetManager.setCommandSets(updated);
    });
    await captureCssFrame(page, frameDirectory, '05-three-step-order.png');

    await page.locator('#closeCommandWorkspaceModal').click();
    await page.locator('#newConnectionBtn').click();
    await page.evaluate(() => window.selectConnectionProfile('post-command-set'));
    await sanitizeSeededCatalog(page);
    await expect(page.locator('#connectionModalTitle')).toHaveText('Quick Connect');
    await expect(page.locator('#connectionCommandModeSet')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#commandSetSelect option:checked')).toHaveText('Baseline diagnostics');
    await expect(page.locator('#connectionCommandPreview')).toContainText('uptime');
    await expect(page.locator('#connectionModal')).not.toContainText('E2E');
    await expect(page.locator('#connectionModal')).not.toContainText('.local');
    await expectCurrentCaptureTerminology(page);
    await captureCssFrame(page, frameDirectory, '06-connection-assignment.png');

    expect(fs.readdirSync(frameDirectory).filter(name => name.endsWith('.png'))).toHaveLength(6);
    await assertCaptureNetworkClean(page);
});

test('captures a contained multi-session workspace and the current theme menu', async ({ page }, testInfo) => {
    await installCaptureNetworkGuard(page);
    await login(page);
    await installSshConnectTrap(page);
    await sanitizeSeededCatalog(page);
    await seedDemoWorkspace(page);

    expect(page.viewportSize()).toEqual(DESKTOP_VIEWPORT);
    await expect(page.locator('#sessionTabs')).toContainText('Production Edge');
    await expect(page.locator('#sessionTabs')).toContainText('Build Runner');
    await expect(page.locator('#sessionTabs')).toContainText('Audit Node');
    await expect(page.locator('#sessionTabs')).toContainText('Database Bastion');
    await expect(page.locator('#notepadPanel')).toContainText('Notepad');
    await expect(page.locator('#sessionNotepad')).toHaveValue(/edge-01\.example/);
    await expect(page.locator('header.header')).not.toContainText('E2E');
    await expect(page.locator('main')).not.toContainText('E2E');
    await expect(page.locator('header.header')).not.toContainText('.local');
    await expect(page.locator('main')).not.toContainText('.local');
    await expectCurrentCaptureTerminology(page);
    await assertWorkspaceIsContained(page);
    await captureDesktopStill(page, 'multi.png', testInfo);

    await page.locator('#accountBtnHeader').click();
    await page.locator('#accountSettingsBtn').click();
    await expect(page.locator('#settingsModal')).toHaveClass(/show/);
    await expect(page.locator('#settingsThemeSelect option')).toHaveCount(10);
    await expect(page.locator('#settingsThemeSelect')).toContainText('Glass Ops');
    await expect(page.locator('#settingsThemeSelect')).toContainText('Obsidian');
    const themeBounds = await page.locator('#settingsModal .modal-content').boundingBox();
    expect(themeBounds).not.toBeNull();
    expect(themeBounds.x).toBeGreaterThanOrEqual(0);
    expect(themeBounds.y).toBeGreaterThanOrEqual(0);
    expect(themeBounds.x + themeBounds.width).toBeLessThanOrEqual(DESKTOP_VIEWPORT.width);
    expect(themeBounds.y + themeBounds.height).toBeLessThanOrEqual(DESKTOP_VIEWPORT.height);
    await assertWorkspaceIsContained(page);
    await captureDesktopStill(page, 'themes.png', testInfo);

    await assertCaptureNetworkClean(page);
});

test.describe('mobile product capture', () => {
    test.use({
        viewport: MOBILE_VIEWPORT,
        deviceScaleFactor: 3,
    });

    test('captures the current Hosts start surface without overflow', async ({ page }, testInfo) => {
        await installCaptureNetworkGuard(page);
        await login(page);
        await installSshConnectTrap(page);
        await sanitizeSeededCatalog(page);

        expect(page.viewportSize()).toEqual(MOBILE_VIEWPORT);
        const launcher = page.locator('.profile-launcher');
        await expect(launcher.getByText('Hosts', { exact: true })).toBeVisible();
        await expect(launcher.getByText('Production gateway', { exact: true })).toBeVisible();
        await expect(launcher).not.toContainText('E2E');
        await expect(launcher).not.toContainText('.local');
        await expectCurrentCaptureTerminology(page);

        const layout = await page.evaluate(() => ({
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            bodyWidth: document.body.scrollWidth,
        }));
        expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
        expect(layout.bodyWidth).toBeLessThanOrEqual(layout.viewportWidth);

        const filePath = captureOutputPath(testInfo, 'mobile.png');
        await page.screenshot({
            path: filePath,
            animations: 'disabled',
            caret: 'hide',
        });
        expect(readPngSize(filePath)).toEqual(MOBILE_CAPTURE_SIZE);
        await assertCaptureNetworkClean(page);
    });
});
