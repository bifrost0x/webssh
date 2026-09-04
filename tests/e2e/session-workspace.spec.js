const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 4 / 3,
});

function capturePath(testInfo, filename) {
    return process.env.WEBSSH_CAPTURE_ASSETS === '1'
        ? path.resolve(__dirname, '..', '..', 'assets', filename)
        : testInfo.outputPath(filename);
}

function pngSize(filePath) {
    const png = fs.readFileSync(filePath);
    return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) };
}

async function seedLinuxSession(page, options = {}) {
    await expect.poll(() => page.evaluate(() => (
        typeof Terminal === 'function'
        && typeof SessionManager !== 'undefined'
        && typeof SessionManager.createSession === 'function'
    ))).toBe(true);
    await page.evaluate(seedOptions => {
        const originalEmit = window.socket.emit.bind(window.socket);
        let insightSample = 0;
        window.__workspaceEvents = [];
        window.__workspaceInventoryRequests = 0;
        window.__workspaceInventoryMode = 'full';
        window.__workspaceClipboard = null;
        window.__workspaceChartSamples = { pressure: 0, network: 0 };
        const fileRows = [
            { name: 'releases', is_dir: true, size: 0, permissions: 'drwxr-xr-x' },
            { name: 'compose.yaml', is_dir: false, size: 2841, permissions: '-rw-r--r--' },
            { name: 'healthcheck.sh', is_dir: false, size: 912, permissions: '-rwxr-xr-x' },
            { name: 'README.md', is_dir: false, size: 4876, permissions: '-rw-r--r--' },
        ];
        const linuxFileSource = {
            source_id: 'sftp-session:workspace-linux',
            kind: 'sftp',
            label: 'Production Edge',
            endpoint: 'edge-01.example:22',
            protocol: 'SFTP',
            capabilities: [
                'list', 'read', 'write', 'mkdir', 'rename', 'delete',
                'preview', 'edit', 'recursive', 'remote-transfer',
            ],
            ephemeral: false,
            security: { host_key_verified: true },
        };
        const systemd = {
            state: 'degraded',
            total: 3,
            active: 1,
            failed: 1,
            returned: 3,
            truncated: false,
            services: [
                { unit: 'nginx.service', load: 'loaded', active: 'active', sub: 'running', description: 'A high performance web server' },
                { unit: 'backup.service', load: 'loaded', active: 'failed', sub: 'failed', description: 'Nightly backup job' },
                { unit: 'cleanup.service', load: 'loaded', active: 'inactive', sub: 'dead', description: 'Temporary file cleanup' },
            ],
        };
        const docker = {
            version: '27.5.1',
            running: 1,
            total: 2,
            returned: 2,
            truncated: false,
            containers: [
                { name: 'webssh', status: 'Up 3 hours (healthy)' },
                { name: 'worker', status: 'Exited (1) 12 minutes ago' },
            ],
        };

        const originalDrawLineChart = window.SessionDiagnosticsCharts.drawLineChart;
        window.SessionDiagnosticsCharts.drawLineChart = function recordChartSamples(canvas, series, options) {
            const sampleCount = Math.max(0, ...series.map(item => item.values?.length || 0));
            if (canvas.id === 'sessionDiagnosticsPressureChart') {
                window.__workspaceChartSamples.pressure = sampleCount;
            } else if (canvas.id === 'sessionDiagnosticsNetworkChart') {
                window.__workspaceChartSamples.network = sampleCount;
            }
            return originalDrawLineChart.call(this, canvas, series, options);
        };
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: {
                writeText(text) {
                    window.__workspaceClipboard = text;
                    return Promise.resolve();
                },
            },
        });

        function deliver(event, payload) {
            queueMicrotask(() => window.socket.listeners(event).forEach(listener => listener(payload)));
        }

        window.socket.emit = function workspaceTestEmit(event, payload, ...rest) {
            let recordedPayload = payload;
            try {
                recordedPayload = structuredClone(payload);
            } catch (_error) {
                // Socket callbacks are not part of the observability requests under test.
            }
            window.__workspaceEvents.push({ event, payload: recordedPayload });
            if (event === 'list_profiles') {
                deliver('profiles_list', { profiles: [] });
                return window.socket;
            }
            if (payload?.session_id === 'workspace-cisco') {
                if (event === 'probe_session_sftp') {
                    deliver('session_sftp_capability', {
                        success: true,
                        available: false,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (event === 'request_session_insights') {
                    deliver('session_insights', {
                        success: false,
                        unsupported: true,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (['ssh_input', 'ssh_resize'].includes(event)) return window.socket;
            }
            if (payload?.session_id === 'workspace-linux'
                    || payload?.source_id === linuxFileSource.source_id) {
                if (event === 'probe_session_sftp') {
                    const sendCapability = () => deliver('session_sftp_capability', {
                        success: true,
                        available: seedOptions.sftpAvailable !== false,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                    });
                    if (seedOptions.sftpProbeDelayMs) {
                        setTimeout(sendCapability, seedOptions.sftpProbeDelayMs);
                    } else {
                        sendCapability();
                    }
                    return window.socket;
                }
                if (event === 'request_session_runtime_inventory') {
                    window.__workspaceInventoryRequests += 1;
                    const response = {
                        success: true,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                        sampled_at: 1786350000 + window.__workspaceInventoryRequests,
                        docker,
                    };
                    if (window.__workspaceInventoryMode === 'generic') {
                        deliver('session_runtime_inventory', {
                            success: false,
                            session_id: payload.session_id,
                            request_id: payload.request_id,
                            error: 'Runtime inventory unavailable',
                        });
                    } else if (window.__workspaceInventoryMode === 'permission') {
                        deliver('session_runtime_inventory', {
                            ...response,
                            permission_denied: ['systemd'],
                        });
                    } else {
                        deliver('session_runtime_inventory', { ...response, systemd });
                    }
                    return window.socket;
                }
                if (event === 'request_session_insights') {
                    insightSample += 1;
                    window.__workspaceInsightSample = insightSample;
                    const cpuSamples = [
                        [200, 0, 150, 950],
                        [260, 0, 180, 1060],
                        [400, 0, 260, 1120],
                    ];
                    const memory = {
                        total_kib: 16 * 1024 * 1024,
                        available_kib: 6 * 1024 * 1024,
                        used_kib: 10 * 1024 * 1024,
                    };
                    const stats = seedOptions.partialMetrics ? { memory } : {
                        cpu: cpuSamples[Math.min(insightSample - 1, cpuSamples.length - 1)],
                        memory,
                        disk: {
                            total_kib: 100 * 1024 * 1024,
                            available_kib: 39 * 1024 * 1024,
                            used_kib: 61 * 1024 * 1024,
                            percent: 61,
                        },
                        uptime_seconds: 93784,
                        os_name: 'Ubuntu 24.04.2 LTS',
                    };
                    if (payload.include_diagnostics === true) {
                        window.__workspaceExpandedRequests = (
                            window.__workspaceExpandedRequests || 0
                        ) + 1;
                        Object.assign(stats, {
                            load: { one: 1.25, five: 0.75, fifteen: 0.5, cpu_count: 8 },
                            swap: {
                                total_kib: 2 * 1024 * 1024,
                                available_kib: 1536 * 1024,
                                used_kib: 512 * 1024,
                            },
                            network: {
                                received_bytes: 1000000 + insightSample * 8192,
                                transmitted_bytes: 500000 + insightSample * 4096,
                            },
                            processes: {
                                total: 215,
                                zombies: 1,
                                top_cpu: [
                                    { pid: 812, user: 'postgres', command: 'postgres', cpu_percent: 32.5, memory_percent: 4.1 },
                                    { pid: 924, user: 'deploy', command: 'python3', cpu_percent: 18, memory_percent: 2.5 },
                                ],
                                top_memory: [
                                    { pid: 177, user: 'redis', command: 'redis-server', cpu_percent: 3.5, memory_percent: 12.4 },
                                ],
                            },
                        });
                    }
                    deliver('session_insights', {
                        success: true,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                        stats,
                    });
                    return window.socket;
                }
                if (event === 'get_home_directory') {
                    deliver('home_directory', {
                        source_id: payload.source_id,
                        path: '/srv/webssh/current',
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (event === 'list_directory') {
                    deliver('directory_listing', {
                        source_id: payload.source_id,
                        path: payload.remote_path,
                        files: fileRows,
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (event === 'rename_file') {
                    const acknowledgement = rest.find(value => typeof value === 'function');
                    acknowledgement?.({
                        success: true,
                        source_id: payload.source_id,
                        old_path: payload.old_path,
                        new_path: payload.new_path,
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (['ssh_input', 'ssh_resize'].includes(event)) return window.socket;
            }
            return originalEmit(event, payload, ...rest);
        };

        window.__createWorkspaceSession = function createWorkspaceSession() {
            if (seedOptions.bufferedOutput) {
                TerminalManager.seedRestoredOutput(
                    'workspace-linux',
                    seedOptions.bufferedOutput,
                    1,
                );
            }
            SessionManager.createSession({
                session_id: 'workspace-linux',
                host: 'edge-01.example',
                port: 22,
                username: 'ops',
                display_name: 'Production Edge',
                file_source: linuxFileSource,
                use_tmux: seedOptions.useTmux === true,
                tmux_session_name: seedOptions.useTmux
                    ? 'webssh_ops_edge_01'
                    : null,
            });
            SessionManager.assignSessionToPane('workspace-linux', 0);
        };
        window.__createWorkspaceSwitchSession = function createWorkspaceSwitchSession() {
            SessionManager.createSession({
                session_id: 'workspace-cisco',
                host: 'core-switch.example',
                port: 22,
                username: 'operator',
                display_name: 'Core Switch',
            });
            SessionManager.assignSessionToPane('workspace-cisco', 0);
        };
        window.__createWorkspaceSession();
        document.querySelector('.account-name').textContent = 'operator';
        setTimeout(() => {
            TerminalManager.writeOutput('workspace-linux', [
                '\u001b[1;36mProduction Edge - Ubuntu 24.04 LTS\u001b[0m',
                'ops@edge-01:~$ systemctl is-active webssh',
                'active',
                'ops@edge-01:~$ uptime',
                ' 10:42:18 up 1 day, 2:03, load average: 0.18, 0.12, 0.09',
                'ops@edge-01:~$ ',
            ].join('\r\n'));
        }, 250);
        document.getElementById('sessionNotepad').value = [
            'Release checklist',
            '',
            '- Review service status',
            '- Verify deployment health',
            '- Archive audit notes',
        ].join('\n');
    }, options);
}

test('terminal selections copy through keyboard and command palette actions', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await expect(page.locator('.terminal-pane.active .xterm-helper-textarea')).toBeAttached();

    const selectTerminalOutput = () => page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const terminal = TerminalManager.terminals[terminalKey];
        terminal.selectAll();
        return terminal.getSelection();
    });
    await expect.poll(selectTerminalOutput).toContain('Production Edge');
    const keyboardSelection = await selectTerminalOutput();
    await page.locator('.terminal-pane.active .xterm-helper-textarea').focus();
    await page.keyboard.press('Control+c');
    await expect.poll(() => page.evaluate(() => window.__workspaceClipboard))
        .toBe(keyboardSelection);

    const paletteSelection = await page.evaluate(() => {
        window.__workspaceClipboard = null;
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const terminal = TerminalManager.terminals[terminalKey];
        terminal.selectAll();
        return terminal.getSelection();
    });
    expect(paletteSelection).not.toBe('');
    await page.locator('#saveTranscriptBtn').focus();
    await page.keyboard.press('Control+k');
    await page.locator('#commandPaletteInput').fill('Copy Selection');
    await page.locator('#commandPaletteInput').press('Enter');
    await expect.poll(() => page.evaluate(() => window.__workspaceClipboard))
        .toBe(paletteSelection);
    await expect(page.locator('.notification-success')).toContainText('Selection copied');
    await assertNoExternalRequests(page);
});

test('Android IME composition sends the complete value without its stale prefix', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const terminal = TerminalManager.terminals[terminalKey];
        const textarea = terminal.textarea;
        window.__androidCompositionDispose = TerminalManager.setupAndroidCompositionGuard(
            terminal,
            true,
        );

        textarea.value = '1';
        textarea.setSelectionRange(1, 1);
        textarea.dispatchEvent(new CompositionEvent('compositionstart', {
            bubbles: true,
        }));
        textarea.value = '12345';
        textarea.setSelectionRange(5, 5);
        textarea.dispatchEvent(new CompositionEvent('compositionupdate', {
            bubbles: true,
            data: '12345',
        }));
        textarea.dispatchEvent(new CompositionEvent('compositionend', {
            bubbles: true,
            data: '12345',
        }));
    });

    await expect.poll(() => page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .map(event => event.payload.data))).toContain('12345');
    expect(await page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .map(event => event.payload.data))).not.toContain('2345');
    await page.evaluate(() => window.__androidCompositionDispose());
    await assertNoExternalRequests(page);
});

test('tmux ignores replayed OSC 52 and accepts a live clipboard selection', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, {
        useTmux: true,
        bufferedOutput: '\u001b]52;;c3RhbGUgdG11eCBzZWxlY3Rpb24=\u0007',
    });

    await page.waitForTimeout(100);
    expect(await page.evaluate(() => window.__workspaceClipboard)).toBeNull();

    await page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        TerminalManager.terminals[terminalKey].write(
            '\u001b]52;;dG11eCBzZWxlY3Rpb24=\u0007',
        );
    });

    expect(await page.evaluate(() => window.__workspaceClipboard)).toBeNull();
    await page.locator('#notificationContainer .notification-action').click();
    await expect.poll(() => page.evaluate(() => window.__workspaceClipboard))
        .toBe('tmux selection');
    await assertNoExternalRequests(page);
});

test('plain SSH sessions ignore remote OSC 52 clipboard writes', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        TerminalManager.terminals[terminalKey].write(
            '\u001b]52;;dW50cnVzdGVkIHJlbW90ZSBvdXRwdXQ=\u0007',
        );
    });
    await page.waitForTimeout(100);

    expect(await page.evaluate(() => window.__workspaceClipboard)).toBeNull();
    await assertNoExternalRequests(page);
});

test('single-session workspace keeps terminal primary with on-demand Files, Diagnostics, and Notes', async ({ page }, testInfo) => {
    await login(page);
    await seedLinuxSession(page);

    const filesTab = page.locator('#contextFilesTab');
    await expect(filesTab).toBeEnabled();
    await expect(filesTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#contextWorkspace')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#fmLeftBadge')).toHaveText('ops@edge-01.example');
    await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(5);
    await expect(page.locator('#fmRightPane')).toBeHidden();
    await expect(page.locator('#fmTransfer')).toBeHidden();
    await expect(page.locator('#fmEmbeddedUpload')).toBeVisible();
    await expect(page.locator('#fmNewFolder')).toBeEnabled();
    await expect(page.locator('#fmEmbeddedUpload')).toBeEnabled();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');

    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#sftpFileManager')).toBeVisible();
    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#fmNewFolder')).toBeEnabled();
    await expect(page.locator('#fmEmbeddedUpload')).toBeEnabled();

    const embeddedFileLayout = await page.evaluate(() => {
        const bounds = element => element.getBoundingClientRect();
        const toolbar = document.querySelector('.fm-embedded-mode .fm-toolbar-right');
        const toolbarBounds = bounds(toolbar);
        const fileRows = Array.from(document.querySelectorAll(
            '.fm-embedded-mode #fmLeftList .fm-file-item',
        ));
        const xterm = document.querySelector('.terminal-pane.active .xterm');
        const viewport = document.querySelector('.terminal-pane.active .xterm-viewport');
        const themeProbe = document.createElement('span');
        themeProbe.style.color = getComputedStyle(document.body).getPropertyValue('--term-background');
        document.body.appendChild(themeProbe);
        const terminalBackground = getComputedStyle(themeProbe).color;
        themeProbe.remove();
        return {
            maxRowHeight: Math.max(...fileRows.map(row => bounds(row).height)),
            toolbarOverflow: toolbar.scrollWidth - toolbar.clientWidth,
            toolbarRows: new Set(Array.from(toolbar.querySelectorAll('button'))
                .map(button => Math.round(bounds(button).top))).size,
            toolbarButtonsInside: Array.from(toolbar.querySelectorAll('button')).every(button => {
                const buttonBounds = bounds(button);
                return buttonBounds.left >= toolbarBounds.left
                    && buttonBounds.right <= toolbarBounds.right + 1;
            }),
            xtermPadding: getComputedStyle(xterm).padding,
            viewportBackground: getComputedStyle(viewport).backgroundColor,
            terminalBackground,
        };
    });
    expect(embeddedFileLayout.maxRowHeight).toBeLessThanOrEqual(46);
    expect(embeddedFileLayout.toolbarOverflow).toBeLessThanOrEqual(1);
    expect(embeddedFileLayout.toolbarRows).toBe(1);
    expect(embeddedFileLayout.toolbarButtonsInside).toBe(true);
    expect(embeddedFileLayout.xtermPadding).toBe('0px');
    expect(embeddedFileLayout.viewportBackground).toBe(embeddedFileLayout.terminalBackground);

    await page.locator('#fmLeftList .fm-file-item[data-index="0"]').dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases');
    expect(await page.evaluate(() => window.__workspaceInsightSample || 0)).toBe(0);
    await expect(page.locator('#notepadPanel')).toBeHidden();

    const geometry = await page.evaluate(() => {
        const box = selector => {
            const rect = document.querySelector(selector).getBoundingClientRect();
            return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, width: rect.width };
        };
        return {
            terminal: box('#terminalGrid'),
            files: box('#sessionFilesPanel'),
            viewport: { width: innerWidth, height: innerHeight },
        };
    });
    expect(geometry.terminal.width).toBeGreaterThan(650);
    expect(geometry.files.width).toBeGreaterThanOrEqual(360);
    expect(geometry.terminal.right).toBeLessThanOrEqual(geometry.files.left + 1);
    expect(geometry.files.right).toBeLessThanOrEqual(geometry.viewport.width);
    expect(geometry.files.bottom).toBeLessThanOrEqual(geometry.viewport.height);

    const initialContextWidth = await page.locator('#contextWorkspace').evaluate(
        element => element.getBoundingClientRect().width,
    );
    await page.locator('#contextWorkspaceResizer').focus();
    await page.locator('#contextWorkspaceResizer').press('ArrowLeft');
    await expect.poll(() => page.evaluate(() => Number(
        localStorage.getItem('webssh.workspace.contextWidth'),
    ))).toBe(Math.round(initialContextWidth + 24));
    const resizedContextWidth = await page.locator('#contextWorkspace').evaluate(
        element => element.getBoundingClientRect().width,
    );
    expect(resizedContextWidth).toBeGreaterThan(initialContextWidth);

    const screenshotPath = capturePath(testInfo, 'session-workspace.png');
    await page.screenshot({
        path: screenshotPath,
        animations: 'disabled',
        caret: 'hide',
    });
    expect(pngSize(screenshotPath)).toEqual({ width: 2560, height: 1440 });

    const commandsTab = page.locator('#contextCommandsTab');
    await expect(commandsTab).toBeEnabled();
    await commandsTab.click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await expect(page.locator('.session-command-search')).toBeFocused();
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
    await expect(page.locator('.session-command-item')).not.toHaveCount(0);
    const commandsScreenshotPath = capturePath(testInfo, 'session-commands-context.png');
    await page.screenshot({
        path: commandsScreenshotPath,
        animations: 'disabled',
        caret: 'hide',
    });
    expect(pngSize(commandsScreenshotPath)).toEqual({ width: 2560, height: 1440 });
    const insertedCommand = await page.locator('.session-command-item code').first().innerText();
    await page.locator('.session-command-item').first().getByRole('button', { name: 'Insert' }).click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    const insertedEvent = await page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .at(-1));
    expect(insertedEvent.payload).toEqual({
        session_id: 'workspace-linux',
        data: insertedCommand,
    });
    expect(insertedCommand).not.toMatch(/[\r\n]/);

    await page.getByRole('button', { name: 'Manage Commands' }).click();
    await expect(page.locator('#commandWorkspaceModal')).toHaveClass(/show/);
    await expect(page.locator('#sessionCommandsPanel')).toBeHidden();
    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();

    await page.locator('#contextNotesTab').click();
    await expect(page.locator('#notepadPanel')).toBeVisible();
    await expect(page.locator('#sessionNotepad')).toHaveValue(/Release checklist/);
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    expect(await page.evaluate(() => window.__workspaceInsightSample || 0)).toBe(0);
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('#notepadPanel')).toBeHidden();
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await page.evaluate(() => {
        window.sessionWorkspace.setVisible(false);
        window.sessionWorkspace.setVisible(true);
    });
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();
    await page.locator('#contextWorkspaceLauncher').click();
    await expect(page.locator('#notepadPanel')).toBeVisible();

    const diagnosticsTab = page.locator('#contextDiagnosticsTab');
    await expect(diagnosticsTab).toBeEnabled();
    await diagnosticsTab.click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsState')).toHaveText('Live');
    await expect(page.locator('#sessionDiagnosticsMemoryValue')).toHaveText('62.5%');
    await expect(page.locator('#sessionDiagnosticsDiskValue')).toHaveText('61.0%');
    await expect(page.locator('#sessionDiagnosticsOs')).toHaveText('Ubuntu 24.04.2 LTS');
    await expect(page.locator('#sessionDiagnosticsCpuValue')).toContainText('%', { timeout: 6000 });
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();

    await page.evaluate(() => SessionManager.setSplitLayout(2));
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await expect(filesTab).toBeEnabled();
    await page.locator('#contextWorkspaceLauncher').click();
    await filesTab.click();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await page.evaluate(() => SessionManager.setSplitLayout(1));
    await expect(filesTab).toBeEnabled();
    await expect(filesTab).toHaveAttribute('aria-selected', 'false');
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await assertNoExternalRequests(page);
});

test('embedded Workspace SFTP keeps folder drag beside the Move picker', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#fmTransferBetween')).toBeHidden();

    const source = page.locator('#fmLeftList .fm-file-item[data-index="1"]');
    const target = page.locator('#fmLeftList .fm-file-item[data-index="0"]');
    const move = page.locator('#fmMove');
    await expect(move).toBeVisible();
    await expect(move).toBeDisabled();
    await source.click();
    await expect(move).toBeEnabled();

    await move.click();
    await expect(page.locator('.fm-move-picker')).toBeVisible();
    await expect(page.locator('[data-move-picker-path]')).toHaveText(
        '/srv/webssh/current',
    );
    await expect(page.locator('[data-move-picker-confirm]')).toBeDisabled();
    await page.keyboard.press('Escape');
    await expect(page.locator('.fm-move-picker')).toHaveCount(0);

    await source.dragTo(target);

    await expect.poll(() => page.evaluate(() => (
        window.__workspaceEvents.find(event => event.event === 'rename_file')?.payload
    ))).toMatchObject({
        source_id: 'sftp-session:workspace-linux',
        old_path: '/srv/webssh/current/compose.yaml',
        new_path: '/srv/webssh/current/releases/compose.yaml',
    });
    await expect(page.locator('.fm-directory-drop-target')).toHaveCount(0);
    await assertNoExternalRequests(page);
});

test('360px mobile workspace keeps tools available and preserves context across live resizes', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 360, height: 640 });
    await login(page);
    await seedLinuxSession(page);
    await page.waitForTimeout(500);

    expect(await page.evaluate(() => window.__workspaceInsightSample || 0)).toBe(0);
    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await expect(page.locator('#contextFilesTab')).toBeEnabled();
    await expect(page.locator('#contextCommandsTab')).toBeEnabled();
    await expect(page.locator('#contextNotesTab')).toBeEnabled();
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#contextWorkspaceLauncher')).toBeHidden();
    await expect(page.locator('#mobileAppDock')).toBeVisible();
    await expect(page.locator('#mobileCommandToggle')).toBeVisible();
    await expect(page.locator('.split-controls')).toBeHidden();

    const terminalDock = page.locator('[data-mobile-view="workspaces"]');
    const sftpDock = page.locator('[data-mobile-view="session-files"]');
    const commandsDock = page.locator('[data-mobile-view="session-commands"]');
    const metricsDock = page.locator('[data-mobile-view="session-diagnostics"]');
    await expect(terminalDock).toContainText('Terminal');
    await expect(sftpDock).toContainText('SFTP');
    await expect(commandsDock).toContainText('Commands');
    await expect(metricsDock).toContainText('Metrics');
    await expect(sftpDock).toBeEnabled();
    await expect(commandsDock).toBeEnabled();
    await expect(metricsDock).toBeEnabled();

    await sftpDock.click();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(sftpDock).toHaveClass(/active/);

    await page.evaluate(() => {
        const manager = window.sftpFileManager;
        Object.assign(manager.panes.left, {
            loading: false,
            pendingDirectoryRequestId: null,
            pendingDirectoryPath: null,
            files: [
                { name: 'releases', is_dir: true, size: 0 },
                ...Array.from({ length: 30 }, (_, index) => ({
                    name: `mobile-report-${String(index).padStart(2, '0')}.txt`,
                    is_dir: false,
                    size: 12 + index,
                })),
            ],
        });
        manager.updatePathInput('left', manager.panes.left.path);
        manager.renderPane('left');
    });

    const embeddedList = page.locator('#sessionFilesPanel #fmLeftList');
    const embeddedFile = embeddedList.locator('.fm-file-item[data-index="1"]');
    await embeddedFile.click();
    await expect(embeddedFile).toHaveClass(/selected/);

    const embeddedScrollLayout = await page.evaluate(() => {
        const panel = document.getElementById('sessionFilesPanel');
        const mount = document.getElementById('sessionFilesMount');
        const list = document.getElementById('fmLeftList');
        return {
            panelDisplay: getComputedStyle(panel).display,
            panelHeight: panel.clientHeight,
            mountHeight: mount.clientHeight,
            listClientHeight: list.clientHeight,
            listScrollHeight: list.scrollHeight,
        };
    });
    expect(embeddedScrollLayout.listScrollHeight).toBeGreaterThan(
        embeddedScrollLayout.listClientHeight,
    );

    const embeddedListBox = await embeddedList.boundingBox();
    const touchClient = await page.context().newCDPSession(page);
    const touchX = embeddedListBox.x + (embeddedListBox.width / 2);
    const touchStartY = embeddedListBox.y + Math.min(embeddedListBox.height - 24, 300);
    await touchClient.send('Input.dispatchTouchEvent', {
        type: 'touchStart',
        touchPoints: [{ x: touchX, y: touchStartY }],
    });
    await touchClient.send('Input.dispatchTouchEvent', {
        type: 'touchMove',
        touchPoints: [{ x: touchX + 20, y: touchStartY - 2 }],
    });
    await touchClient.send('Input.dispatchTouchEvent', {
        type: 'touchMove',
        touchPoints: [{ x: touchX + 18, y: touchStartY - 160 }],
    });
    await touchClient.send('Input.dispatchTouchEvent', {
        type: 'touchEnd',
        touchPoints: [],
    });
    await expect.poll(() => embeddedList.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
    expect(embeddedScrollLayout.panelDisplay).toBe('flex');
    expect(embeddedScrollLayout.mountHeight).toBeLessThanOrEqual(
        embeddedScrollLayout.panelHeight,
    );

    await metricsDock.click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(metricsDock).toHaveClass(/active/);
    await terminalDock.click();
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await expect(terminalDock).toHaveClass(/active/);

    await page.evaluate(() => {
        TerminalManager.writeOutput(
            'workspace-linux',
            Array.from({ length: 160 }, (_, index) => `mobile history line ${index + 1}`)
                .join('\r\n'),
        );
    });
    await expect.poll(() => page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux']?.[0];
        return TerminalManager.terminals[terminalKey]?.buffer?.active?.baseY || 0;
    })).toBeGreaterThan(0);
    const scrollBeforeTouch = await page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const terminal = TerminalManager.terminals[terminalKey];
        terminal.scrollToBottom();
        return terminal.buffer.active.viewportY;
    });
    await page.locator('.terminal-pane.active .xterm').evaluate(surface => {
        const eventOptions = {
            bubbles: true,
            cancelable: true,
            pointerType: 'touch',
            pointerId: 41,
            clientX: 180,
        };
        surface.dispatchEvent(new PointerEvent('pointerdown', {
            ...eventOptions,
            clientY: 180,
        }));
        surface.dispatchEvent(new PointerEvent('pointermove', {
            ...eventOptions,
            clientY: 300,
        }));
        surface.dispatchEvent(new PointerEvent('pointerup', {
            ...eventOptions,
            clientY: 300,
        }));
    });
    await expect.poll(() => page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        return TerminalManager.terminals[terminalKey].buffer.active.viewportY;
    })).toBeLessThan(scrollBeforeTouch);

    await page.locator('#mobileCommandToggle').click();
    await expect(page.locator('#mobileInputBar')).toBeVisible();
    await expect(page.locator('#mobileInputCloseBtn')).toBeVisible();
    await expect(page.locator('#mobileCommandToggle')).toBeHidden();
    const sendHitTarget = await page.locator('#mobileSendBtn').evaluate(element => {
        const rect = element.getBoundingClientRect();
        return document.elementFromPoint(
            rect.left + rect.width / 2,
            rect.top + rect.height / 2,
        )?.closest('button')?.id;
    });
    expect(sendHitTarget).toBe('mobileSendBtn');
    await page.locator('#mobileInputCloseBtn').click();
    await expect(page.locator('#mobileCommandToggle')).toBeVisible();

    await page.locator('#mobileMoreBtn').click();
    await expect(page.locator('#headerButtons')).toHaveAttribute('role', 'dialog');
    await expect(page.locator('#headerButtons')).toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('.main-content')).toHaveAttribute('inert', '');
    await expect(page.locator('#workspaceNavBtn')).toBeFocused();
    await expect(page.locator('#manageProfilesBtn')).toBeVisible();
    await expect(page.locator('#fileTransferBtn')).toBeVisible();
    await expect(page.locator('#commandLibraryBtn')).toBeVisible();
    await expect(page.locator('#mobileToolsAction')).toContainText('Notes');
    await page.locator('#accountBtnHeader').focus();
    await page.keyboard.press('Tab');
    await expect(page.locator('#workspaceNavBtn')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.locator('#headerButtons')).not.toHaveClass(/is-open/);
    await expect(page.locator('.main-content')).not.toHaveAttribute('inert', '');
    await expect(page.locator('#mobileMoreBtn')).toBeFocused();
    await commandsDock.click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(commandsDock).toHaveClass(/active/);
    await page.evaluate(() => window.showNotification(
        'Connected to testuser@host.example',
        'success',
        10000,
    ));
    const mobileToastGeometry = await page.evaluate(() => {
        const toast = document.querySelector('.notification');
        const toolsHeader = document.querySelector('.context-workspace-header');
        const toastBox = toast.getBoundingClientRect();
        const headerBox = toolsHeader.getBoundingClientRect();
        return {
            separated: toastBox.bottom <= headerBox.top || toastBox.top >= headerBox.bottom,
            toastRight: toastBox.right,
            viewportWidth: innerWidth,
        };
    });
    expect(mobileToastGeometry.separated).toBe(true);
    expect(mobileToastGeometry.toastRight).toBeLessThanOrEqual(
        mobileToastGeometry.viewportWidth,
    );
    const commandsGeometry = await page.locator('#sessionCommandsPanel').evaluate(element => ({
        left: element.getBoundingClientRect().left,
        right: element.getBoundingClientRect().right,
        width: element.getBoundingClientRect().width,
    }));
    expect(commandsGeometry.left).toBeGreaterThanOrEqual(0);
    expect(commandsGeometry.right).toBeLessThanOrEqual(360);
    expect(commandsGeometry.width).toBeGreaterThanOrEqual(320);
    await expect(page.locator('header.header')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);

    await page.evaluate(() => {
        window.__workspaceResizeContinuity = 'preserved-without-reload';
    });
    const mobileScreenshotPath = capturePath(testInfo, 'session-mobile-commands-context.png');
    await page.screenshot({
        path: mobileScreenshotPath,
        animations: 'disabled',
        caret: 'hide',
    });

    await page.setViewportSize({ width: 900, height: 800 });
    await expect.poll(() => page.evaluate(() => window.workspaceLayoutController?.getState().mode))
        .toBe('tablet');
    await expect(page.locator('#contextCommandsTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Workspaces', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'File Manager', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Hosts', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Commands', exact: true })).toBeVisible();
    expect(await page.evaluate(() => window.__workspaceResizeContinuity)).toBe('preserved-without-reload');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(900);

    await page.setViewportSize({ width: 1280, height: 800 });
    await expect.poll(() => page.evaluate(() => window.workspaceLayoutController?.getState().mode))
        .toBe('desktop');
    await expect(page.locator('#contextCommandsTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    expect(await page.evaluate(() => window.__workspaceResizeContinuity)).toBe('preserved-without-reload');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(1280);
    await assertNoExternalRequests(page);
});

test('desktop-to-mobile resize is not mistaken for an open virtual keyboard', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await login(page);
    await seedLinuxSession(page);
    await page.locator('#contextNotesTab').click();
    await page.locator('#sessionNotepad').focus();

    await page.setViewportSize({ width: 360, height: 640 });
    await expect.poll(() => page.evaluate(() => window.workspaceLayoutController?.getState().mode))
        .toBe('mobile');
    await expect(page.locator('body')).not.toHaveClass(/keyboard-open/);
    await expect(page.locator('header.header')).toBeVisible();
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#contextNotesPanel')).toBeHidden();
    await expect(page.locator('#contextWorkspaceLauncher')).toBeHidden();
    await expect(page.locator('#mobileAppDock')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);

    await page.locator('#mobileMoreBtn').click();
    await page.locator('#mobileToolsAction').click();
    await expect(page.locator('#contextNotesPanel')).toBeVisible();
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('header.header')).toBeVisible();
    await expect(page.locator('.terminal-pane.active')).toBeVisible();
    await assertNoExternalRequests(page);
});

test('wide workspace keeps embedded SFTP closed when the session probe fails', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, { sftpAvailable: false });

    await expect.poll(() => page.evaluate(() => window.__workspaceEvents.filter(
        event => event.event === 'probe_session_sftp',
    ).length)).toBe(1);
    await expect(page.locator('#contextFilesTab')).toBeEnabled();
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await expect(page.locator('#contextDiagnosticsTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await page.locator('#contextFilesTab').click();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesStatus')).toContainText('SFTP is not available');
    await assertNoExternalRequests(page);
});

test('manual context choice wins while SFTP capability is still probing', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, { sftpProbeDelayMs: 500 });

    await page.locator('#contextNotesTab').click();
    await expect(page.locator('#contextNotesTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#contextFilesTab')).toBeEnabled({ timeout: 3000 });
    await expect(page.locator('#contextNotesTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#notepadPanel')).toBeVisible();
    await assertNoExternalRequests(page);
});

test('desktop context width survives a page reload without affecting mobile layout', async ({ page }) => {
    await login(page);
    await page.evaluate(() => {
        localStorage.setItem('webssh.workspace.contextWidth', '512');
    });
    await page.reload();

    await expect(page.locator('#contextWorkspace')).toBeVisible();
    await expect.poll(() => page.locator('#contextWorkspace').evaluate(
        element => Math.round(element.getBoundingClientRect().width),
    )).toBe(512);

    await page.setViewportSize({ width: 360, height: 640 });
    await expect.poll(() => page.evaluate(() => window.workspaceLayoutController?.getState().mode))
        .toBe('mobile');
    await expect(page.locator('#contextWorkspaceResizer')).toBeHidden();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
    await assertNoExternalRequests(page);
});

test('automatic context width follows live desktop resizes without a reload', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await login(page);
    await page.evaluate(() => {
        localStorage.removeItem('webssh.workspace.contextWidth');
        localStorage.removeItem('webssh.workspace.contextWidthMode');
    });
    await page.reload();

    const contextWidth = () => page.locator('#contextWorkspace').evaluate(
        element => Math.round(element.getBoundingClientRect().width),
    );
    await expect.poll(contextWidth).toBe(420);
    await expect.poll(() => page.evaluate(
        () => window.workspaceLayoutController?.getContextWidthMode(),
    )).toBe('auto');

    await page.setViewportSize({ width: 1920, height: 1080 });
    await expect.poll(contextWidth).toBe(614);

    await page.setViewportSize({ width: 3440, height: 1440 });
    await expect.poll(contextWidth).toBe(720);

    await page.setViewportSize({ width: 1280, height: 900 });
    await expect.poll(contextWidth).toBe(420);
    await assertNoExternalRequests(page);
});

test('narrow desktop tools contain German diagnostics and commands inside every surface', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await login(page);
    await page.evaluate(() => localStorage.setItem('language', 'de'));
    await page.reload();
    await seedLinuxSession(page);

    await page.locator('#contextWorkspaceResizer').focus();
    await page.locator('#contextWorkspaceResizer').press('Home');
    await expect.poll(() => page.locator('#contextWorkspace').evaluate(
        element => Math.round(element.getBoundingClientRect().width),
    )).toBe(320);

    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsMemoryValue')).toHaveText('62.5%');

    const diagnosticsGeometry = await page.evaluate(() => {
        const panel = document.querySelector('#contextWorkspace');
        const content = document.querySelector('.session-diagnostics-content');
        const grid = document.querySelector('.session-diagnostics-primary-grid');
        const visible = selector => Array.from(document.querySelectorAll(selector))
            .filter(element => !element.hidden && element.getClientRects().length > 0);
        const contained = (child, parent) => {
            const childBox = child.getBoundingClientRect();
            const parentBox = parent.getBoundingClientRect();
            return childBox.left >= parentBox.left - 1
                && childBox.right <= parentBox.right + 1;
        };
        const cards = visible('.session-diagnostics-primary-card');
        const sections = visible('.session-diagnostics-section');
        const escapedDescendants = [...cards, ...sections].flatMap(surface => (
            visible('h3, h4, strong, small, canvas, .session-diagnostics-card-heading')
                .filter(element => surface.contains(element) && !contained(element, surface))
                .map(element => ({
                    element: `${element.tagName}.${element.className}`,
                    surface: `${surface.tagName}.${surface.className}`,
                }))
        ));
        const overflowingSurfaces = [...cards, ...sections]
            .filter(surface => surface.scrollWidth > surface.clientWidth + 1)
            .map(surface => ({
                element: `${surface.tagName}.${surface.className}`,
                clientWidth: surface.clientWidth,
                scrollWidth: surface.scrollWidth,
            }));
        return {
            documentContained: document.documentElement.scrollWidth <= innerWidth,
            panelClipsOverflow: getComputedStyle(panel).overflowX === 'hidden',
            contentContained: content.scrollWidth <= content.clientWidth + 1,
            columns: getComputedStyle(grid).gridTemplateColumns.split(' ').length,
            escapedDescendants,
            overflowingSurfaces,
        };
    });
    expect(diagnosticsGeometry).toEqual({
        documentContained: true,
        panelClipsOverflow: true,
        contentContained: true,
        columns: 1,
        escapedDescendants: [],
        overflowingSurfaces: [],
    });

    await page.locator('#contextCommandsTab').click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(page.locator('.session-command-item')).not.toHaveCount(0);
    const commandsGeometry = await page.evaluate(() => {
        const panel = document.querySelector('#contextWorkspace');
        const results = document.querySelector('.session-command-results');
        const footer = document.querySelector('.session-command-popover-footer');
        const contained = (child, parent) => {
            const childBox = child.getBoundingClientRect();
            const parentBox = parent.getBoundingClientRect();
            return childBox.left >= parentBox.left - 1
                && childBox.right <= parentBox.right + 1;
        };
        const items = Array.from(document.querySelectorAll('.session-command-item'))
            .filter(element => element.getClientRects().length > 0);
        return {
            documentContained: document.documentElement.scrollWidth <= innerWidth,
            panelContained: panel.scrollWidth <= panel.clientWidth + 1,
            resultsContained: results.scrollWidth <= results.clientWidth + 1,
            footerContained: footer.scrollWidth <= footer.clientWidth + 1
                && Array.from(footer.children).every(child => contained(child, footer)),
            itemsContained: items.every(item => (
                item.scrollWidth <= item.clientWidth + 1
                && Array.from(item.children).every(child => contained(child, item))
            )),
        };
    });
    expect(commandsGeometry).toEqual({
        documentContained: true,
        panelContained: true,
        resultsContained: true,
        footerContained: true,
        itemsContained: true,
    });
    await assertNoExternalRequests(page);
});

test('Files context follows session capability and stays mounted while tools switch', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    const filesTab = page.locator('#contextFilesTab');
    const panel = page.locator('#sessionFilesPanel');
    await expect(filesTab).toHaveAttribute('aria-selected', 'true');
    await expect(panel).toBeVisible();

    await page.evaluate(() => window.__createWorkspaceSwitchSession());
    await expect.poll(() => page.evaluate(() => window.__workspaceEvents.some(
        event => event.event === 'probe_session_sftp'
            && event.payload.session_id === 'workspace-cisco',
    ))).toBe(true);
    await expect(filesTab).toBeEnabled();
    await expect(filesTab).toHaveAttribute('aria-selected', 'false');
    await expect(panel).toBeHidden();
    await filesTab.click();
    await expect(panel).toBeVisible();
    await expect(page.locator('#sessionFilesStatus')).toContainText('SFTP is not available');

    await page.evaluate(() => SessionManager.assignSessionToPane('workspace-linux', 0));
    await expect(filesTab).toBeEnabled();
    await filesTab.click();
    await expect(panel).toBeVisible();

    await page.locator('#contextCommandsTab').click();
    await expect(panel).toBeHidden();
    await page.evaluate(() => SessionManager.assignSessionToPane('workspace-cisco', 0));
    await expect(panel).toBeHidden();
    await page.evaluate(() => SessionManager.assignSessionToPane('workspace-linux', 0));
    await expect(filesTab).toBeEnabled();
    await filesTab.click();
    await expect(panel).toBeVisible();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await assertNoExternalRequests(page);
});

test('closing the full File Manager restores the active embedded Files context', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel #fmLeftList .fm-file-item')).toHaveCount(5);

    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await page.locator('.fm-source-tab-add[data-source-target="left"]').click();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    await page.locator('[data-source-key="sftp-session:workspace-linux"]').click();
    await expect(page.locator('#sftpFileManager #fmLeftList .fm-file-item')).toHaveCount(5);
    await page.locator('#workspaceNavBtn').click();

    await expect(page.locator('#sftpFileManager')).not.toHaveClass(/show/);
    await expect(page.locator('#contextFilesTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel #fmLeftBadge')).toHaveText('ops@edge-01.example');
    await expect(page.locator('#sessionFilesPanel #fmLeftList .fm-file-item')).toHaveCount(5);
    await assertNoExternalRequests(page);
});

test('Escape closes the source launcher but top-level navigation restores embedded Files', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel #fmLeftList .fm-file-item')).toHaveCount(5);

    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await page.locator('.fm-source-tab-add[data-source-target="left"]').click();
    await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);

    await page.keyboard.press('Escape');
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);

    await page.keyboard.press('Escape');
    await expect(page.locator('#sftpFileManager')).toHaveClass(/show/);
    await expect(page.locator('#fileTransferBtn')).toHaveAttribute('aria-current', 'page');

    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#sftpFileManager')).not.toHaveClass(/show/);
    await expect(page.locator('#contextFilesTab')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel #fmLeftBadge')).toHaveText('ops@edge-01.example');
    await expect(page.locator('#sessionFilesPanel #fmLeftList .fm-file-item')).toHaveCount(5);
    await assertNoExternalRequests(page);
});

test('partial telemetry shows only metrics returned by the device', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, { partialMetrics: true, sftpAvailable: false });

    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsMemoryMetric')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsCpuMetric')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsDiskMetric')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsOs')).toBeHidden();
    await assertNoExternalRequests(page);
});

test('diagnostics canvas renders correlated inventory and keeps controls clipboard-only', async ({ page }, testInfo) => {
    await login(page);
    await seedLinuxSession(page);
    await expect(page.locator('header')).toHaveCount(1);

    expect(await page.evaluate(() => window.__workspaceExpandedRequests || 0)).toBe(0);
    const diagnosticsTab = page.locator('#contextDiagnosticsTab');
    await expect(diagnosticsTab).toBeEnabled();
    await diagnosticsTab.click();

    await expect(diagnosticsTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();

    const drawerWidth = await page.locator('.session-diagnostics-drawer').evaluate(
        element => element.getBoundingClientRect().width,
    );
    expect(drawerWidth).toBeGreaterThanOrEqual(420);
    expect(drawerWidth).toBeLessThanOrEqual(720);
    for (const selector of [
        '#sessionDiagnosticsCpuMetric',
        '#sessionDiagnosticsMemoryMetric',
        '#sessionDiagnosticsDiskMetric',
        '#sessionDiagnosticsLoadMetric',
    ]) {
        await expect(page.locator(selector)).toBeVisible();
    }
    await expect(page.locator('#sessionDiagnosticsPressureChart')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsNetworkChart')).toBeVisible({ timeout: 6000 });
    await expect(page.locator('#sessionDiagnosticsProcessesSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsCpuProcesses')).toContainText('postgres');
    await expect(page.locator('#sessionDiagnosticsMemoryProcesses')).toContainText('redis-server');
    await expect(page.locator('.session-process-percent .session-diagnostics-bar > span')).toHaveCount(3);
    await expect(page.locator('#sessionDiagnosticsSystemdSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsSystemdServices tr')).toHaveCount(3);
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('nginx.service');
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('backup.service');
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('cleanup.service');
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsDockerContainers tr')).toHaveCount(2);
    await expect(page.locator('#sessionDiagnosticsDockerContainers')).toContainText('webssh');
    await expect(page.locator('#sessionDiagnosticsDockerContainers')).toContainText('worker');

    const screenshotPath = capturePath(testInfo, 'session-diagnostics.png');
    await page.screenshot({
        path: screenshotPath,
        animations: 'disabled',
        caret: 'hide',
    });
    expect(pngSize(screenshotPath)).toEqual({ width: 2560, height: 1440 });

    const services = page.locator('#sessionDiagnosticsSystemdServices tr');
    const search = page.locator('#sessionDiagnosticsSystemdSearch');
    await search.fill('backup');
    await expect(services).toHaveCount(1);
    await expect(services).toContainText('backup.service');
    await search.fill('');
    await page.locator('[data-systemd-filter="failed"]').click();
    await expect(services).toHaveCount(1);
    await expect(services).toContainText('backup.service');
    await page.locator('[data-systemd-filter="inactive"]').click();
    await expect(services).toHaveCount(1);
    await expect(services).toContainText('cleanup.service');
    await page.locator('[data-systemd-filter="all"]').click();
    await expect(services).toHaveCount(3);

    const backupRow = services.filter({ hasText: 'backup.service' });
    await backupRow.getByRole('button', { name: 'Restart for backup.service' }).click();
    await expect.poll(() => page.evaluate(() => window.__workspaceClipboard)).toBe(
        'sudo systemctl restart -- backup.service',
    );
    await expect(page.locator('#sessionDiagnosticsClipboardFeedback')).toHaveText(
        'Command copied: Restart backup.service',
    );
    const clipboardNotification = page.locator('.notification-success').filter({
        hasText: 'Command copied to clipboard',
    });
    await expect(clipboardNotification).toBeVisible();
    await expect.poll(() => clipboardNotification.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const topmost = document.elementFromPoint(
            bounds.left + (bounds.width / 2),
            bounds.top + (bounds.height / 2),
        );
        return topmost === element || element.contains(topmost);
    }), { timeout: 1500 }).toBe(true);
    expect(await page.evaluate(() => window.__workspaceEvents.filter(({ event }) => (
        event !== 'request_session_runtime_inventory'
        && /systemd|service.*(start|stop|restart)/i.test(event)
    )))).toEqual([]);

    await expect.poll(() => page.evaluate(() => window.__workspaceChartSamples?.pressure || 0), {
        timeout: 6000,
    }).toBeGreaterThan(2);
    const preservedHistory = await page.evaluate(() => window.__workspaceChartSamples.pressure);
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await expect(diagnosticsTab).toHaveAttribute('aria-selected', 'false');
    await page.locator('#contextWorkspaceLauncher').click();
    await diagnosticsTab.click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect.poll(() => page.evaluate(() => window.__workspaceChartSamples?.pressure || 0)).toBeGreaterThanOrEqual(
        preservedHistory,
    );

    const beforeRefresh = await page.evaluate(() => window.__workspaceInventoryRequests);
    await page.evaluate(() => { window.__workspaceInventoryMode = 'generic'; });
    await page.locator('#sessionDiagnosticsRefresh').click();
    await expect.poll(() => page.evaluate(() => window.__workspaceInventoryRequests)).toBe(beforeRefresh + 1);
    await expect(page.locator('#sessionDiagnosticsState')).toHaveText('Live');
    await expect(page.locator('#sessionDiagnosticsLastUpdated')).toContainText('Inventory stale');
    await expect(page.locator('#sessionDiagnosticsSystemdServices tr')).toHaveCount(3);
    await expect(page.locator('#sessionDiagnosticsDockerContainers tr')).toHaveCount(2);

    await page.evaluate(() => { window.__workspaceInventoryMode = 'permission'; });
    await page.locator('#sessionDiagnosticsRefresh').click();
    await expect(page.locator('#sessionDiagnosticsPermissions')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsPermissionList')).toContainText(
        'systemd service details are restricted',
    );
    await expect(page.locator('#sessionDiagnosticsSystemdSection')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeVisible();

    await page.evaluate(() => SessionManager.removeSessionUI('workspace-linux'));
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await page.evaluate(() => {
        window.__workspaceInventoryMode = 'full';
        window.__createWorkspaceSession();
    });
    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect.poll(() => page.evaluate(limit => {
        const samples = window.__workspaceChartSamples?.pressure;
        return Number.isInteger(samples) && samples > 0 && samples < limit;
    }, preservedHistory)).toBe(true);
    await assertNoExternalRequests(page);
});

test('diagnostics charts keep stable dimensions across primary workspace navigation', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsNetworkChart')).toBeVisible({ timeout: 6000 });

    const canvases = page.locator([
        '#sessionDiagnosticsCpuSparkline',
        '#sessionDiagnosticsMemorySparkline',
        '#sessionDiagnosticsDiskSparkline',
        '#sessionDiagnosticsLoadSparkline',
        '#sessionDiagnosticsPressureChart',
        '#sessionDiagnosticsNetworkChart',
    ].join(', '));
    const dimensions = () => canvases.evaluateAll(elements => elements.map(canvas => ({
        clientWidth: canvas.clientWidth,
        clientHeight: canvas.clientHeight,
        width: canvas.width,
        height: canvas.height,
        styleWidth: canvas.style.width,
        styleHeight: canvas.style.height,
    })));
    const initial = await dimensions();
    expect(initial).toHaveLength(6);
    expect(initial.every(({ clientWidth, clientHeight }) => clientWidth > 0 && clientHeight > 0)).toBe(true);
    expect(initial.every(({ styleWidth, styleHeight }) => !styleWidth && !styleHeight)).toBe(true);

    for (let iteration = 0; iteration < 4; iteration += 1) {
        await page.locator('#fileTransferBtn').click();
        await expect(page.locator('#sftpFileManager')).toBeVisible();
        await page.evaluate(() => new Promise(resolve => {
            window.dispatchEvent(new Event('themeChanged'));
            requestAnimationFrame(() => requestAnimationFrame(resolve));
        }));
        await page.locator('#workspaceNavBtn').click();
        await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
        await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
    }

    expect(await dimensions()).toEqual(initial);
    await assertNoExternalRequests(page);
});

test('compact breakpoints close diagnostics until the user reopens session tools', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect.poll(() => page.evaluate(() => window.__workspaceExpandedRequests || 0), {
        timeout: 6000,
    }).toBeGreaterThan(0);

    const beforeResize = await page.evaluate(() => window.__workspaceExpandedRequests);
    await page.setViewportSize({ width: 800, height: 900 });
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();

    await page.locator('#contextWorkspaceLauncher').click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect.poll(() => page.evaluate(() => window.__workspaceExpandedRequests), {
        timeout: 6000,
    }).toBeGreaterThan(beforeResize);
    await expect(page.locator('#sessionDiagnosticsState')).toHaveText('Live');
    await assertNoExternalRequests(page);
});
