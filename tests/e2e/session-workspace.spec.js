const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('playwright/test');
const { openWorkspace, login, assertNoExternalRequests } = require('./helpers');
const { captureOutputPath } = require('./capture-output');

test.use({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 4 / 3,
});

function captureAssetsEnabled() {
    return process.env.WEBSSH_CAPTURE_ASSETS === '1';
}

function capturePath(filename) {
    return captureOutputPath(filename);
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
        window.__workspaceDirectory = {
            path: '/srv/webssh/current', shell_ready: true, shell_id: '42', shell: 'bash',
            tmux: seedOptions.useTmux === true,
            bracketed_paste: seedOptions.legacyTmux ? undefined : seedOptions.useTmux === true,
        };
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
                window.__workspacePressureSeries = series;
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
                if (seedOptions.directorySync && event === 'request_session_directory') {
                    const acknowledge = rest.find(value => typeof value === 'function');
                    queueMicrotask(() => acknowledge({success: true, directory: {...window.__workspaceDirectory}}));
                    return window.socket;
                }
                if (seedOptions.directorySync && event === 'ssh_input') {
                    const match = /^cd -- '([^']+)'\r$/.exec(payload.data);
                    if (match) window.__workspaceDirectory.path = match[1];
                    return window.socket;
                }
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
                        cpu: cpuSamples[Math.min(insightSample - 1, cpuSamples.length - 1)].map(
                            (value, index) => value + Math.max(0, insightSample - cpuSamples.length) * [60, 0, 30, 110][index],
                        ),
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
                            load: seedOptions.highLoad
                                ? { one: 4, five: 3, fifteen: 2, cpu_count: 3 }
                                : { one: 1.25, five: 0.75, fifteen: 0.5, cpu_count: 8 },
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
                    if (seedOptions.diskOnlyMetrics) {
                        Object.keys(stats).forEach(key => delete stats[key]);
                        const percent = insightSample === 1 ? 20 : 80;
                        stats.disk = {
                            total_kib: 100 * 1024 * 1024,
                            used_kib: percent * 1024 * 1024,
                            available_kib: (100 - percent) * 1024 * 1024,
                            percent,
                        };
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
            return originalEmit(...arguments);
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
            if (seedOptions.initialLiveOutput) {
                TerminalManager.writeOutput('workspace-linux', seedOptions.initialLiveOutput);
            }
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
        if (!seedOptions.initialLiveOutput) setTimeout(() => {
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

for (const legacyTmux of [false, true]) {
test(`first tmux folder double-click accepts the prompt buffered during attachment (${legacyTmux ? 'legacy' : 'pane mode'})`, async ({page}) => {
    await login(page);
    await seedLinuxSession(page, {
        useTmux: true, directorySync: true, legacyTmux,
        // Captured startup sequence from tmux 3.4: paste mode is enabled
        // before device-attribute and foreground/background colour queries.
        initialLiveOutput: '\x1b[?1049h\x1b[?2004h\x1b[c\x1b[>c\x1b[>q'
            + '\x1b]10;?\x1b\\\x1b]11;?\x1b\\ops@edge:~$ ',
    });
    // Exercise initial buffering and its write callback, without injecting a
    // second prompt after attachment to repair readiness for the test.
    await expect.poll(() => page.evaluate(() => {
        const key = TerminalManager.sessionTerminals['workspace-linux'][0];
        return TerminalManager.terminals[key].buffer.active.getLine(0)?.translateToString(true);
    })).toContain('ops@edge:~$');
    await page.locator('#contextFilesTab').click();
    await expect(page.locator('#sessionDirectorySyncInput')).toBeChecked();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await page.locator('#fmLeftList .fm-file-item').filter({hasText: 'releases'}).dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases');
    const sent = await page.evaluate(() => window.__workspaceEvents.filter(event => event.event === 'ssh_input'));
    expect(sent.filter(event => event.payload.data.startsWith('cd -- ')).map(event => event.payload)).toEqual([
        {session_id: 'workspace-linux', data: "cd -- '/srv/webssh/current/releases'\r"},
    ]);
    expect(sent.some(event => /^\x1b\]1[01];rgb:/.test(event.payload.data))).toBe(true);
    await expect(page.locator('.notification').filter({hasText: 'Folder sync paused'})).toHaveCount(0);
    await assertNoExternalRequests(page);
});

test(`tmux folder double-clicks synchronize repeatedly (${legacyTmux ? 'legacy' : 'pane mode'})`, async ({page}) => {
    await login(page);
    await seedLinuxSession(page, {useTmux: true, directorySync: true, legacyTmux});
    await page.locator('#contextFilesTab').click();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await page.evaluate(() => new Promise(resolve => {
        const key = TerminalManager.sessionTerminals['workspace-linux'][0];
        // Captured tmux behavior: alternate outer screen, one prompt enable;
        // short subsequent commands do not produce another DEC 2004 transition.
        TerminalManager.terminals[key].write('\x1b[?1049h\x1b[?2004hops@edge:~$ ', resolve);
    }));
    await expect(page.locator('#sessionDirectorySyncInput')).toBeChecked();
    const folder = page.locator('#fmLeftList .fm-file-item').filter({hasText: 'releases'});
    await folder.dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases');
    await folder.dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases/releases');
    const sent = await page.evaluate(() => window.__workspaceEvents.filter(event => event.event === 'ssh_input'));
    expect(sent.map(event => event.payload)).toEqual([
        {session_id: 'workspace-linux', data: "cd -- '/srv/webssh/current/releases'\r"},
        {session_id: 'workspace-linux', data: "cd -- '/srv/webssh/current/releases/releases'\r"},
    ]);
    await page.evaluate(() => window.SessionDirectorySync.noteInput('workspace-linux', 'unfinished'));
    await folder.dblclick();
    await expect(page.locator('.notification').filter({hasText: 'Folder sync paused'})).toBeVisible();
    expect(await page.evaluate(() => window.__workspaceEvents.filter(event => event.event === 'ssh_input').length)).toBe(2);
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases/releases');
    await assertNoExternalRequests(page);
});
}

test('tmux folder clicks recover after manual commands and Ctrl+C without outer prompt signals', async ({page}) => {
    await login(page);
    await seedLinuxSession(page, {useTmux: true, directorySync: true});
    await page.locator('#contextFilesTab').click();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await page.evaluate(() => new Promise(resolve => {
        const key = TerminalManager.sessionTerminals['workspace-linux'][0];
        TerminalManager.terminals[key].write('\x1b[?1049h\x1b[?2004hops@edge:~$ ', resolve);
    }));
    await page.evaluate(async () => {
        const key = TerminalManager.sessionTerminals['workspace-linux'][0];
        await SSHInput.send('workspace-linux', 'cd /srv/manual');
        await SSHInput.send('workspace-linux', '\r');
        window.__workspaceDirectory.path = '/srv/manual';
        // Real tmux redraws short commands with CR/LF but no DEC 2004 toggle.
        await new Promise(resolve => TerminalManager.terminals[key].write(
            'cd /srv/manual\r\nops@edge:/srv/manual$ ', resolve));
    });
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/manual');
    const folder = page.locator('#fmLeftList .fm-file-item').filter({hasText: 'releases'});
    await folder.dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/manual/releases');

    await page.evaluate(() => SSHInput.send('workspace-linux', 'echo unfinished'));
    await folder.dblclick();
    await expect(page.locator('.notification').filter({hasText: 'Folder sync paused'})).toBeVisible();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/manual/releases');
    await page.evaluate(async () => {
        const key = TerminalManager.sessionTerminals['workspace-linux'][0];
        await SSHInput.send('workspace-linux', '\x03');
        await new Promise(resolve => TerminalManager.terminals[key].write(
            '^C\r\nops@edge:/srv/manual/releases$ ', resolve));
        // Bash can be the foreground process while its prompt hook still runs.
        window.__workspaceDirectory.bracketed_paste = false;
    });
    await folder.dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/manual/releases');
    expect(await page.evaluate(() => window.__workspaceEvents.filter(event =>
        event.event === 'ssh_input' && event.payload.data.startsWith('cd -- ')).length)).toBe(1);
    await page.evaluate(() => { window.__workspaceDirectory.bracketed_paste = true; });
    await folder.dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/manual/releases/releases');
    expect(await page.evaluate(() => window.__workspaceEvents.filter(event =>
        event.event === 'ssh_input' && event.payload.data.startsWith('cd -- ')).length)).toBe(2);
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

test('Android IME input-before-keydown rollover is forwarded exactly once', async ({ page }) => {
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

        for (const character of '12345') {
            textarea.value += character;
            textarea.setSelectionRange(textarea.value.length, textarea.value.length);
            textarea.dispatchEvent(new InputEvent('input', {
                bubbles: true,
                composed: true,
                data: character,
                inputType: 'insertText',
            }));
            const keydown = new KeyboardEvent('keydown', {
                bubbles: true,
                cancelable: true,
                key: 'Unidentified',
            });
            Object.defineProperty(keydown, 'keyCode', {value: 229});
            textarea.dispatchEvent(keydown);
            const keyup = new KeyboardEvent('keyup', {
                bubbles: true,
                key: character,
            });
            Object.defineProperty(keyup, 'keyCode', {
                value: character.charCodeAt(0),
            });
            textarea.dispatchEvent(keyup);
        }
    });

    await expect.poll(() => page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .map(event => event.payload.data)
        .join(''))).toBe('12345');
    await page.waitForTimeout(50);
    expect(await page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .map(event => event.payload.data)
        .join(''))).toBe('12345');
    await page.evaluate(() => window.__androidCompositionDispose());
    await assertNoExternalRequests(page);
});

test('tmux resync ignores replayed OSC 52 and accepts a live clipboard selection', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, {
        useTmux: true,
    });
    await expect.poll(() => page.evaluate(() => (
        TerminalManager.getTranscript('workspace-linux')
    ))).toContain('Production Edge');

    const tabCount = await page.locator('.session-tab').count();
    await page.evaluate(() => {
        window.__workspaceClipboard = null;
        SessionManager.restoreSession({
            session_id: 'workspace-linux',
            buffered_output: [
                '\u001b]52;;c3RhbGUgdG11eCBzZWxlY3Rpb24=\u0007',
                'resynced tmux session',
                'ops@edge-01:~$ ',
            ].join('\r\n'),
            output_sequence: 2,
        });
    });

    await expect.poll(() => page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const buffer = TerminalManager.terminals[terminalKey].buffer.active;
        return Array.from({length: buffer.length}, (_unused, index) => (
            buffer.getLine(index)?.translateToString(true) || ''
        )).join('\n');
    })).toContain('resynced tmux session');
    await expect(page.locator('.session-tab')).toHaveCount(tabCount);

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

test('clipboard fallback preserves terminal focus and subsequent input', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await page.evaluate(() => {
        Object.defineProperty(navigator, 'clipboard', {configurable: true, value: undefined});
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const terminal = TerminalManager.terminals[terminalKey];
        terminal.focus();
        terminal.selectAll();
        window.__workspaceEvents = [];
        window.__fallbackCopyCalls = 0;
        document.execCommand = command => {
            if (command === 'copy') window.__fallbackCopyCalls += 1;
            return command === 'copy';
        };
    });

    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+c' : 'Control+c');
    expect(await page.evaluate(() => window.__fallbackCopyCalls)).toBe(1);
    await expect(page.locator('.terminal-pane.active .xterm-helper-textarea')).toBeFocused();
    await page.keyboard.type('ls');
    await expect.poll(() => page.evaluate(() => window.__workspaceEvents
        .filter(event => event.event === 'ssh_input')
        .map(event => event.payload.data)
        .join(''))).toBe('ls');
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
        const toolbar = document.querySelector('.fm-embedded-mode .fm-toolbar');
        const toolbarBounds = bounds(toolbar);
        const toolbarButtons = Array.from(toolbar.querySelectorAll('button'))
            .filter(button => bounds(button).width > 0 && bounds(button).height > 0);
        const fileRows = Array.from(document.querySelectorAll(
            '.fm-embedded-mode #fmLeftList .fm-file-item',
        ));
        const xterm = document.querySelector('.terminal-pane.active .xterm');
        const viewport = document.querySelector('.terminal-pane.active .xterm-viewport');
        const themeProbe = document.createElement('span');
        themeProbe.style.backgroundColor = 'color-mix(in srgb, var(--term-background) 100%, transparent)';
        document.body.appendChild(themeProbe);
        const terminalBackground = getComputedStyle(themeProbe).backgroundColor;
        themeProbe.remove();
        return {
            maxRowHeight: Math.max(...fileRows.map(row => bounds(row).height)),
            toolbarOverflow: toolbar.scrollWidth - toolbar.clientWidth,
            toolbarRows: new Set(toolbarButtons
                .map(button => Math.round(bounds(button).top))).size,
            toolbarButtonsInside: toolbarButtons.every(button => {
                const buttonBounds = bounds(button);
                return buttonBounds.left >= toolbarBounds.left
                    && buttonBounds.right <= toolbarBounds.right + 1;
            }),
            xtermPadding: getComputedStyle(xterm).padding,
            viewportBackground: getComputedStyle(viewport).backgroundColor,
            paneBackground: getComputedStyle(xterm.closest('.terminal-pane')).backgroundColor,
            terminalBackground,
        };
    });
    expect(embeddedFileLayout.maxRowHeight).toBeLessThanOrEqual(46);
    expect(embeddedFileLayout.toolbarOverflow).toBeLessThanOrEqual(1);
    expect(embeddedFileLayout.toolbarRows).toBe(1);
    expect(embeddedFileLayout.toolbarButtonsInside).toBe(true);
    expect(embeddedFileLayout.xtermPadding).toBe('0px');
    expect(embeddedFileLayout.viewportBackground).toBe('rgba(0, 0, 0, 0)');
    expect(embeddedFileLayout.paneBackground).toBe(embeddedFileLayout.terminalBackground);

    const directorySync = page.locator('#sessionDirectorySyncInput');
    await expect(directorySync).toBeChecked();
    await directorySync.uncheck();
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

    if (captureAssetsEnabled()) {
        const screenshotPath = capturePath('session-workspace.png');
        await page.screenshot({
            path: screenshotPath,
            animations: 'disabled',
            caret: 'hide',
        });
        expect(pngSize(screenshotPath)).toEqual({ width: 2560, height: 1440 });
    }

    const commandsTab = page.locator('#contextCommandsTab');
    await expect(commandsTab).toBeEnabled();
    await commandsTab.click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await expect(page.locator('.session-command-search')).toBeFocused();
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
    await expect(page.locator('.session-command-item')).not.toHaveCount(0);
    if (captureAssetsEnabled()) {
        const commandsScreenshotPath = capturePath('session-commands-context.png');
        await page.screenshot({
            path: commandsScreenshotPath,
            animations: 'disabled',
            caret: 'hide',
        });
        expect(pngSize(commandsScreenshotPath)).toEqual({ width: 2560, height: 1440 });
    }
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

test('360px mobile workspace keeps tools available and preserves context across live resizes', async ({ page, browserName }, testInfo) => {
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
    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();
    await expect(page.locator('#mobileAppDock')).toBeVisible();
    await expect(page.locator('#mobileCommandToggle')).toBeVisible();
    await expect(page.locator('.split-controls')).toBeHidden();

    const terminalDock = page.locator('[data-mobile-view="workspaces"]');
    const sftpDock = page.locator('#contextFilesTab');
    const commandsDock = page.locator('#contextCommandsTab');
    const metricsDock = page.locator('#contextDiagnosticsTab');
    await expect(terminalDock).toContainText('Terminal');
    await expect(sftpDock).toContainText('Files');
    await expect(commandsDock).toContainText('Commands');
    await expect(metricsDock).toContainText('Diagnostics');
    await expect(sftpDock).toBeEnabled();
    await expect(commandsDock).toBeEnabled();
    await expect(metricsDock).toBeEnabled();

    await page.locator('#contextWorkspaceLauncher').click();
    await sftpDock.click();
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(sftpDock).toHaveAttribute('aria-selected', 'true');

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

    await page.locator('#mobileMoreBtn').click();
    await expect(page.locator('#headerButtons')).toHaveClass(/is-open/);
    await page.keyboard.press('Escape');
    await expect(page.locator('#headerButtons')).not.toHaveClass(/is-open/);
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );
    await expect(embeddedFile).toHaveClass(/selected/);

    await page.locator('#newTabBtn').click();
    const mobileLauncher = page.locator('.terminal-pane.active .profile-launcher');
    await expect(mobileLauncher).toBeVisible();
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(page.locator('#mobileCommandToggle')).toBeDisabled();
    await expect(page.locator('[data-mobile-view="commands"]')).toBeEnabled();
    expect(await page.evaluate(() => ({
        interactive: SessionManager.getActiveSession(),
        workspace: SessionManager.getWorkspaceSession(),
        path: window.sftpFileManager.panes.left.path,
        selected: Array.from(window.sftpFileManager.panes.left.selected),
    }))).toEqual({
        interactive: null,
        workspace: 'workspace-linux',
        path: '/srv/webssh/current',
        selected: [1],
    });
    await mobileLauncher.locator('.profile-launcher-return').click();
    await expect(page.locator('.terminal-pane.active .xterm')).toBeVisible();
    await page.locator('#contextWorkspaceLauncher').click();
    await sftpDock.click();
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );
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

    if (browserName === 'chromium') {
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
    } else {
        // CDP touch injection is Chromium-only. Other engines exercise native
        // scrolling in the same compact layout; device swipe QA is separate.
        await embeddedList.hover();
        await page.mouse.wheel(0, 160);
    }
    await expect.poll(() => embeddedList.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
    expect(embeddedScrollLayout.panelDisplay).toBe('flex');
    expect(embeddedScrollLayout.mountHeight).toBeLessThanOrEqual(
        embeddedScrollLayout.panelHeight,
    );

    await metricsDock.click();
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(metricsDock).toHaveAttribute('aria-selected', 'true');
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
    await page.locator('#contextWorkspaceLauncher').click();
    await commandsDock.click();
    await expect(page.locator('#sessionCommandsPanel')).toBeVisible();
    await expect(commandsDock).toHaveAttribute('aria-selected', 'true');
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
    if (captureAssetsEnabled()) {
        await page.screenshot({
            path: capturePath('session-mobile-commands-context.png'),
            animations: 'disabled',
            caret: 'hide',
        });
    }

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

for (const width of [360, 1920]) {
    test(`command management stays compact without session actions at ${width}px`, async ({ page }, testInfo) => {
        await page.setViewportSize({ width, height: width === 360 ? 640 : 1080 });
        await login(page);
        await seedLinuxSession(page);
        await page.evaluate(() => window.CommandLibrary.openLibrary());
        const panel = page.locator('#commandLibraryPanel');
        await expect(panel).toBeVisible();
        await expect(panel.locator('#commandWorkspaceTarget, .cmd-execute')).toHaveCount(0);
        await expect(panel.getByRole('button', { name: 'Open connections', exact: true })).toHaveCount(0);
        const geometry = await page.evaluate(() => ({
            panelWidth: document.getElementById('commandLibraryPanel').getBoundingClientRect().width,
            bodyWidth: document.querySelector('.command-workspace-body').getBoundingClientRect().width,
            pageWidth: document.documentElement.scrollWidth,
        }));
        expect(geometry.panelWidth).toBeGreaterThan(geometry.bodyWidth * 0.85);
        expect(geometry.panelWidth).toBeLessThanOrEqual(geometry.bodyWidth + 1);
        expect(geometry.pageWidth).toBeLessThanOrEqual(width);
        if (captureAssetsEnabled()) {
            await page.screenshot({ path: capturePath(`commands-${width}.png`) });
        }
        if (width === 360) {
            await page.evaluate(() => {
                const original = window.CommandLibrary.commands[0];
                window.CommandLibrary.setCommands(Array.from({ length: 95 }, (_, index) => ({
                    ...original, id: `scroll-${index}`, name: `Command ${index}`,
                })));
            });
            for (let chunk = 0; chunk < 3; chunk++) {
                await panel.locator('.command-row').last().scrollIntoViewIfNeeded();
            }
            await expect(panel.locator('.command-row')).toHaveCount(95);
            const action = panel.locator('.command-row').last().locator('button').first();
            await action.scrollIntoViewIfNeeded();
            await expect(action).toBeInViewport();
        }
    });
}

test('workspace tools resume after repeated transport interruptions', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    const files = page.locator('#sessionFilesMount');
    for (let cycle = 0; cycle < 3; cycle++) {
        await page.locator('#contextFilesTab').click();
        await expect(files).toBeVisible();
        await page.evaluate(() => window.socket.disconnect());
        await expect(files).toBeVisible();
        await expect(files.locator('.fm-file-item').first()).toBeVisible();
        await expect(files.locator('.fm-embedded-mode')).toHaveAttribute('inert', '');
        await expect(page.locator('#sessionFilesStatus')).toContainText('Reconnecting');
        await page.evaluate(() => { window.socket.connect(); });
        await expect.poll(() => page.evaluate(() => window.socket.connected)).toBe(true);
        await page.locator('#contextFilesTab').click();
        await expect(files).toBeVisible();
        await expect(files.locator('.fm-file-item').first()).toBeVisible();
        await expect(files.locator('.fm-embedded-mode')).not.toHaveAttribute('inert', '');
        await page.locator('#contextDiagnosticsTab').click();
        await expect(page.locator('#sessionDiagnosticsState')).toHaveText('Live');
        await page.evaluate(() => window.socket.disconnect());
        await expect(page.locator('#sessionDiagnosticsState')).toContainText('Reconnecting');
        await expect(page.locator('#sessionDiagnosticsRefresh')).toBeDisabled();
        await page.evaluate(() => { window.socket.connect(); });
        await expect(page.locator('#sessionDiagnosticsState')).toHaveText('Live');
        await page.locator('#contextCommandsTab').click();
        await expect(page.locator('#sessionCommandsPanel').getByRole('button', {name: 'Open connections', exact: true})).toHaveCount(0);
        const sudo = page.locator('.session-command-sudo-input');
        await sudo.check();
        await page.locator('#sessionCommandsPanel').getByRole('button', {name: 'Insert', exact: true}).first().click();
        const sent = await page.evaluate(() => window.__workspaceEvents.filter(item => item.event === 'ssh_input').at(-1)?.payload);
        expect(sent.session_id).toBe('workspace-linux');
        expect(sent.data).toMatch(/^sudo\s/);
        expect(sent.data).not.toMatch(/[\r\n]/);
    }
    await assertNoExternalRequests(page);
});

for (const reconnecting of [false, true]) {
test(`account settings navigation does not warn for an active SSH session (reconnecting: ${reconnecting})`, async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    if (reconnecting) await page.evaluate(() => window.socket.disconnect());
    const dialogs = [];
    page.on('dialog', async dialog => {
        dialogs.push(dialog.type());
        await dialog.accept();
    });
    await page.locator('#accountBtnHeader').click();
    if (reconnecting) await page.locator('#accountSettingsBtn').press('Enter');
    else await page.locator('#accountSettingsBtn').click();
    await expect(page).toHaveURL(/\/settings#preferences$/);
    expect(dialogs).toEqual([]);
});
}

test('host context shares the notes header without taking an editor column', async ({ page }, testInfo) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await seedLinuxSession(page);
    await page.locator('#contextNotesTab').click();
    for (const width of [1440, 1024]) {
        await page.setViewportSize({width, height: 900});
        const panel = page.locator('#contextNotesPanel');
        const notes = page.locator('#notepadPanel');
        await expect(notes).toBeVisible();
        await expect(notes.locator('.workspace-drawer-header #activeHostContextBtn')).toBeVisible();
        await expect.poll(async () => {
            const outer = await panel.boundingBox();
            const inner = await notes.boundingBox();
            return outer.width - inner.width;
        }).toBeLessThan(4);
    }
    await page.screenshot({path: testInfo.outputPath('notes-header.png')});
});

test('account settings navigation still protects unsaved notes', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await page.locator('#contextNotesTab').click();
    await page.evaluate(() => window.socket.disconnect());
    await page.locator('#sessionNotepad').fill('Unsaved offline note');
    const dialogPromise = page.waitForEvent('dialog').then(async dialog => {
        const type = dialog.type();
        await dialog.dismiss();
        return type;
    });
    await page.locator('#accountBtnHeader').click();
    await page.locator('#accountSettingsBtn').click();
    expect(await dialogPromise).toBe('beforeunload');
    await expect(page).toHaveURL(/\/$/);
    await expect(page.locator('#sessionNotepad')).toHaveValue('Unsaved offline note');
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
    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();
    await expect(page.locator('#mobileAppDock')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);

    await page.locator('#mobileMoreBtn').click();
    await page.locator('#mobileToolsAction').click();
    await expect(page.locator('#contextNotesPanel')).toBeVisible();
    await expect(page.locator('#contextWorkspaceClose')).toBeVisible();
    await page.locator('[data-mobile-view="workspaces"]').click();
    await expect(page.locator('#contextNotesPanel')).toBeHidden();
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
    await openWorkspace(page);

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
    await openWorkspace(page);

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
    await openWorkspace(page);
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
        const cards = visible('.session-diagnostics-metric-row');
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
            rowsStacked: getComputedStyle(grid).display === 'block' && cards.every((card, index) => index === 0
                || card.getBoundingClientRect().top >= cards[index - 1].getBoundingClientRect().bottom - 1),
            escapedDescendants,
            overflowingSurfaces,
        };
    });
    expect(diagnosticsGeometry).toEqual({
        documentContained: true,
        panelClipsOverflow: true,
        contentContained: true,
        rowsStacked: true,
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

test('connection launcher preserves the live session and Files context until replacement', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    const filesPanel = page.locator('#sessionFilesPanel');
    const selectedFile = filesPanel.locator('#fmLeftList .fm-file-item[data-index="1"]');
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await expect(filesPanel.locator('#fmLeftList .fm-file-item')).toHaveCount(5);
    await selectedFile.click();
    await expect(selectedFile).toHaveClass(/selected/);

    const requestCountsBefore = await page.evaluate(() => ({
        home: window.__workspaceEvents.filter(
            entry => entry.event === 'get_home_directory'
        ).length,
        list: window.__workspaceEvents.filter(
            entry => entry.event === 'list_directory'
        ).length,
    }));

    await page.evaluate(() => {
        ProfileManager.profilesLoaded = true;
        ProfileManager.profiles = [{
            id: 'saved-replacement',
            name: 'Staging gateway',
            host: 'staging.example',
            port: 22,
            username: 'deploy',
            auth_type: 'password',
        }];
    });

    await page.locator('#newTabBtn').click();

    const launcher = page.locator('.terminal-pane.active .profile-launcher');
    const returnButton = launcher.locator('.profile-launcher-return');
    await expect(launcher).toBeVisible();
    await expect(returnButton).toContainText('Production Edge');
    await expect(returnButton).toBeFocused();
    const launcherSearch = launcher.locator('.profile-launcher-search');
    await launcherSearch.click();
    await expect(launcherSearch).toBeFocused();
    await returnButton.focus();
    await page.keyboard.press('Control+f');
    await expect(launcherSearch).toBeFocused();
    await expect(page.locator('#terminalSearchBar')).toHaveClass(/hidden/);
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await expect(selectedFile).toHaveClass(/selected/);

    await selectedFile.click({ button: 'right' });
    await expect(page.locator('.fm-context-menu')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('.fm-context-menu')).toHaveCount(0);
    await expect(launcher).toBeVisible();
    await expect(filesPanel).toBeVisible();

    await page.keyboard.press('Control+k');
    await expect(page.locator('#commandPaletteModal')).toHaveClass(/show/);
    await page.keyboard.press('Escape');
    await expect(page.locator('#commandPaletteModal')).not.toHaveClass(/show/);
    await expect(launcher).toBeVisible();
    await expect(filesPanel).toBeVisible();

    expect(await page.evaluate(() => ({
        assignment: SessionManager.paneAssignments[0],
        activeSession: SessionManager.getActiveSession(),
        workspaceSession: SessionManager.getWorkspaceSession(),
        launcherOpen: SessionManager.isConnectionLauncherOpen(0),
        connected: SessionManager.getSession('workspace-linux')?.connected,
        filesMode: window.sftpFileManager?.displayMode,
        disconnects: window.__workspaceEvents.filter(
            entry => entry.event === 'ssh_disconnect'
        ).length,
    }))).toEqual({
        assignment: 'workspace-linux',
        activeSession: null,
        workspaceSession: 'workspace-linux',
        launcherOpen: true,
        connected: true,
        filesMode: 'embedded',
        disconnects: 0,
    });

    await launcher.locator('.profile-launcher-new').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect(launcher).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await expect(selectedFile).toHaveClass(/selected/);

    await page.evaluate(() => {
        TerminalManager.writeOutput(
            'workspace-linux',
            '\r\noutput received while choosing a connection\r\n',
        );
    });
    await page.keyboard.press('Escape');

    await expect(launcher).toHaveCount(0);
    await expect(page.locator('.terminal-pane.active .xterm')).toBeVisible();
    await expect.poll(() => page.evaluate(() => {
        const terminalKey = TerminalManager.sessionTerminals['workspace-linux'][0];
        const buffer = TerminalManager.terminals[terminalKey].buffer.active;
        return Array.from({ length: buffer.length }, (_entry, index) => (
            buffer.getLine(index)?.translateToString(true) || ''
        )).join('\n');
    })).toContain('output received while choosing a connection');
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await expect(selectedFile).toHaveClass(/selected/);

    expect(await page.evaluate(() => ({
        home: window.__workspaceEvents.filter(
            entry => entry.event === 'get_home_directory'
        ).length,
        list: window.__workspaceEvents.filter(
            entry => entry.event === 'list_directory'
        ).length,
        disconnects: window.__workspaceEvents.filter(
            entry => entry.event === 'ssh_disconnect'
        ).length,
        launcherOpen: SessionManager.isConnectionLauncherOpen(0),
    }))).toEqual({
        ...requestCountsBefore,
        disconnects: 0,
        launcherOpen: false,
    });
    await assertNoExternalRequests(page);
});

test('pending saved-profile connection can be cancelled from its tab by keyboard', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await page.evaluate(() => {
        ProfileManager.keys = [{ id: 'direct-key', usable: true }];
        ProfileManager.profilesLoaded = true;
        ProfileManager.profiles = [{
            id: 'direct-cancel-profile',
            name: 'Direct staging host',
            host: 'direct.example',
            port: 22,
            username: 'deploy',
            auth_type: 'key',
            key_id: 'direct-key',
            startup_mode: 'none',
        }];
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__directConnectEvents = [];
        window.socket.emit = function holdDirectConnection(event, payload, ...rest) {
            if (event === 'ssh_connect' || event === 'ssh_connect_cancel') {
                window.__directConnectEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                if (event === 'ssh_connect_cancel') {
                    queueMicrotask(() => rest[0]?.({
                        success: true,
                        cancelled: true,
                    }));
                }
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
    });

    await page.locator('#newTabBtn').click();
    await page.locator('[data-profile-id="direct-cancel-profile"]').click();
    await expect.poll(() => page.evaluate(() => (
        window.__directConnectEvents.filter(entry => entry.event === 'ssh_connect').length
    ))).toBe(1);

    const requestId = await page.evaluate(() => (
        window.__directConnectEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));
    const pendingTab = page.locator(`[data-pending-id="${requestId}"]`).first();
    const cancelButton = pendingTab.getByRole('button', { name: 'Cancel connection' });
    await expect(cancelButton).toHaveAttribute('type', 'button');
    await cancelButton.focus();
    await cancelButton.press('Enter');

    await expect(pendingTab).toHaveCount(0);
    await expect(
        page.locator('.terminal-pane.active .xterm-helper-textarea')
    ).toBeFocused();
    await expect.poll(() => page.evaluate(() => (
        window.__directConnectEvents.filter(entry => entry.event === 'ssh_connect_cancel')
    ))).toEqual([{
        event: 'ssh_connect_cancel',
        payload: { client_request_id: requestId },
    }]);
    expect(await page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        workspace: SessionManager.getWorkspaceSession(),
        connected: SessionManager.getSession('workspace-linux')?.connected,
        disconnects: window.__workspaceEvents.filter(
            entry => entry.event === 'ssh_disconnect'
        ).length,
    }))).toEqual({
        active: 'workspace-linux',
        workspace: 'workspace-linux',
        connected: true,
        disconnects: 0,
    });
    await assertNoExternalRequests(page);
});

test('pending connection cancellation returns focus to an empty pane launcher', async ({ page }) => {
    await login(page);
    await expect.poll(() => page.evaluate(() => (
        ProfileManager.keys.some(key => key.usable === true)
    ))).toBe(true);

    await page.evaluate(() => {
        const keyId = ProfileManager.keys.find(key => key.usable === true).id;
        ProfileManager.profilesLoaded = true;
        ProfileManager.profiles = [{
            id: 'empty-pane-profile',
            name: 'Empty pane host',
            host: 'empty.example',
            port: 22,
            username: 'deploy',
            auth_type: 'key',
            key_id: keyId,
            startup_mode: 'none',
        }];
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__emptyPaneConnectEvents = [];
        window.socket.emit = function holdEmptyPaneConnection(event, payload, ...rest) {
            if (event === 'ssh_connect' || event === 'ssh_connect_cancel') {
                window.__emptyPaneConnectEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                if (event === 'ssh_connect_cancel') {
                    queueMicrotask(() => rest[0]?.({
                        success: true,
                        cancelled: true,
                    }));
                }
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
        SessionManager.renderPane(SessionManager.getActivePaneIndex());
    });

    await page.locator('[data-profile-id="empty-pane-profile"]').click();
    await expect.poll(() => page.evaluate(() => (
        window.__emptyPaneConnectEvents.find(entry => entry.event === 'ssh_connect')
            ?.payload.client_request_id
    ))).toBeTruthy();
    const requestId = await page.evaluate(() => (
        window.__emptyPaneConnectEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));
    const cancelButton = page.locator(
        `[data-pending-id="${requestId}"] [aria-label="Cancel connection"]`
    );
    await cancelButton.focus();
    await cancelButton.press('Enter');

    await expect(page.locator(`[data-pending-id="${requestId}"]`)).toHaveCount(0);
    await expect(
        page.locator('.terminal-pane.active .profile-launcher-search')
    ).toBeFocused();
    await expect.poll(() => page.evaluate(expectedRequestId => (
        window.__emptyPaneConnectEvents.some(
            entry => entry.event === 'ssh_connect_cancel'
                && entry.payload.client_request_id === expectedRequestId
        )
    ), requestId)).toBe(true);
    await assertNoExternalRequests(page);
});

test('a late cancellation keeps and opens the already committed connection', async ({ page }) => {
    await login(page);
    await expect.poll(() => page.evaluate(() => (
        ProfileManager.keys.some(key => key.usable === true)
    ))).toBe(true);

    await page.evaluate(() => {
        const keyId = ProfileManager.keys.find(key => key.usable === true).id;
        ProfileManager.profilesLoaded = true;
        ProfileManager.profiles = [{
            id: 'committed-profile',
            name: 'Committed host',
            host: 'committed.example',
            port: 22,
            username: 'deploy',
            auth_type: 'key',
            key_id: keyId,
            startup_mode: 'none',
        }];
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__committedConnectEvents = [];
        window.socket.emit = function holdCommittedConnection(event, payload, ...rest) {
            if (event === 'ssh_connect') {
                window.__committedConnectEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                return window.socket;
            }
            if (event === 'ssh_connect_cancel') {
                window.__committedConnectEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                queueMicrotask(() => rest[0]?.({
                    success: false,
                    cancelled: false,
                    reason: 'already_committed',
                }));
                return window.socket;
            }
            if (event === 'ssh_discard_late_connection') {
                window.__committedConnectEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
        SessionManager.renderPane(SessionManager.getActivePaneIndex());
    });

    await page.locator('[data-profile-id="committed-profile"]').click();
    await expect.poll(() => page.evaluate(() => (
        window.__committedConnectEvents.find(entry => entry.event === 'ssh_connect')
            ?.payload.client_request_id
    ))).toBeTruthy();
    const requestId = await page.evaluate(() => (
        window.__committedConnectEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));
    const pendingTab = page.locator(`[data-pending-id="${requestId}"]`).first();
    await pendingTab.getByRole('button', { name: 'Cancel connection' }).click();

    await expect(pendingTab).toBeVisible();
    await expect(page.locator('.notification')).toContainText(
        'can no longer be cancelled safely',
    );

    await page.evaluate(activeRequestId => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: 'committed-session',
            host: 'committed.example',
            port: 22,
            username: 'deploy',
            client_request_id: activeRequestId,
        }));
    }, requestId);

    await expect(pendingTab).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('committed-session');
    expect(await page.evaluate(() => window.__committedConnectEvents.filter(
        entry => entry.event === 'ssh_discard_late_connection'
    ))).toEqual([]);
    await assertNoExternalRequests(page);
});

test('a completed connection explains a cancellation acknowledgement that arrives later', async ({ page }) => {
    await login(page);
    await expect.poll(() => page.evaluate(() => (
        ProfileManager.keys.some(key => key.usable === true)
    ))).toBe(true);

    await page.evaluate(() => {
        const keyId = ProfileManager.keys.find(key => key.usable === true).id;
        ProfileManager.profilesLoaded = true;
        ProfileManager.profiles = [{
            id: 'completion-race-profile',
            name: 'Completion race host',
            host: 'completion-race.example',
            port: 22,
            username: 'deploy',
            auth_type: 'key',
            key_id: keyId,
            startup_mode: 'none',
        }];
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__completionRaceEvents = [];
        window.__completionRaceCancelAcknowledgement = null;
        window.socket.emit = function holdCompletionRace(event, payload, ...rest) {
            if (
                event === 'ssh_connect'
                || event === 'ssh_connect_cancel'
                || event === 'ssh_discard_late_connection'
            ) {
                window.__completionRaceEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                if (event === 'ssh_connect_cancel') {
                    window.__completionRaceCancelAcknowledgement = rest[0];
                }
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
        SessionManager.renderPane(SessionManager.getActivePaneIndex());
    });

    await page.locator('[data-profile-id="completion-race-profile"]').click();
    await expect.poll(() => page.evaluate(() => (
        window.__completionRaceEvents.find(entry => entry.event === 'ssh_connect')
            ?.payload.client_request_id
    ))).toBeTruthy();
    const requestId = await page.evaluate(() => (
        window.__completionRaceEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));
    const pendingTab = page.locator(`[data-pending-id="${requestId}"]`).first();
    await pendingTab.getByRole('button', { name: 'Cancel connection' }).click();
    await expect.poll(() => page.evaluate(activeRequestId => ({
        cancelRequests: window.__completionRaceEvents.filter(entry => (
            entry.event === 'ssh_connect_cancel'
            && entry.payload.client_request_id === activeRequestId
        )).length,
        hasAcknowledgement: (
            typeof window.__completionRaceCancelAcknowledgement === 'function'
        ),
    }), requestId)).toEqual({
        cancelRequests: 1,
        hasAcknowledgement: true,
    });

    await page.evaluate(activeRequestId => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: 'completion-race-session',
            host: 'completion-race.example',
            port: 22,
            username: 'deploy',
            client_request_id: activeRequestId,
        }));
    }, requestId);

    await expect(pendingTab).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('completion-race-session');

    await page.evaluate(() => {
        const acknowledge = window.__completionRaceCancelAcknowledgement;
        window.__completionRaceCancelAcknowledgement = null;
        acknowledge({
            success: false,
            cancelled: false,
            reason: 'not_found',
        });
    });

    await expect(page.getByText(
        'Cancellation was too late. The connection had already opened and remains active.',
        { exact: true },
    )).toBeVisible();
    expect(await page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        connected: SessionManager.getSession('completion-race-session')?.connected,
        discards: window.__completionRaceEvents.filter(
            entry => entry.event === 'ssh_discard_late_connection'
        ),
    }))).toEqual({
        active: 'completion-race-session',
        connected: true,
        discards: [],
    });
    await assertNoExternalRequests(page);
});

test('a lost cancellation acknowledgement stays retryable and clears a finished request safely', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await page.evaluate(() => {
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__cancelRecoveryEvents = [];
        window.__cancelRecoveryResponse = 'drop';
        window.socket.emit = function holdCancellation(event, payload, ...rest) {
            if (
                event === 'ssh_connect'
                || event === 'ssh_connect_cancel'
                || event === 'ssh_discard_late_connection'
            ) {
                window.__cancelRecoveryEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                if (
                    event === 'ssh_connect_cancel'
                    && window.__cancelRecoveryResponse === 'not_found'
                ) {
                    queueMicrotask(() => rest[0]?.({
                        success: false,
                        cancelled: false,
                        reason: 'not_found',
                    }));
                }
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
    });

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('cancel-recovery.example');
    await page.locator('#usernameInput').fill('deploy');
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => (
        window.__cancelRecoveryEvents.find(entry => entry.event === 'ssh_connect')
            ?.payload.client_request_id
    ))).toBeTruthy();
    const requestId = await page.evaluate(() => (
        window.__cancelRecoveryEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));
    const pendingTab = page.locator(`[data-pending-id="${requestId}"]`).first();
    const pendingCancel = pendingTab.getByRole('button', { name: 'Cancel connection' });

    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');
    await expect(
        page.locator('.terminal-pane.active .xterm-helper-textarea')
    ).toBeFocused();
    await expect(pendingCancel).toHaveAttribute('aria-busy', 'true');

    await expect(page.getByText(
        'Cancellation was not confirmed. The attempt is still pending; try cancelling again.',
        { exact: true },
    )).toBeVisible({ timeout: 8000 });
    await expect(pendingCancel).toHaveAttribute('aria-busy', 'false');

    await page.evaluate(() => {
        window.__cancelRecoveryResponse = 'not_found';
    });
    await pendingCancel.click();
    await expect(pendingTab).toHaveCount(0);
    await expect(page.getByText(
        'The connection attempt is no longer active.',
        { exact: true },
    )).toBeVisible();

    await page.evaluate(activeRequestId => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: 'cancel-recovery-late-session',
            host: 'cancel-recovery.example',
            port: 22,
            username: 'deploy',
            client_request_id: activeRequestId,
        }));
    }, requestId);
    await expect.poll(() => page.evaluate(activeRequestId => (
        window.__cancelRecoveryEvents.some(entry => (
            entry.event === 'ssh_discard_late_connection'
            && entry.payload.client_request_id === activeRequestId
            && entry.payload.session_id === 'cancel-recovery-late-session'
        ))
    ), requestId)).toBe(true);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');

    await page.locator('#newTabBtn').click();
    await expect(page.locator('.terminal-pane.active .profile-launcher-new')).toBeVisible();
    await assertNoExternalRequests(page);
});

test('a failed late replacement leaves the preserved terminal active', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    await page.evaluate(() => {
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__lateReplacementEvents = [];
        window.socket.emit = function holdLateReplacement(event, payload, ...rest) {
            if (event === 'ssh_connect' || event === 'ssh_connect_cancel') {
                window.__lateReplacementEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                if (event === 'ssh_connect_cancel') {
                    queueMicrotask(() => rest[0]?.({
                        success: false,
                        cancelled: false,
                        reason: 'already_committed',
                    }));
                }
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
    });

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('late-replacement.example');
    await page.locator('#usernameInput').fill('deploy');
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => (
        window.__lateReplacementEvents.find(entry => entry.event === 'ssh_connect')
            ?.payload.client_request_id
    ))).toBeTruthy();
    const requestId = await page.evaluate(() => (
        window.__lateReplacementEvents.find(entry => entry.event === 'ssh_connect')
            .payload.client_request_id
    ));

    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');
    await expect(
        page.locator('.terminal-pane.active .xterm-helper-textarea')
    ).toBeFocused();
    await expect(page.locator('.notification')).toContainText(
        'can no longer be cancelled safely',
    );

    await page.evaluate(activeRequestId => {
        window.socket.listeners('ssh_error').forEach(listener => listener({
            error: 'Late replacement failed',
            client_request_id: activeRequestId,
        }));
    }, requestId);
    await expect(page.locator(`[data-pending-id="${requestId}"]`)).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');
    await expect(
        page.locator('.terminal-pane.active .xterm-helper-textarea')
    ).toBeFocused();
    expect(await page.evaluate(() => window.__workspaceEvents.filter(
        entry => entry.event === 'ssh_disconnect'
            && entry.payload?.session_id === 'workspace-linux'
    ))).toEqual([]);
    await assertNoExternalRequests(page);
});

test('failed and cancelled replacements preserve the current session until a successful replacement', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );

    await page.evaluate(() => {
        const previousEmit = window.socket.emit.bind(window.socket);
        window.__heldConnectAttempts = [];
        window.socket.emit = function holdReplacementConnections(event, payload, ...rest) {
            if (event === 'ssh_connect') {
                window.__heldConnectAttempts.push(structuredClone(payload));
                return window.socket;
            }
            if (event === 'ssh_connect_cancel') {
                window.__workspaceEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                queueMicrotask(() => rest[0]?.({
                    success: true,
                    cancelled: true,
                }));
                return window.socket;
            }
            if (payload?.session_id === 'replacement-session'
                    || payload?.source_id === 'sftp-session:replacement-session') {
                window.__workspaceEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                const deliver = (responseEvent, responsePayload) => queueMicrotask(() => {
                    window.socket.listeners(responseEvent).forEach(
                        listener => listener(responsePayload),
                    );
                });
                if (event === 'probe_session_sftp') {
                    deliver('session_sftp_capability', {
                        success: true,
                        available: true,
                        session_id: payload.session_id,
                        request_id: payload.request_id,
                    });
                } else if (event === 'get_home_directory') {
                    deliver('home_directory', {
                        source_id: payload.source_id,
                        path: '/home/replacement-user',
                        request_id: payload.request_id,
                    });
                } else if (event === 'list_directory') {
                    deliver('directory_listing', {
                        source_id: payload.source_id,
                        path: payload.remote_path,
                        files: [{
                            name: 'replacement-ready.txt',
                            is_dir: false,
                            size: 24,
                            permissions: '-rw-r--r--',
                        }],
                        request_id: payload.request_id,
                    });
                }
                return window.socket;
            }
            if (event === 'ssh_disconnect' && payload?.session_id === 'late-session') {
                window.__workspaceEvents.push({
                    event,
                    payload: structuredClone(payload),
                });
                return window.socket;
            }
            return previousEmit(event, payload, ...rest);
        };
    });

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('replacement.example');
    await page.locator('#usernameInput').fill('replacement-user');
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();

    await expect.poll(() => page.evaluate(() => window.__heldConnectAttempts.length))
        .toBe(1);
    const failedRequestId = await page.evaluate(
        () => window.__heldConnectAttempts[0].client_request_id
    );
    await page.evaluate(requestId => {
        window.socket.listeners('ssh_error').forEach(listener => listener({
            error: 'Replacement connection failed',
            client_request_id: requestId,
        }));
    }, failedRequestId);

    await expect(page.locator('.notification')).toContainText(
        'Replacement connection failed',
    );
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    expect(await page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        workspace: SessionManager.getWorkspaceSession(),
        assignment: SessionManager.paneAssignments[0],
        replacementExists: Boolean(SessionManager.getSession('late-session')),
    }))).toEqual({
        active: null,
        workspace: 'workspace-linux',
        assignment: 'workspace-linux',
        replacementExists: false,
    });
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );

    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__heldConnectAttempts.length))
        .toBe(2);
    const cancelledRequestId = await page.evaluate(
        () => window.__heldConnectAttempts[1].client_request_id
    );
    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('workspace-linux');
    await expect.poll(() => page.evaluate(requestId => (
        window.__workspaceEvents
            .filter(entry => entry.event === 'ssh_connect_cancel')
            .map(entry => entry.payload?.client_request_id)
    ), cancelledRequestId)).toEqual([cancelledRequestId]);

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('replacement.example');
    await page.locator('#usernameInput').fill('replacement-user');
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__heldConnectAttempts.length))
        .toBe(3);
    const lateSuccessRequestId = await page.evaluate(
        () => window.__heldConnectAttempts[2].client_request_id
    );
    await page.evaluate(requestId => {
        window.socket.listeners('ssh_auth_banner').forEach(listener => listener({
            prompt_id: 'cancelled-banner-prompt',
            banner: 'This cancelled request must stay hidden',
            context: 'target',
            host: 'replacement.example',
            port: 22,
            client_request_id: requestId,
        }));
    }, cancelledRequestId);
    await expect(page.locator('#sshAuthBannerModal')).not.toHaveClass(/show/);
    await page.evaluate(requestId => {
        window.socket.listeners('ssh_auth_banner').forEach(listener => listener({
            prompt_id: 'current-banner-prompt',
            banner: 'Current connection banner',
            context: 'target',
            host: 'replacement.example',
            port: 22,
            client_request_id: requestId,
        }));
    }, lateSuccessRequestId);
    await expect(page.locator('#sshAuthBannerModal')).toHaveClass(/show/);
    await page.evaluate(requestId => {
        window.socket.listeners('ssh_error').forEach(listener => listener({
            error: 'Cancelled request finished late',
            client_request_id: requestId,
        }));
    }, cancelledRequestId);
    await expect(page.locator('#sshAuthBannerModal')).toHaveClass(/show/);
    await page.evaluate(() => {
        window.socket.listeners('ssh_error').forEach(listener => listener({
            error: 'Unrelated session input error',
            session_id: 'workspace-linux',
        }));
    });
    await expect(page.locator('#sshAuthBannerModal')).toHaveClass(/show/);
    await expect(page.locator('#connectBtn')).toBeDisabled();
    await page.locator('#sshAuthBannerCancel').click();

    await page.locator('#cancelConnectionBtn').click();
    await expect(page.locator('#connectBtn')).toHaveText('Connect');
    await expect(page.locator('#connectBtn')).toBeEnabled();
    await expect(page.locator('#connectSpinner')).toHaveClass(/hidden/);
    await page.evaluate(requestId => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: 'late-session',
            host: 'replacement.example',
            port: 22,
            username: 'replacement-user',
            client_request_id: requestId,
        }));
    }, lateSuccessRequestId);

    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(requestId => (
        window.__workspaceEvents.some(
            entry => entry.event === 'ssh_discard_late_connection'
                && entry.payload.session_id === 'late-session'
                && entry.payload.client_request_id === requestId
        )
    ), lateSuccessRequestId)).toBe(true);
    expect(await page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        assignment: SessionManager.paneAssignments[0],
        replacementExists: Boolean(SessionManager.getSession('late-session')),
    }))).toEqual({
        active: 'workspace-linux',
        assignment: 'workspace-linux',
        replacementExists: false,
    });
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );

    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('replacement.example');
    await page.locator('#usernameInput').fill('replacement-user');
    await page.locator('#passwordInput').fill('replacement-password');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__heldConnectAttempts.length))
        .toBe(4);
    const successfulRequestId = await page.evaluate(
        () => window.__heldConnectAttempts[3].client_request_id
    );

    expect(await page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        workspace: SessionManager.getWorkspaceSession(),
        assignment: SessionManager.paneAssignments[0],
        currentConnected: SessionManager.getSession('workspace-linux')?.connected,
        replacementExists: Boolean(SessionManager.getSession('replacement-session')),
    }))).toEqual({
        active: null,
        workspace: 'workspace-linux',
        assignment: 'workspace-linux',
        currentConnected: true,
        replacementExists: false,
    });

    await page.evaluate(requestId => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: 'replacement-session',
            host: 'replacement.example',
            port: 22,
            username: 'replacement-user',
            display_name: 'Replacement host',
            client_request_id: requestId,
            file_source: {
                source_id: 'sftp-session:replacement-session',
                kind: 'sftp',
                label: 'Replacement host',
                endpoint: 'replacement.example:22',
                protocol: 'SFTP',
                capabilities: [
                    'list', 'read', 'write', 'mkdir', 'rename', 'delete',
                    'preview', 'edit', 'recursive', 'remote-transfer',
                ],
                ephemeral: false,
                security: { host_key_verified: true },
            },
        }));
    }, successfulRequestId);

    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => ({
        active: SessionManager.getActiveSession(),
        workspace: SessionManager.getWorkspaceSession(),
        assignment: SessionManager.paneAssignments[0],
        currentConnected: SessionManager.getSession('workspace-linux')?.connected,
        replacementConnected: SessionManager.getSession('replacement-session')?.connected,
        filesSession: window.sessionWorkspace?.getState?.().sessionId,
    }))).toEqual({
        active: 'replacement-session',
        workspace: 'replacement-session',
        assignment: 'replacement-session',
        currentConnected: true,
        replacementConnected: true,
        filesSession: 'replacement-session',
    });
    await expect(page.locator('#tab-workspace-linux')).toBeVisible();
    await expect(page.locator('#tab-workspace-linux')).not.toHaveClass(/active/);
    await expect(page.locator('#tab-replacement-session')).toHaveClass(/active/);
    await expect(page.locator('#sessionFilesPanel #fmLeftBadge')).toContainText(
        'replacement-user@replacement.example',
    );
    await expect(page.locator('#sessionFilesPanel #fmLeftPath')).toHaveValue(
        '/home/replacement-user',
    );
    await expect(page.locator('#sessionFilesPanel #fmLeftList .fm-file-item', {
        hasText: 'replacement-ready.txt',
    })).toHaveCount(1);
    expect(await page.evaluate(() => window.__workspaceEvents.filter(
        entry => entry.event === 'ssh_disconnect'
            && entry.payload?.session_id === 'workspace-linux'
    ))).toEqual([]);
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

test('compact Escape closes the Files menu before the Files context', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 900 });
    await login(page);
    await seedLinuxSession(page);

    await expect(page.locator('#contextWorkspaceLauncher')).toBeVisible();
    await page.locator('#contextWorkspaceLauncher').click();
    const filesPanel = page.locator('#sessionFilesPanel');
    const selectedFile = filesPanel.locator(
        '#fmLeftList .fm-file-item[data-index="1"]'
    );
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await selectedFile.click();
    await expect(selectedFile).toHaveClass(/selected/);

    await selectedFile.click({ button: 'right' });
    await expect(page.locator('.fm-context-menu')).toBeVisible();
    await page.keyboard.press('Escape');

    await expect(page.locator('.fm-context-menu')).toHaveCount(0);
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await expect(selectedFile).toHaveClass(/selected/);

    await page.keyboard.press('Escape');
    await expect(page.locator('#contextWorkspace')).toBeHidden();
    await expect(filesPanel).toBeHidden();
    await assertNoExternalRequests(page);
});

test('Escape respects focused controls outside embedded Files', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);

    const filesPanel = page.locator('#sessionFilesPanel');
    const selectedFile = filesPanel.locator(
        '#fmLeftList .fm-file-item[data-index="1"]'
    );
    await selectedFile.click();
    await expect(selectedFile).toHaveClass(/selected/);

    await page.locator('#broadcastToggleBtn').click();
    await expect(page.locator('#broadcastBar')).toBeVisible();
    await expect(page.locator('#broadcastInput')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.locator('#broadcastBar')).toBeHidden();
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );
    await expect(selectedFile).toHaveClass(/selected/);

    const sessionLabel = page.locator('#tab-workspace-linux .tab-label');
    await sessionLabel.dblclick();
    const renameInput = sessionLabel.locator('.tab-rename-input');
    await renameInput.fill('Discard this rename');
    await page.keyboard.press('Escape');
    await expect(renameInput).toHaveCount(0);
    await expect(sessionLabel).toContainText('Production Edge');
    await expect(filesPanel).toBeVisible();
    await expect(filesPanel.locator('#fmLeftPath')).toHaveValue(
        '/srv/webssh/current',
    );
    await expect(selectedFile).toHaveClass(/selected/);
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
    await page.locator('#sessionDiagnosticsNetworkSection summary').click();
    await expect(page.locator('#sessionDiagnosticsNetworkChart')).toBeVisible({ timeout: 6000 });
    await expect(page.locator('#sessionDiagnosticsProcessesSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsCpuProcesses')).toContainText('postgres');
    await expect(page.locator('#sessionDiagnosticsMemoryProcesses')).toContainText('redis-server');
    await expect(page.locator('.session-process-percent .session-diagnostics-bar > span')).toHaveCount(3);
    await page.locator('[data-diagnostics-view="systemd"]').click();
    await expect(page.locator('#sessionDiagnosticsSystemdSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsSystemdServices tr')).toHaveCount(3);
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('nginx.service');
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('backup.service');
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('cleanup.service');
    await page.locator('[data-diagnostics-view="docker"]').click();
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsDockerContainers tr')).toHaveCount(2);
    await expect(page.locator('#sessionDiagnosticsDockerContainers')).toContainText('webssh');
    await expect(page.locator('#sessionDiagnosticsDockerContainers')).toContainText('worker');

    if (captureAssetsEnabled()) {
        const screenshotPath = capturePath('session-diagnostics.png');
        await page.screenshot({
            path: screenshotPath,
            animations: 'disabled',
            caret: 'hide',
        });
        expect(pngSize(screenshotPath)).toEqual({ width: 2560, height: 1440 });
    }

    await page.locator('[data-diagnostics-view="systemd"]').click();
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
    await page.locator('[data-diagnostics-view="docker"]').click();
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
    await page.locator('#sessionDiagnosticsNetworkSection summary').click();
    await expect(page.locator('#sessionDiagnosticsNetworkChart')).toBeVisible({ timeout: 6000 });

    const canvases = page.locator([
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
    expect(initial).toHaveLength(2);
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


for (const width of [360, 1920]) {
    test(`command drafts and scroll follow active session at ${width}px`, async ({ page }, testInfo) => {
        await page.setViewportSize({width, height: width === 360 ? 740 : 1080});
        await login(page);
        await seedLinuxSession(page);
        await page.evaluate(() => {
            window.CommandSetManager.setCommandSets([]);
            window.CommandLibrary.setCommands(Array.from({length: 30}, (_, index) => ({
                id: `draft-${index}`, name: `Service ${index}`, command: 'systemctl status',
                parameters: 'webssh', description: 'Service state', os: ['linux'],
            })));
            SessionManager.createSession({session_id: 'second-draft', host: 'second.example', username: 'ops', port: 22});
            SessionManager.switchSession('workspace-linux');
            window.workspaceLayoutController.openContext('commands', 'user');
        });
        const search = page.locator('.session-command-search');
        await search.fill('Service');
        const row = page.locator('.session-command-item').nth(8);
        await row.locator('summary').click();
        await row.locator('input').fill('nginx --no-pager');
        await page.locator('.session-command-sudo-input').check();
        await expect(row.locator('code')).toHaveText('sudo systemctl status nginx --no-pager');
        await row.scrollIntoViewIfNeeded();
        const top = await page.locator('.session-command-results').evaluate(el => el.scrollTop);
        await page.evaluate(() => SessionManager.switchSession('second-draft'));
        await expect(search).toHaveValue('Service');
        await expect(row.locator('input')).toHaveValue('nginx --no-pager');
        expect(await page.locator('.session-command-results').evaluate(el => el.scrollTop)).toBeCloseTo(top, 0);
        await row.getByRole('button', {name: 'Insert', exact: true}).click();
        const sent = await page.evaluate(() => window.__workspaceEvents.filter(item => item.event === 'ssh_input').at(-1)?.payload);
        expect(sent).toEqual({session_id: 'second-draft', data: 'sudo systemctl status nginx --no-pager'});
        expect(await page.evaluate(() => window.CommandLibrary.commands[8].parameters)).toBe('webssh');
        if (captureAssetsEnabled()) {
            await page.screenshot({ path: capturePath(`parameters-${width}.png`) });
        }
        await row.getByRole('button', {name: 'Restore saved parameters'}).click();
        await expect(row.locator('input')).toHaveValue('webssh');
        await expect(row.locator('code')).toHaveText('sudo systemctl status webssh');
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    });
}


test('Files retains stale rows through a failed refresh and retry', async ({ page }, testInfo) => {
    await login(page);
    await seedLinuxSession(page);
    await page.locator('#contextFilesTab').click();
    const rows = page.locator('#sessionFilesMount .fm-file-item');
    await expect(rows).toHaveCount(5);
    const previousRows = await rows.allTextContents();
    await page.evaluate(() => {
        const emit = window.socket.emit.bind(window.socket);
        let fail = true;
        window.socket.emit = function failOneDirectory(event, ...args) {
            if (event === 'list_directory' && fail) {
                fail = false;
                const payload = args[0];
                queueMicrotask(() => window.socket.listeners('error').forEach(listener => listener({
                    operation: 'list_directory', source_id: payload.source_id,
                    request_id: payload.request_id, path: payload.remote_path, cursor: 0,
                    error: 'Temporary directory failure',
                })));
                return window.socket;
            }
            return emit(event, ...args);
        };
        window.socket.disconnect();
    });
    await expect(page.locator('#sessionFilesStatus')).toContainText('Reconnecting');
    expect(await rows.allTextContents()).toEqual(previousRows);
    await page.evaluate(() => { window.socket.connect(); });
    await expect(page.locator('#sessionFilesStatus')).toContainText('Could not refresh');
    await expect(page.locator('#sessionFilesMount .fm-embedded-mode')).toHaveAttribute('inert', '');
    expect(await rows.allTextContents()).toEqual(previousRows);
    if (captureAssetsEnabled()) {
        await page.screenshot({ path: capturePath('files-stale-retry.png') });
    }
    await page.locator('#sessionFilesStatus').getByRole('button', {name: 'Reload', exact: true}).click();
    await expect(page.locator('#sessionFilesStatus')).toBeHidden();
    await expect(page.locator('#sessionFilesMount .fm-embedded-mode')).not.toHaveAttribute('inert', '');
    await expect(rows).toHaveCount(5);
});


test.describe('mobile session header touch interaction', () => {
    test.use({hasTouch: true, viewport: {width: 390, height: 844}});

    test('header opens the session chooser from Commands and preserves the terminal', async ({page}) => {
        await login(page);
        await seedLinuxSession(page);
        await page.locator('[data-mobile-view="commands"]').tap();
        await expect(page.locator('#commandWorkspaceModal')).toBeVisible();
        const summary = page.locator('#mobileSessionSummary');
        await expect(summary).toBeEnabled();
        await summary.tap();
        await expect(page.locator('#commandWorkspaceModal')).toBeHidden();
        const launcher = page.locator('.terminal-pane.active .profile-launcher');
        await expect(launcher).toBeVisible();
        await expect(launcher.locator('.profile-launcher-return')).toBeVisible();
        await expect(page.locator('#sessionTabs .session-tab')).toHaveCount(1);
        await launcher.locator('.profile-launcher-return').tap();
        await expect(page.locator('.terminal-pane.active .xterm')).toBeVisible();
        await assertNoExternalRequests(page);
    });
});


test('diagnostics explains high load and keeps metric and inventory timestamps distinct', async ({ page }, testInfo) => {
    await login(page);
    await seedLinuxSession(page, { highLoad: true });
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsLoadValue')).toHaveText('133.3%');
    await expect(page.locator('#sessionDiagnosticsAssessment')).not.toHaveAttribute('open');
    await expect(page.locator('#sessionDiagnosticsFindings')).toBeHidden();
    const metricsHeight = await page.locator('.session-diagnostics-primary-grid').evaluate(el => el.getBoundingClientRect().height);
    expect(metricsHeight).toBeLessThan(220);
    await page.locator('#sessionDiagnosticsAssessment summary').click();
    await expect(page.locator('#sessionDiagnosticsLoadDetail')).toContainText('4.00 / 3.00 / 2.00');
    await expect(page.locator('#sessionDiagnosticsFindings')).toContainText('I/O');
    await expect(page.locator('#sessionDiagnosticsPressureScale')).toHaveText('133.3%');
    await expect(page.locator('#sessionDiagnosticsMetricsUpdated')).toContainText('Measurements received');
    await expect(page.locator('#sessionDiagnosticsLastUpdated')).toContainText('Inventory updated');
    await expect(page.locator('#sessionDiagnosticsHistoryCaption')).toContainText('samples over', { timeout: 6500 });
    await expect(page.locator('#sessionDiagnosticsCpuValue')).toContainText('%');
    await page.locator('#sessionDiagnosticsAssessment summary').click();
    await expect(page.locator('#sessionDiagnosticsCpuProcesses')).toBeInViewport();
    await expect.poll(() => page.evaluate(() => window.__workspaceChartSamples?.pressure || 0), { timeout: 6500 }).toBeGreaterThan(2);
    await page.screenshot({ path: testInfo.outputPath('diagnostics-high-load.png') });
    await page.locator('#contextWorkspace').screenshot({ path: testInfo.outputPath('diagnostics-panel.png') });
    await page.locator('[data-diagnostics-view="systemd"]').click();
    await expect(page.locator('#sessionDiagnosticsSystemdSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsProcessesSection')).toBeHidden();
    await page.locator('[data-diagnostics-view="systemd"]').press('ArrowRight');
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeVisible();
    await page.locator('[data-diagnostics-view="processes"]').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#contextWorkspaceLauncher').click();
    await page.locator('#sessionDiagnosticsAssessment summary').click();
    await expect(page.locator('#sessionDiagnosticsFindings')).toBeVisible();
    await page.locator('#sessionDiagnosticsAssessment summary').click();
    await expect(page.locator('#sessionDiagnosticsCpuValue')).toContainText('%', { timeout: 6500 });
    await expect(page.locator('#sessionDiagnosticsCpuMetric')).toBeVisible({ timeout: 6500 });
    const headerHeight = await page.locator('.session-diagnostics-header').evaluate(el => el.getBoundingClientRect().height);
    expect(headerHeight).toBeLessThan(190);
    await page.screenshot({ path: testInfo.outputPath('diagnostics-mobile.png') });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});


test('diagnostics retains the root disk trend when other measurements are unavailable', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page, { diskOnlyMetrics: true });
    await page.locator('#contextDiagnosticsTab').click();
    await expect(page.locator('#sessionDiagnosticsPressureChart')).toBeVisible({ timeout: 6500 });
    await expect(page.locator('#sessionDiagnosticsDiskValue')).toHaveText('80.0%');
    await expect(page.locator('#sessionDiagnosticsPressureSection .session-chart-legend .disk')).toHaveText('Root disk');
    await expect.poll(() => page.evaluate(() => {
        const disk = window.__workspacePressureSeries?.find(item => item.key === 'disk');
        return disk?.values.filter(value => value !== null).slice(0, 2);
    })).toEqual([20, 80]);
    await expect(page.locator('#sessionDiagnosticsPressureChart')).toHaveAttribute('aria-label', /Root disk 80\.0%/);
    for (const metric of ['Cpu', 'Memory', 'Load']) {
        await expect(page.locator(`#sessionDiagnostics${metric}Metric`)).toBeHidden();
    }
    await page.locator('[data-diagnostics-view="systemd"]').click();
    await expect(page.locator('#sessionDiagnosticsSystemdServices')).toContainText('nginx.service');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#contextWorkspaceLauncher').click();
    await expect(page.locator('#sessionDiagnosticsPressureChart')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

async function setFontTestPreferences(page, settings) {
    const result = await page.evaluate(async appearance => {
        const response = await fetch('/api/account/preferences', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content},
            body: JSON.stringify({terminal_appearance: appearance}),
        });
        const result = await response.json();
        if (response.ok) window.TerminalAppearance.setPreferences(result.settings.terminal_appearance);
        return response.ok;
    }, settings);
    expect(result).toBe(true);
}

test('font changes preserve the live TUI, input modes, scrollback and existing colours while resizing the PTY', async ({page}) => {
    await login(page);
    await setFontTestPreferences(page, {foreground: '#dce8f4', background: '#142536', background_opacity: 45, cursor_style: 'bar', cursor_blink: false});
    try {
        await seedLinuxSession(page, {useTmux: true, initialLiveOutput: '\r\n'});
        await expect.poll(() => page.evaluate(() => TerminalManager.terminalReady['workspace-linux'])).toBe(true);
        await page.evaluate(async () => {
            const term = TerminalManager.terminals['workspace-linux'];
            window.__fontTerminalRef = term;
            window.__fontOldSize = {cols: term.cols, rows: term.rows};
            const history = Array.from({length: 150}, (_, i) => `history-${i}`).join('\r\n');
            await new Promise(resolve => TerminalManager.writeOutput('workspace-linux', history + '\r\n\x1b[?1049h\x1b[H\x1b[?2004h\x1b[?1h\x1b[38;2;123;45;67m\uf07b app.py\x1b[0m', null, resolve));
            window.__workspaceEvents = [];
        });
        await page.locator('#terminalAppearanceBtn').click();
        await page.locator('[name="terminalFontPreset"][value="WebSSH Fira Mono"]').check();
        await expect(page.locator('#terminalFontStatus')).not.toContainText('Loading');
        await page.evaluate(async () => {
            await document.fonts.ready;
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        });
        expect(await page.evaluate(() => window.__workspaceEvents.filter(e => e.event === 'ssh_resize'))).toEqual([]);
        expect(await page.evaluate(() => TerminalAppearance.getPreferences().font_family)).toBeUndefined();
        await page.locator('#terminalFontSize').fill('22');
        await page.locator('#terminalLineHeight').fill('1.3');
        await page.locator('#terminalAppearanceSave').click();
        await expect.poll(() => page.evaluate(() => TerminalAppearance.getPreferences().font_size)).toBe(22);
        await expect.poll(() => page.evaluate(() => {
            const term = TerminalManager.terminals['workspace-linux'];
            const resize = window.__workspaceEvents.filter(e => e.event === 'ssh_resize').at(-1)?.payload;
            return resize?.cols === term.cols && resize?.rows === term.rows && term.rows < window.__fontOldSize.rows;
        })).toBe(true);
        const state = await page.evaluate(() => {
            const term = TerminalManager.terminals['workspace-linux'];
            const baseline = new Terminal({allowProposedApi: true});
            const baselineUnicode = baseline.unicode.activeVersion;
            baseline.dispose();
            const history = Array.from({length: term.buffer.normal.length}, (_, i) => term.buffer.normal.getLine(i).translateToString(true)).join('\n');
            return {same: term === window.__fontTerminalRef, unicode: term.unicode.activeVersion, baselineUnicode,
                screen: term.buffer.active.type, text: term.buffer.active.getLine(0).translateToString(true),
                ansi: term.buffer.active.getLine(0).getCell(0).getFgColor(), history,
                paste: term.modes.bracketedPasteMode, cursorKeys: term.modes.applicationCursorKeysMode,
                family: term.options.fontFamily, foreground: term.options.theme.foreground,
                cursor: term.options.cursorStyle, blink: term.options.cursorBlink,
                opacity: TerminalAppearance.getPreferences().background_opacity};
        });
        expect(state).toMatchObject({same: true, unicode: state.baselineUnicode, screen: 'alternate', text: '\uf07b app.py',
            ansi: 0x7b2d43, paste: true, cursorKeys: true, foreground: '#dce8f4', cursor: 'bar', blink: false, opacity: 45});
        expect(state.family).toBe('"WebSSH Fira Mono", "WebSSH Nerd Symbols", monospace');
        expect(state.history).toContain('history-0');
        expect(state.history).toContain('history-149');
        await page.locator('[data-close-terminal-appearance]').last().click();
        await page.locator('#terminal-workspace-linux textarea').press('ArrowUp');
        await expect.poll(() => page.evaluate(() => window.__workspaceEvents.filter(e => e.event === 'ssh_input').map(e => e.payload.data).join(''))).toContain('\x1bOA');
        await page.evaluate(() => new Promise(resolve => TerminalManager.writeOutput('workspace-linux', '\x1b[?1049l', null, resolve)));
        expect(await page.evaluate(() => TerminalManager.terminals['workspace-linux'].buffer.active.type)).toBe('normal');
        assertNoExternalRequests(page);
    } finally {
        await setFontTestPreferences(page, {});
    }
});

test('failed font downloads and cancelled previews leave existing terminal input and settings usable', async ({page}) => {
    await page.route('**/static/vendor/terminal-fonts/*.woff2', route => route.abort());
    await login(page);
    await setFontTestPreferences(page, {font_family: 'Consolas', font_size: 15});
    try {
        await seedLinuxSession(page);
        await expect.poll(() => page.evaluate(() => TerminalManager.terminalReady['workspace-linux'])).toBe(true);
        const originalFamily = await page.evaluate(() => TerminalManager.terminals['workspace-linux'].options.fontFamily);
        await page.locator('#terminalAppearanceBtn').click();
        await page.locator('[name="terminalFontPreset"][value="WebSSH Hack"]').check();
        await expect(page.locator('#terminalFontStatus')).toContainText(/unavailable/i);
        await page.locator('[data-close-terminal-appearance]').last().click();
        expect(await page.evaluate(() => TerminalManager.terminals['workspace-linux'].options.fontFamily)).toBe(originalFamily);
        expect(await page.evaluate(() => TerminalAppearance.getPreferences().font_family)).toBe('Consolas');
        await page.locator('#terminal-workspace-linux textarea').pressSequentially('echo retained');
        await page.locator('#terminal-workspace-linux textarea').press('Enter');
        await expect.poll(() => page.evaluate(() => window.__workspaceEvents.filter(e => e.event === 'ssh_input').map(e => e.payload.data).join(''))).toContain('echo retained\r');
        assertNoExternalRequests(page);
    } finally {
        await setFontTestPreferences(page, {});
    }
});

test('first-contact trust shows exact fingerprint and closes stale approval', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await page.evaluate(() => {
        const emit = window.socket.emit.bind(window.socket);
        window.__trustAnswers = [];
        window.socket.emit = (event, payload, ...args) => {
            if (event === 'ssh_connect') {
                window.__trustRequest = payload.client_request_id;
                return window.socket;
            }
            if (event === 'ssh_host_key_decision') {
                window.__trustAnswers.push(payload);
                return window.socket;
            }
            return emit(event, payload, ...args);
        };
    });
    await page.locator('#newTabBtn').click();
    await page.locator('.terminal-pane.active .profile-launcher-new').click();
    await page.locator('#hostInput').fill('trust.example');
    await page.locator('#usernameInput').fill('tester');
    await page.locator('#passwordInput').fill('not-sent');
    await page.locator('#connectBtn').click();
    await expect.poll(() => page.evaluate(() => window.__trustRequest)).toBeTruthy();
    const showPrompt = () => page.evaluate(() => {
        for (const handler of window.socket.listeners('ssh_host_key')) handler({
            prompt_id: 'exact-key-prompt', client_request_id: window.__trustRequest,
            host: 'trust.example', port: 2222, key_type: 'ssh-ed25519',
            fingerprint: 'SHA256:verified-fingerprint', context: 'jump_host',
        });
    });
    await showPrompt();
    await expect(page.locator('#sshHostKeyModal')).toHaveClass(/show/);
    await expect(page.locator('#sshHostKeyTarget')).toContainText('trust.example:2222');
    await expect(page.locator('#sshHostKeyFingerprint')).toHaveText('ssh-ed25519\nSHA256:verified-fingerprint');
    await page.locator('#sshHostKeyAccept').click();
    await expect.poll(() => page.evaluate(() => window.__trustAnswers[0]?.accepted)).toBe(true);
    await expect(page.locator('#sshHostKeyModal')).not.toHaveClass(/show/);
    await showPrompt();
    await page.locator('#sshHostKeyCancel').focus();
    await page.keyboard.press('Escape');
    await expect.poll(() => page.evaluate(() => window.__trustAnswers[1]?.accepted)).toBe(false);
    await showPrompt();
    await page.evaluate(() => {
        for (const handler of window.socket.listeners('ssh_host_key_closed')) handler({prompt_id: 'exact-key-prompt'});
    });
    await expect(page.locator('#sshHostKeyModal')).not.toHaveClass(/show/);
});
