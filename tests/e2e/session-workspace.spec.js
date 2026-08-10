const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 4 / 3,
});

function capturePath(testInfo) {
    return process.env.WEBSSH_CAPTURE_ASSETS === '1'
        ? path.resolve(__dirname, '..', '..', 'assets', 'session-workspace.png')
        : testInfo.outputPath('session-workspace-2560x1440.png');
}

function pngSize(filePath) {
    const png = fs.readFileSync(filePath);
    return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) };
}

async function seedLinuxSession(page) {
    await expect.poll(() => page.evaluate(() => (
        typeof Terminal === 'function'
        && typeof SessionManager !== 'undefined'
        && typeof SessionManager.createSession === 'function'
    ))).toBe(true);
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        let insightSample = 0;
        const fileRows = [
            { name: 'releases', is_dir: true, size: 0, permissions: 'drwxr-xr-x' },
            { name: 'compose.yaml', is_dir: false, size: 2841, permissions: '-rw-r--r--' },
            { name: 'healthcheck.sh', is_dir: false, size: 912, permissions: '-rwxr-xr-x' },
            { name: 'README.md', is_dir: false, size: 4876, permissions: '-rw-r--r--' },
        ];

        function deliver(event, payload) {
            queueMicrotask(() => window.socket.listeners(event).forEach(listener => listener(payload)));
        }

        window.socket.emit = function workspaceTestEmit(event, payload, ...rest) {
            if (payload?.session_id === 'workspace-linux') {
                if (event === 'request_session_insights') {
                    insightSample += 1;
                    window.__workspaceInsightSample = insightSample;
                    const cpuSamples = [
                        [200, 0, 150, 950],
                        [260, 0, 180, 1060],
                        [400, 0, 260, 1120],
                    ];
                    const stats = {
                        cpu: cpuSamples[Math.min(insightSample - 1, cpuSamples.length - 1)],
                        memory: {
                            total_kib: 16 * 1024 * 1024,
                            available_kib: 6 * 1024 * 1024,
                            used_kib: 10 * 1024 * 1024,
                        },
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
                            systemd: {
                                state: 'degraded',
                                running: 41,
                                failed: 1,
                                failed_units: ['backup.service'],
                            },
                        });
                        const diagnosticsMode = window.__workspaceDiagnosticsMode || 'full';
                        if (diagnosticsMode === 'full') {
                            stats.docker = {
                                version: '27.5.1',
                                running: 2,
                                total: 3,
                                containers: [
                                    { name: 'webssh', status: 'Up 3 hours (healthy)' },
                                    { name: 'redis', status: 'Up 3 hours' },
                                ],
                            };
                        } else if (diagnosticsMode === 'permission') {
                            stats.permission_denied = ['docker'];
                        }
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
                        session_id: payload.session_id,
                        path: '/srv/webssh/current',
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (event === 'list_directory') {
                    deliver('directory_listing', {
                        session_id: payload.session_id,
                        path: payload.remote_path,
                        files: fileRows,
                        request_id: payload.request_id,
                    });
                    return window.socket;
                }
                if (['ssh_input', 'ssh_resize'].includes(event)) return window.socket;
            }
            return originalEmit(event, payload, ...rest);
        };

        SessionManager.createSession({
            session_id: 'workspace-linux',
            host: 'edge-01.example',
            port: 22,
            username: 'ops',
            display_name: 'Production Edge',
        });
        SessionManager.assignSessionToPane('workspace-linux', 0);
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
    });
}

test('single-session workspace combines terminal, SFTP, live Linux stats, and notepad', async ({ page }, testInfo) => {
    await login(page);
    await seedLinuxSession(page);

    const toggle = page.locator('#sessionSftpToggleBtn');
    await expect(toggle).toBeEnabled();
    await expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#sessionMainSplit')).toHaveClass(/sftp-open/);
    await expect(page.locator('#sessionFilesPanel')).toBeVisible();
    await expect(page.locator('#fmLeftBadge')).toHaveText('ops@edge-01.example');
    await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(5);
    await expect(page.locator('#fmRightPane')).toBeHidden();
    await expect(page.locator('#fmTransfer')).toBeHidden();
    await expect(page.locator('#fmEmbeddedUpload')).toBeVisible();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current');
    await page.locator('#fmLeftList .fm-file-item[data-index="0"]').dblclick();
    await expect(page.locator('#fmLeftPath')).toHaveValue('/srv/webssh/current/releases');
    await expect(page.locator('#sessionInsightsState')).toHaveText('Live');
    await expect(page.locator('#sessionRamValue')).toContainText('10.0 GB');
    await expect(page.locator('#sessionDiskValue')).toContainText('61.0 GB');
    await expect(page.locator('#sessionOsValue')).toHaveText('Ubuntu 24.04.2 LTS');
    await expect(page.locator('#sessionCpuValue')).toContainText('%', { timeout: 6000 });
    await expect.poll(() => page.evaluate(() => window.__workspaceInsightSample || 0), {
        timeout: 10000,
    }).toBeGreaterThanOrEqual(3);

    const geometry = await page.evaluate(() => {
        const box = selector => {
            const rect = document.querySelector(selector).getBoundingClientRect();
            return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, width: rect.width };
        };
        return {
            terminal: box('#terminalGrid'),
            files: box('#sessionFilesPanel'),
            insights: box('#sessionInsightsCard'),
            notepad: box('.notepad-section'),
            viewport: { width: innerWidth, height: innerHeight },
        };
    });
    expect(geometry.terminal.width).toBeGreaterThan(650);
    expect(geometry.files.width).toBeGreaterThanOrEqual(360);
    expect(geometry.terminal.right).toBeLessThanOrEqual(geometry.files.left + 1);
    expect(geometry.insights.bottom).toBeLessThanOrEqual(geometry.notepad.top + 1);
    expect(geometry.files.right).toBeLessThanOrEqual(geometry.insights.left + 1);
    expect(geometry.files.bottom).toBeLessThanOrEqual(geometry.viewport.height);

    const screenshotPath = capturePath(testInfo);
    await page.screenshot({
        path: screenshotPath,
        animations: 'disabled',
        caret: 'hide',
    });
    expect(pngSize(screenshotPath)).toEqual({ width: 2560, height: 1440 });

    const samplesBeforeCollapse = await page.evaluate(() => window.__workspaceInsightSample);
    await page.locator('#notepadToggle').click();
    await page.waitForTimeout(4500);
    expect(await page.evaluate(() => window.__workspaceInsightSample)).toBe(samplesBeforeCollapse);

    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await page.evaluate(() => SessionManager.notifyWorkspaceChange());
    await expect(toggle).toHaveAttribute('aria-pressed', 'false');

    await page.evaluate(() => SessionManager.setSplitLayout(2));
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await expect(toggle).toBeDisabled();
    await page.evaluate(() => SessionManager.setSplitLayout(1));
    await expect(toggle).toBeEnabled();
    await expect(toggle).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#sessionFilesPanel')).toBeHidden();
    await assertNoExternalRequests(page);
});

test('mobile workspace does not poll hidden Linux telemetry', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 900 });
    await login(page);
    await seedLinuxSession(page);
    await page.waitForTimeout(500);

    expect(await page.evaluate(() => window.__workspaceInsightSample || 0)).toBe(0);
    await expect(page.locator('#sessionInsightsCard')).toBeHidden();
    await assertNoExternalRequests(page);
});

test('diagnostics overlay requests and renders optional details only while open', async ({ page }) => {
    await login(page);
    await seedLinuxSession(page);
    await expect(page.locator('header')).toHaveCount(1);
    await expect(page.locator('#sessionInsightsState')).toHaveText('Live');
    await page.waitForTimeout(500);

    expect(await page.evaluate(() => window.__workspaceExpandedRequests || 0)).toBe(0);
    const toggle = page.locator('#sessionDiagnosticsToggle');
    await expect(toggle).toBeEnabled();
    await toggle.click();

    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsProcessesSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsCpuProcesses')).toContainText('postgres');
    await expect(page.locator('#sessionDiagnosticsMemoryProcesses')).toContainText('redis-server');
    await expect(page.locator('#sessionDiagnosticsSystemdSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsSystemdCounts')).toHaveText('41 active - 1 failed');
    await expect(page.locator('#sessionDiagnosticsSystemdFailures')).toContainText('backup.service');
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsDockerContainers')).toContainText('webssh');
    await expect(page.locator('#sessionDiagnosticsNetworkMetric')).toBeVisible({ timeout: 6000 });
    await expect(page.locator('#sessionDiagnosticsNetworkValue')).toContainText('KB/s');

    const beforePermission = await page.evaluate(() => window.__workspaceExpandedRequests);
    await page.evaluate(() => { window.__workspaceDiagnosticsMode = 'permission'; });
    await expect.poll(() => page.evaluate(() => window.__workspaceExpandedRequests), {
        timeout: 6000,
    }).toBeGreaterThan(beforePermission);
    await expect(page.locator('#sessionDiagnosticsPermissions')).toBeVisible();
    await expect(page.locator('#sessionDiagnosticsPermissionList')).toContainText(
        'cannot access the Docker daemon',
    );
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeHidden();

    const beforeGenericOmission = await page.evaluate(() => window.__workspaceExpandedRequests);
    await page.evaluate(() => { window.__workspaceDiagnosticsMode = 'generic'; });
    await expect.poll(() => page.evaluate(() => window.__workspaceExpandedRequests), {
        timeout: 6000,
    }).toBeGreaterThan(beforeGenericOmission);
    await expect(page.locator('#sessionDiagnosticsPermissions')).toBeHidden();
    await expect(page.locator('#sessionDiagnosticsDockerSection')).toBeHidden();

    await page.keyboard.press('Escape');
    await expect(page.locator('#sessionDiagnosticsOverlay')).toBeHidden();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    const expandedAfterClose = await page.evaluate(() => window.__workspaceExpandedRequests);
    await page.waitForTimeout(4500);
    expect(await page.evaluate(() => window.__workspaceExpandedRequests)).toBe(expandedAfterClose);
    await assertNoExternalRequests(page);
});
