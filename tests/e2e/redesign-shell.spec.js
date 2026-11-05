const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests, assertRouteGeometry} = require('./helpers');

async function overview(page) {
    if (!await page.locator('#overviewNavBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#connectionOverview')).toBeVisible();
}

// Browser-only fixtures for reproducible visual evidence, never shipped in the app.
async function seedPresentation(page) {
    await page.evaluate(() => {
        const profiles = [
            ['web', 'prod-web-01', 'Production', 'bastion'],
            ['api', 'prod-api-01', 'Production', 'bastion'],
            ['db', 'db-cluster', 'Database', 'db-jump'],
            ['nas', 'nas', 'Homelab', null],
            ['router', 'pfSense', 'Homelab', null],
        ].map(([id, name, group, jump]) => ({id, name, group, jump_host_id: jump,
            host: `${id}.example.invalid`, port: 22, username: 'demo', auth_type: 'password',
            favorite: ['web', 'nas'].includes(id), startup_mode: 'none'}));
        ProfileManager.setProfiles(profiles);
        JumpHostManager.setJumpHosts([{id: 'bastion', name: 'bastion-01'}, {id: 'db-jump', name: 'db-jump'}]);
        profiles.forEach(profile => ConnectionHistory.addConnection(profile.name, 22, 'demo'));
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, ...args) => {
            const payload = args[0];
            if (payload?.session_id?.startsWith('design-') || payload?.source_id?.includes('design-')) {
                const deliver = (name, value) => queueMicrotask(() => window.socket.listeners(name).forEach(listener => listener(value)));
                if (event === 'probe_session_sftp') deliver('session_sftp_capability', {success: true, available: true, session_id: payload.session_id, request_id: payload.request_id});
                if (event === 'request_session_directory') args.find(value => typeof value === 'function')?.({success: true, directory: {path: '/home/demo', shell_ready: true, shell_id: 'design', shell: 'bash'}});
                if (event === 'get_home_directory') deliver('home_directory', {source_id: payload.source_id, path: '/home/demo', request_id: payload.request_id});
                if (event === 'list_directory') deliver('directory_listing', {
                    source_id: payload.source_id, path: payload.remote_path, request_id: payload.request_id,
                    files: [{name: '.config', is_dir: true, size: 0}, {name: 'backups', is_dir: true, size: 0},
                        {name: 'projects', is_dir: true, size: 0}, {name: 'compose.yaml', is_dir: false, size: 2841},
                        {name: 'README.md', is_dir: false, size: 4876}],
                });
                return window.socket;
            }
            return original(event, ...args);
        };
        for (const [index, profile] of profiles.slice(0, 3).entries()) {
            const id = `design-${index}`;
            SessionManager.createSession({session_id: id, host: profile.host, username: 'demo', port: 22,
                display_name: profile.name, file_source: {source_id: `sftp-session:${id}`, kind: 'sftp',
                    label: profile.name, endpoint: `${profile.host}:22`, protocol: 'SFTP',
                    capabilities: ['list', 'read', 'write', 'mkdir', 'rename', 'delete', 'preview', 'edit', 'recursive'],
                    ephemeral: false, security: {host_key_verified: true}}});
        }
        SessionManager.assignSessionToPane('design-0', 0);
        SessionManager.switchSession('design-0');
        window.sftpFileManager.transferQueue = [
            {id: 'design-transfer-1', filename: 'backup.tar.gz', status: 'active', progress: 68},
            {id: 'design-transfer-2', filename: 'logs-2026.zip', status: 'pending', progress: 0},
            {id: 'design-transfer-3', filename: 'data.sql', status: 'complete', progress: 100},
        ];
    });
    await expect.poll(() => page.evaluate(() => TerminalManager.terminalReady['design-0'])).toBe(true);
    await page.evaluate(() => new Promise(resolve => TerminalManager.terminals['design-0'].write(
        '\x1b[36mdemo@prod-web-01\x1b[0m:~$ ls -la\r\n' +
        'drwxr-xr-x  .config\r\ndrwxr-xr-x  backups\r\ndrwxr-xr-x  projects\r\n' +
        '-rw-r--r--  compose.yaml\r\n-rw-r--r--  README.md\r\n\r\n' +
        '\x1b[36mdemo@prod-web-01\x1b[0m:~$ \r\n', resolve)));
}

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

test('one real search and exact group filter preserve existing recent-history review', async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(() => {
        ConnectionHistory.addConnection('history.example.invalid', 2222, 'demo');
        ProfileManager.setProfiles([
            {id: 'a', name: 'Alpha', group: 'Ops', auth_type: 'password'},
            {id: 'b', name: 'Beta', group: 'Ops extended', auth_type: 'password'},
        ]);
    });
    await overview(page);
    const group = page.locator('#overviewGroupFilter');
    await group.selectOption('group:Ops');
    await expect(page.locator('.overview-compact-row')).toHaveCount(1);
    await expect(page.locator('#overviewHosts')).toContainText('Alpha');
    await expect(group).toHaveValue('group:Ops');
    await group.selectOption('');
    await expect(page.locator('.overview-compact-row')).toHaveCount(2);
    await page.locator('#overviewHostSearch').fill('Beta');
    await expect(page.locator('#overviewHosts .overview-row-title')).toHaveText(['Beta']);
    await expect(page.locator('#overviewHosts')).toContainText('Beta');
    await expect(page.locator('#overviewHistory')).toBeHidden();
    await page.locator('#overviewHostSearch').fill('');
    await page.locator('#overviewHistory button').click();
    await expect(page.locator('#hostInput')).toHaveValue('history.example.invalid');
    await expect(page.locator('#portInput')).toHaveValue('2222');
    await expect(page.locator('#usernameInput')).toHaveValue('demo');
    await expect(page.locator('#passwordInput')).toBeFocused();
    expect(await sshAttempts(page)).toEqual([]);
});

test('workspace host tree launches through the existing saved-profile review', async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await installSshConnectTrap(page);
    await expect(page.locator('.shell-groups')).toBeHidden();
    await page.evaluate(() => SessionManager.createSession({session_id: 'tree-test', host: 'fixture.example.invalid', username: 'demo', port: 22}));
    await page.locator('#toggleHostRail').click();
    await page.locator('#shellGroups').getByRole('button', {name: 'Password review', exact: true}).click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#hostInput')).toHaveValue('password.local');
    await expect(page.locator('#passwordInput')).toBeFocused();
    expect(await sshAttempts(page)).toEqual([]);
});

test('network distinguishes configured, direct and missing routes and retains paths after resize', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(() => {
        JumpHostManager.setJumpHosts([{id: 'jump', name: 'Bastion'}]);
        ProfileManager.setProfiles([
            {id: 'one', name: 'One', group: 'A', jump_host_id: 'jump'},
            {id: 'two', name: 'Two', group: 'B', jump_host_id: 'jump'},
            {id: 'missing', name: 'Missing', group: 'B', jump_host_id: 'absent'},
            {id: 'direct', name: 'Direct', group: 'A'},
        ]);
    });
    await overview(page);
    const previewTarget = page.locator('#overviewHosts [data-host-id="one"]');
    await previewTarget.focus();
    await page.evaluate(() => window.dispatchEvent(new Event('profile-list-change')));
    await expect(previewTarget).toBeFocused();
    await expect(page.locator('.overview-compact-route').filter({hasText:'Saved jump host unavailable'})).toHaveCount(1);
    await page.getByRole('button',{name:'Expand map',exact:true}).click();
    await expect(page.locator('.ssh-route-branch')).toHaveCount(3);
    await expect(page.locator('.ssh-route-canvas > svg > path')).toHaveCount(5);
    for (const width of [1280, 1920, 390]) {
        await page.setViewportSize({width, height: 844});
        await assertRouteGeometry(page);
        await expect(page.getByRole('button',{name:'Close map',exact:true})).toBeInViewport();
    }
    await page.keyboard.press('Escape');
    expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    await previewTarget.click();
    await expect(page.locator('.overview-path-stops > li strong')).toHaveText(['WebSSH server','Bastion','One']);
    await page.locator('.overview-access-heading button').click();
    await page.locator('#overviewHostSearch').fill('Direct');
    await page.locator('#overviewHosts [data-host-id="direct"]').click();
    await expect(page.locator('.overview-path-stops > li strong')).toHaveText(['WebSSH server','Direct']);
    expect(await sshAttempts(page)).toEqual([]);
});

for (const width of [1440, 1024, 390]) {
    test(`reference composition and workspace continuity at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: width === 1440 ? 1024 : 900});
        await login(page);
        await seedPresentation(page);
        await overview(page);
        // Active sessions already appear beside history; only the other targets
        // belong in the compact recent-connections section.
        await expect(page.locator('#overviewHistory button')).toHaveCount(2);
        await expect(page.locator('#overviewHistory')).toContainText('nas');
        await expect(page.locator('#overviewHistory')).toContainText('pfSense');
        await expect(page.locator('#overviewSessionCount')).toHaveText('3');
        await expect(page.locator('#overviewTransferCount')).toHaveText('3');
        await expect(page.locator('#connectionOverview progress')).toHaveCount(0);
        await expect(page.locator('#overviewSessions')).not.toContainText('Connected');
        await page.screenshot({path: test.info().outputPath( `dashboard-${width}.png`)});
        await page.locator('#overviewHosts [data-host-id]').first().click();
        await expect(page.locator('.overview-path-stops > li strong')).toHaveText(['WebSSH server', 'db-jump', 'db-cluster']);
        await expect(page.locator('#overviewAccessTitle')).toBeFocused();
        await expect(page.locator('#overviewAccessTitle')).toBeInViewport();
        await page.screenshot({path: test.info().outputPath( `graph-${width}.png`)});
        if (await page.locator('#workspaceNavBtn').isVisible()) await page.locator('#workspaceNavBtn').click();
        else await page.locator('[data-mobile-view=workspaces]').click();
        await page.evaluate(() => window.workspaceLayoutController.openContext('files', 'user'));
        await expect(page.locator('#contextFilesPanel')).toBeVisible();
        await expect(page.locator('#sessionFilesMount')).toContainText('README.md');
        await page.screenshot({path: test.info().outputPath( `workspace-${width}.png`)});
        if (width === 1440) {
            await page.locator('#fileTransferBtn').click();
            await expect(page.locator('#sftpFileManager')).toBeVisible();
            await page.screenshot({path: test.info().outputPath( 'files-1440.png')});
            await page.evaluate(() => { document.body.dataset.theme = 'paper'; });
            await overview(page);
            await page.screenshot({path: test.info().outputPath( 'dashboard-paper-1440.png')});
        }
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });
}

test('empty overview exposes one search and no invented sessions, routes or transfers', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(() => {
        ProfileManager.setProfiles([]);
        JumpHostManager.setJumpHosts([]);
    });
    await overview(page);
    await expect(page.locator('#overviewHostSearch')).toHaveCount(1);
    await expect(page.locator('#overviewRouteMap .ssh-map-toolbar input')).toHaveCount(1);
    await expect(page.locator('#overviewQuickConnect')).toHaveCount(0);
    await expect(page.locator('#shellConnectBtn')).toBeVisible();
    await expect(page.locator('#shellSearch, #shellQuickConnect, #routesNavBtn, #shellNotes, .overview-quick-actions, .shell-settings')).toHaveCount(0);
    await expect(page.locator('.shell-groups')).toBeHidden();
    await expect(page.locator('#overviewHostCount')).toHaveText('0');
    await expect(page.locator('#overviewSessionCount')).toHaveText('0');
    await expect(page.locator('#overviewSessions button')).toHaveCount(0);
    await expect(page.locator('#overviewAllTransfers')).toBeHidden();
    await expect(page.locator('#overviewHosts')).toContainText('No saved connections');
    await page.screenshot({path: test.info().outputPath('empty-overview.png')});
    await expect(page.locator('.overview-access-inspector')).toHaveCount(0);
    await expect(page.locator('.overview-edges path')).toHaveCount(0);
    await page.setViewportSize({width: 390, height: 844});
    await expect(page.locator('#mobileSessionSummary')).toBeVisible();
    if (await page.locator('.overview-access-inspector').count()) await page.locator('.overview-access-heading button').click();
    await page.screenshot({path: test.info().outputPath('empty-mobile.png')});
    await page.locator('#mobileSessionSummary').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    expect(await sshAttempts(page)).toEqual([]);
});
