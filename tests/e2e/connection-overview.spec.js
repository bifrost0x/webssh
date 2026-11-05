const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

async function openOverview(page) {
    if (!await page.locator('#overviewNavBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#connectionOverview')).toBeVisible();
}

test.beforeEach(async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
});

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

test('overview presents owned inventory and inspects routes without opening connections', async ({page}) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'workspaces');
    await openOverview(page);
    await expect(page.locator('#overviewTitle')).toBeFocused();
    await expect(page.locator('#overviewNavBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('.overview-list-group')).toHaveCount(6);
    await expect(page.locator('#overviewHosts > .overview-pagination')).toHaveCount(0);
    await expect(page.locator('.overview-resource-summary')).toContainText('20');
    await expect(page.locator('#overviewHosts')).not.toContainText('password.local');
    await expect(page.locator('#overviewHosts')).not.toContainText('passworduser');
    await page.locator('#overviewHosts [data-host-id]').first().click();
    await expect(page.locator('#overviewGraphLegend')).toBeHidden();
    await expect(page.locator('.overview-access-inspector')).toBeVisible();
    expect(await sshAttempts(page)).toEqual([]);
    await page.locator('#overviewHostSearch').fill('Password review');
    await expect(page.locator('.overview-compact-row')).toHaveCount(1);
    await page.getByRole('button', {name: 'Connection details: Password review', exact: true}).click();
    await expect(page.locator('.overview-path-stops')).toContainText('Password review');
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect(page.locator('.overview-access-facts')).toContainText('password.local');
    expect(await sshAttempts(page)).toEqual([]);
    expect(errors).toEqual([]);
});

test('single navigation entries retain Files, Commands, Hosts and recent connection form', async ({page}) => {
    for (const [action, target] of [
        ['fileTransferBtn', 'sftpFileManager'], ['commandLibraryBtn', 'commandWorkspaceModal'],
        ['manageProfilesBtn', 'profileManagementModal'],
    ]) {
        await openOverview(page);
        await page.locator(`#${action}`).click();
        await expect(page.locator(`#${target}`)).toBeVisible();
        await expect(page.locator('#connectionOverview')).toBeHidden();
    }
    await openOverview(page);
    await page.locator('#shellConnectBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#hostInput')).toBeVisible();
    expect(await sshAttempts(page)).toEqual([]);
});

for (const layout of [1, 2, 4]) {
    test(`overview retains xterm identity, output, layout and input with ${layout} panes`, async ({page}) => {
        await page.setViewportSize({width: 1440, height: 960});
        await page.evaluate(layout => {
            window.__overviewEvents = [];
            window.socket.emit = (event, ...args) => {
                window.__overviewEvents.push({event, payload: args[0]});
                return window.socket;
            };
            SessionManager.setSplitLayout(layout);
            for (let index = 0; index < layout; index++) {
                SessionManager.createSession({session_id: `overview-${index}`, host: 'fixture.local',
                    username: 'fixture', port: 22, display_name: `Session ${index}`});
                SessionManager.assignSessionToPane(`overview-${index}`, index);
            }
            window.__overviewTerminal = TerminalManager.terminals['overview-0'];
            window.__overviewElement = document.getElementById('terminal-overview-0');
            window.__overviewAssignments = [...SessionManager.paneAssignments];
        }, layout);
        await expect.poll(() => page.evaluate(() => TerminalManager.terminalReady['overview-0'])).toBe(true);
        await page.evaluate(() => new Promise(resolve => window.__overviewTerminal.write('PRESERVED OUTPUT\r\n', resolve)));
        await openOverview(page);
        await expect(page.locator('#overviewSessionCount')).toHaveText(String(layout));
        await page.evaluate(() => window.__overviewTerminal.write('BACKGROUND OUTPUT\r\n'));
        await page.locator('#overviewHosts [data-host-id]').first().click();
        if (await page.locator('.overview-access-inspector').count()) await page.locator('.overview-access-heading button').click();
        await page.locator('#overviewSessions button').first().click();
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'workspaces');
        await expect.poll(() => page.evaluate(() => {
            const terminal = TerminalManager.terminals['overview-0'];
            return {
                identity: terminal === window.__overviewTerminal,
                element: document.getElementById('terminal-overview-0') === window.__overviewElement,
                assignments: JSON.stringify(SessionManager.paneAssignments) === JSON.stringify(window.__overviewAssignments),
                output: terminal.buffer.active.getLine(1)?.translateToString(true),
                columns: terminal.cols > 5,
            };
        })).toEqual({identity: true, element: true, assignments: true, output: 'BACKGROUND OUTPUT', columns: true});
        await page.locator('#terminal-overview-0 .xterm-helper-textarea').focus();
        await page.keyboard.type('echo retained');
        await expect.poll(() => page.evaluate(() => window.__overviewEvents
            .filter(item => item.event === 'ssh_input').map(item => item.payload.data).join(''))).toContain('echo retained');
        expect(await page.evaluate(() => window.__overviewEvents.some(item => ['ssh_connect', 'ssh_disconnect'].includes(item.event)))).toBe(false);
    });
}

test('graph handles empty/loading/missing and large hostile labels without horizontal overflow', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await page.emulateMedia({reducedMotion: 'reduce'});
    await openOverview(page);
    await page.evaluate(() => {
        window.ProfileManager.profilesLoaded = false;
        window.dispatchEvent(new CustomEvent('profile-list-change'));
    });
    await expect(page.locator('#overviewHosts')).toContainText('Loading');
    await page.evaluate(() => window.socket.listeners('error').forEach(listener => listener({error: 'Fixture load error'})));
    await expect(page.locator('#overviewHosts')).toContainText('Saved connections could not be loaded.');
    await page.evaluate(() => window.ProfileManager.setProfiles([]));
    await expect(page.locator('#overviewHosts')).toContainText('No saved connections');
    await page.evaluate(() => {
        window.JumpHostManager.setJumpHosts([{id: 'jump', name: 'Jump'}]);
        window.ProfileManager.setProfiles(Array.from({length: 120}, (_, index) => ({
            id: `host-${index}`, name: '<img src=x onerror=alert(1)>' + 'LongName'.repeat(12),
            group: index % 2 ? 'A' : 'B', jump_host_id: index % 2 ? 'jump' : 'missing',
        })));
    });
    await expect(page.locator('.overview-list-group')).toHaveCount(2);
    await expect(page.locator('#overviewHosts img')).toHaveCount(0);
    await expect(page.locator('.overview-compact-route').filter({hasText:'Saved jump host unavailable'})).toHaveCount(60);
    await page.locator('#overviewGroupFilter').selectOption('group:A');
    await expect(page.locator('.overview-compact-row')).toHaveCount(60);
    await page.locator('#overviewHosts [data-host-id]').first().click();
    await expect(page.locator('.overview-path-stops')).toBeVisible();
    await expect(page.locator('#overviewHosts [data-host-id="host-119"]')).toBeAttached();
    expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    await page.locator('.overview-access-heading button').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.overview-path-stops')).toHaveCount(0);
    await expect(page.locator('.overview-compact-row')).toHaveCount(60);
    await page.evaluate(() => window.i18n.setLanguage('de'));
    await expect(page.locator('#overviewTitle')).toContainText('e2e_admin');
    await expect(page.locator('#overviewTitle')).toHaveText(/(Hallo|Guten Morgen|Guten Abend), e2e_admin\./);
    expect(await sshAttempts(page)).toEqual([]);
});

test('transfer shortcut uses the original queue and updates preserve host focus', async ({page}) => {
    await openOverview(page);
    await expect(page.locator('#overviewAllTransfers')).toBeHidden();
    await page.locator('#overviewHosts [data-host-id]').first().focus();
    await page.evaluate(() => {
        window.sftpFileManager.transferQueue = [{id: 'fixture-transfer', filename: 'fixture.txt', status: 'active', progress: 37}];
        window.sftpFileManager.renderTransferQueue();
    });
    await expect(page.locator('#overviewTransferCount')).toHaveText('1');
    await expect(page.locator('#overviewHosts [data-host-id]').first()).toBeFocused();
    await page.locator('#overviewAllTransfers').click();
    await expect(page.locator('#sftpFileManager')).toBeVisible();
    await expect(page.locator('#fmQueue')).not.toHaveClass(/collapsed/);
    await expect(page.locator('#fmQueueList')).toContainText('fixture.txt');
    await expect(page.locator('#fmQueueList')).toContainText('37%');
    await page.evaluate(() => {
        window.sftpFileManager.transferQueue[0].status = 'error';
        window.sftpFileManager.renderTransferQueue();
    });
    await expect(page.locator('#fmQueueList')).toContainText('Failed');
    await page.evaluate(() => {
        window.sftpFileManager.transferQueue = [];
        window.sftpFileManager.renderTransferQueue();
    });
    await openOverview(page);
    await expect(page.locator('#overviewAllTransfers')).toBeHidden();
});
for (const width of [390, 1440]) {
    test(`overview search opens the existing host editor directly at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await openOverview(page);
        await page.locator('#overviewHostSearch').fill('Password review');
        await page.getByRole('button', {name:'Edit Password review', exact:true}).click();
        await expect(page.locator('#profileEditorName')).toHaveValue('Password review');
        await expect(page.locator('#profileEditorHost')).toHaveValue('password.local');
        expect(await sshAttempts(page)).toEqual([]);
        expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    });
    test(`overview search connects through credential review at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await openOverview(page);
        await page.locator('#overviewHostSearch').fill('Password review');
        await page.getByRole('button', {name:'Connect Password review', exact:true}).click();
        await expect(page.locator('#connectionModal')).toHaveClass(/show/);
        await expect(page.locator('#hostInput')).toHaveValue('password.local');
        expect(await sshAttempts(page)).toEqual([]);
    });
}
test('overview favorites launch a ready saved host without inspecting its path first', async ({page})=>{
    await page.setViewportSize({width:1440,height:900});
    await openOverview(page);
    await page.locator('#overviewSessions').getByRole('button',{name:'Connect Usable key',exact:true}).click();
    await expect.poll(async()=> (await sshAttempts(page)).length).toBe(1);
    expect((await sshAttempts(page))[0].payload.profile_id).toBe('usable-key');
});
