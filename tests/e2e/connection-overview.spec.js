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

test('overview presents owned inventory without opening connections', async ({page}) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'workspaces');
    await openOverview(page);
    await expect(page.locator('#overviewTitle')).toBeFocused();
    await expect(page.locator('#overviewNavBtn')).toHaveAttribute('aria-current', 'page');
    const hosts = page.locator('#overviewHostList .od-host');
    // Other cases on the shared server may add hosts; the dashboard must show every owned one.
    const owned = await page.evaluate(() => ProfileManager.profiles.length);
    expect(owned).toBeGreaterThanOrEqual(20);
    await expect(hosts).toHaveCount(owned);
    await expect(page.locator('#overviewHostTotal')).toHaveText(String(owned));
    await expect(page.locator('#odKpiHosts .od-kpi-value')).toContainText(`/ ${owned}`);
    expect(await sshAttempts(page)).toEqual([]);
    await page.locator('#overviewSearch').fill('Password review');
    await expect(hosts).toHaveCount(1);
    await expect(hosts.first()).toContainText('password.local');
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
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
        await expect(page.locator('#overviewHostList .od-host').first()).toBeVisible();
        await page.evaluate(() => window.__overviewTerminal.write('BACKGROUND OUTPUT\r\n'));
        await page.locator('#overviewSearch').fill('Password review');
        await page.locator('#workspaceNavBtn').click();
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

test('host list handles empty/loading and large hostile labels without horizontal overflow', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await page.emulateMedia({reducedMotion: 'reduce'});
    await openOverview(page);
    await page.evaluate(() => {
        window.ProfileManager.profilesLoaded = false;
        window.dispatchEvent(new CustomEvent('profile-list-change'));
    });
    await expect(page.locator('#overviewHostList')).toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('#overviewHostList .od-skeleton').first()).toBeAttached();
    await page.evaluate(() => window.ProfileManager.setProfiles([]));
    await expect(page.locator('#overviewHostsEmpty')).toBeVisible();
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(0);
    await page.evaluate(() => {
        window.JumpHostManager.setJumpHosts([{id: 'jump', name: 'Jump'}]);
        window.ProfileManager.setProfiles(Array.from({length: 120}, (_, index) => ({
            id: `host-${index}`, name: '<img src=x onerror=alert(1)>' + 'LongName'.repeat(12),
            group: index % 2 ? 'A' : 'B', jump_host_id: index % 2 ? 'jump' : 'missing',
        })));
    });
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(120);
    await expect(page.locator('#connectionOverview img')).toHaveCount(0);
    await expect(page.locator('#overviewHostList .od-host').filter({hasText:'Saved jump host unavailable'})).toHaveCount(60);
    await page.locator('#overviewSearch').fill('Jump');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(60);
    await expect(page.locator('#overviewHostList [data-host-id="host-119"]')).toBeAttached();
    expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    await page.locator('#overviewSearch').press('Escape');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(120);
    await page.evaluate(() => window.i18n.setLanguage('de'));
    await expect(page.locator('#overviewTitle')).toContainText('e2e_admin');
    await expect(page.locator('#overviewTitle')).toHaveText(/^(Hallo|Guten Morgen|Guten Abend), e2e_admin$/);
    expect(await sshAttempts(page)).toEqual([]);
});

for (const width of [390, 1440]) {
    test(`overview search opens the existing host editor directly at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await openOverview(page);
        await page.locator('#overviewSearch').fill('Password review');
        await page.getByRole('button', {name:'Edit Password review', exact:true}).click();
        await expect(page.locator('#profileEditorName')).toHaveValue('Password review');
        await expect(page.locator('#profileEditorHost')).toHaveValue('password.local');
        expect(await sshAttempts(page)).toEqual([]);
        expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    });
    test(`overview search connects through credential review at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height:900});
        await openOverview(page);
        await page.locator('#overviewSearch').fill('Password review');
        await page.getByRole('button', {name:'Connect Password review', exact:true}).click();
        await expect(page.locator('#connectionModal')).toHaveClass(/show/);
        await expect(page.locator('#hostInput')).toHaveValue('password.local');
        expect(await sshAttempts(page)).toEqual([]);
    });
}
test('overview favorites launch a ready saved host without inspecting its path first', async ({page})=>{
    await page.setViewportSize({width:1440,height:900});
    await openOverview(page);
    await page.locator('#overviewHostList').getByRole('button',{name:'Connect Usable key',exact:true}).click();
    await expect.poll(async()=> (await sshAttempts(page)).length).toBe(1);
    expect((await sshAttempts(page))[0].payload.profile_id).toBe('usable-key');
});
