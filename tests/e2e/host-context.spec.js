const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('restored session reconnect treats its old profile association as optional metadata', async ({page}) => {
    await login(page);
    const connection = await page.evaluate(() => {
        SessionManager.sessions['restored-context'] = {id: 'restored-context', host: 'old.example',
            port: 22, username: 'deploy', connected: false, profileId: 'deleted-profile',
            keyId: 'saved-key', authType: 'key', isPersistentCandidate: true, useTmux: true,
            tmuxSessionName: 'existing-tmux', reconnectRouteKnown: true};
        let captured;
        const emit = window.socket.emit;
        window.socket.emit = (event, data) => { if (event === 'ssh_connect') captured = data; };
        try { SessionManager.directReconnect('restored-context'); }
        finally { window.socket.emit = emit; }
        return captured;
    });
    expect(connection).toMatchObject({host: 'old.example', profile_id: 'deleted-profile',
        profile_context_optional: true, reconnect_tmux_name: 'existing-tmux'});
});

async function openContext(page, profileName) {
    await expect.poll(() => page.evaluate(() => window.ProfileManager?.profilesLoaded === true)).toBe(true);
    await openProfileManagement(page);
    // The modal first renders cached profiles. Its queued refresh replaces the
    // cards, so wait for a fresh list and its handler ACK before opening one.
    await page.evaluate(() => new Promise(resolve => window.socket.emit('list_profiles', resolve)));
    const card = page.locator('.profile-management-item').filter({has: page.getByText(profileName, {exact: true})});
    await card.locator('summary').click();
    await card.locator('[data-profile-action="context"]').click();
    await expect(page.locator('#hostContextFields')).toBeVisible();
}

test('private context persists per saved profile, preserves conflicts, and leaves global notes unchanged', async ({page}) => {
    await login(page);
    const globalNotes = await page.locator('#sessionNotepad').inputValue();
    await openContext(page, 'Password review');
    await page.locator('#hostContextNotes').fill('Private deployment notes');
    await page.locator('#hostContextDirectories').fill('/var/log\n/etc');
    await page.locator('#hostContextSave').click();
    await expect(page.locator('#hostContextStatus')).toHaveText('Saved');
    await page.locator('#hostContextNotes').fill('Local draft retained');
    await page.evaluate(async () => {
        const token = document.querySelector('meta[name="csrf-token"]').content;
        const url = '/api/profiles/password-review/context';
        const current = await (await fetch(url)).json();
        await fetch(url, {method: 'PUT', headers: {'Content-Type': 'application/json', 'X-CSRFToken': token}, body: JSON.stringify({...current, notes: 'Changed elsewhere'})});
    });
    await page.locator('#hostContextSave').click();
    await expect(page.locator('#hostContextStatus')).toContainText('changed elsewhere');
    await expect(page.locator('#hostContextNotes')).toHaveValue('Local draft retained');
    await page.locator('#hostContextClose').click();
    await openContext(page, 'Ops first');
    await expect(page.locator('#hostContextNotes')).toHaveValue('');
    await page.locator('#hostContextClose').click();
    await openContext(page, 'Password review');
    await expect(page.locator('#hostContextNotes')).toHaveValue('Local draft retained');
    await page.locator('#hostContextReload').click();
    await expect(page.locator('#hostContextNotes')).toHaveValue('Changed elsewhere');
    await page.reload();
    await openContext(page, 'Password review');
    await expect(page.locator('#hostContextDirectories')).toHaveValue('/var/log\n/etc');
    await expect(page.locator('#sessionNotepad')).toHaveValue(globalNotes);
});

test('active session context rejects stale actions and explains ad-hoc sessions at mobile size', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await login(page);
    await page.evaluate(() => {
        SessionManager.sessions['context-fixture'] = {id: 'context-fixture', host: 'password.local', port: 22,
            username: 'passworduser', connected: true, profileId: 'password-review'};
        SessionManager.activeSessionId = 'context-fixture';
        window.HostContext.openActive();
    });
    await expect(page.locator('#hostContextTarget')).toHaveText('passworduser@password.local:22');
    await page.locator('#hostContextDirectories').fill('/logs');
    await page.locator('#hostContextSave').click();
    await expect(page.locator('#hostContextStatus')).toHaveText('Saved');
    await page.evaluate(() => { SessionManager.activeSessionId = null; });
    await page.locator('#hostContextLaunchers button').click();
    await expect(page.locator('#hostContextStatus')).toContainText('active SSH session changed');
    await page.locator('#hostContextClose').click();
    await page.evaluate(() => {
        SessionManager.sessions['context-fixture'].profileId = null;
        SessionManager.activeSessionId = 'context-fixture';
        window.HostContext.openActive();
    });
    await expect(page.locator('#hostContextEmpty')).toBeVisible();
    await expect(page.locator('#hostContextFields')).toBeHidden();
    expect(await page.locator('#hostContextModal .modal-content').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
});

test('favorites navigate the bound SFTP source and assigned sets use the existing SSH input launcher', async ({page}) => {
    await login(page);
    await expect.poll(() => page.evaluate(() => window.CommandSetManager.commandSets.some(item => item.id === 'e2e-command-set'))).toBe(true);
    await page.evaluate(() => {
        SessionManager.sessions['context-action'] = {id: 'context-action', host: 'password.local', port: 22,
            username: 'passworduser', connected: true, profileId: 'password-review'};
        SessionManager.activeSessionId = 'context-action';
        window.__contextActions = [];
        const fm = window.getSFTPFileManager();
        fm.open = () => {};
        fm.onSourceChange = async (_pane, source) => { window.__contextActions.push(['source', source]); };
        fm.getPaneSourceId = () => 'sftp-session:context-action';
        fm.navigatePaneTo = async (pane, path) => { window.__contextActions.push(['directory', pane, path]); };
        window.SSHInput = {...window.SSHInput, send: async (id, data) => { window.__contextActions.push(['input', id, data]); return true; }};
        window.HostContext.openActive();
    });
    await expect(page.locator('#hostContextFields')).toBeVisible();
    await page.locator('#hostContextDirectories').fill('/var/log');
    await page.locator('#hostContextSets label').filter({hasText: /^E2E command set$/}).locator('input').check();
    await page.locator('#hostContextSave').click();
    await expect(page.locator('#hostContextStatus')).toHaveText('Saved');
    await page.locator('#hostContextLaunchers button').click();
    await expect.poll(() => page.evaluate(() => window.__contextActions)).toEqual([
        ['source', 'sftp-session:context-action'], ['directory', 'left', '/var/log']]);
    await page.evaluate(() => window.HostContext.openActive());
    await page.locator('.host-context-set').filter({hasText: 'E2E command set'}).getByRole('button').click();
    await expect(page.locator('#sessionCommandsMount')).toContainText('E2E command set');
    await page.locator('#session-command-tab-sets').click();
    await page.locator('.session-command-item').filter({hasText: 'E2E command set'}).locator('.btn-primary').click();
    await expect.poll(() => page.evaluate(() => window.__contextActions.at(-1))).toEqual(['input', 'context-action', 'printf set']);
});
