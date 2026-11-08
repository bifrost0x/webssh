const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');

// A saved host behind a password jump host, both with assigned saved passwords.
async function setup(page, {assignTarget = true, assignJump = true} = {}) {
    await login(page, 'e2e_admin', {workspace: false});
    const {profile, jump} = await page.evaluate(() => {
        const base = ProfileManager.profiles.find(item => !item.key_id && !item.jump_host_id && item.auth_type === 'password');
        const jump = {id: 'auto-jump', name: 'Bastion', host: 'bastion.example', port: 22, username: 'ops', auth_type: 'password'};
        JumpHostManager.setJumpHosts([...JumpHostManager.jumpHosts, jump]);
        const profile = {...base, id: 'auto-routed', name: 'Routed host', host: 'routed.example', jump_host_id: jump.id};
        ProfileManager.setProfiles([...ProfileManager.profiles, profile]);
        return {profile, jump};
    });
    const uses = [];
    if (assignTarget) uses.push({id: 'target-password', name: 'Target', uses: [{resource_id: profile.id, valid: true}]});
    if (assignJump) uses.push({id: 'jump-password', name: 'Bastion', uses: [{resource_id: `jump:${jump.id}`, valid: true}]});
    await page.route('**/api/credentials/state', route => route.fulfill({json: {enabled: true,
        profiles: [{...profile, kind: 'ssh'}, {...jump, id: `jump:${jump.id}`, kind: 'jump'}], credentials: uses}}));
    await page.route('**/api/credentials/intents', route => route.fulfill({json: {intent: 'auto-intent'}}));
    await page.route('**/api/credentials/authorize-target', route => route.fulfill({json: {credential_target_token: 'auto-token'}}));
    await installSshConnectTrap(page);
    return {profile, jump};
}

test('a host whose target and jump host passwords are assigned connects without a click', async ({page}) => {
    const {profile, jump} = await setup(page);
    await page.evaluate(id => window.launchProfileForPane(id), profile.id);
    await expect.poll(() => page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    const [{payload: attempt}] = await page.evaluate(() => window.__sshConnectAttempts);
    expect(attempt.profile_id).toBe(profile.id);
    expect(attempt.credential_id).toBe('target-password');
    expect(attempt.proxy_jump).toMatchObject({jump_host_id: jump.id, credential_id: `jump:${jump.id}`});
    expect(attempt.proxy_jump.password).toBeUndefined();
    await assertNoExternalRequests(page);
});

test('without an assigned jump host password the form stays open for input', async ({page}) => {
    const {profile} = await setup(page, {assignJump: false});
    await page.evaluate(id => window.launchProfileForPane(id), profile.id);
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.waitForTimeout(800);
    expect(await page.evaluate(() => window.__sshConnectAttempts.length)).toBe(0);
});

test('reconnecting a jump host session fills the assigned jump host password by itself', async ({page}) => {
    const {jump} = await setup(page, {assignTarget: false});
    await page.evaluate(jumpId => {
        SessionManager.sessions['auto-reconnect'] = {id: 'auto-reconnect', host: 'routed.example', port: 22, username: 'deploy',
            connected: false, authType: 'password', jumpHostId: jumpId, viaJump: true, reconnectRouteKnown: true};
        SessionManager.requestReconnect('auto-reconnect');
    }, jump.id);
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#jumpHostSelect')).toHaveValue(jump.id);
    await expect(page.locator('#jumpHostPasswordInput')).toBeDisabled();
    await expect.poll(() => page.evaluate(() => window.CredentialPicker.get('jumpHostPasswordInput'))).toBe(`jump:${jump.id}`);
});
