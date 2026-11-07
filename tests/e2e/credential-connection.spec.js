const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');

test('Quick Connect retains the manual draft and submits a freshly authorized named password', async ({page}) => {
    await login(page);
    const profile = await page.evaluate(() => window.ProfileManager.profiles.find(item => !item.key_id && !item.jump_host_id));
    expect(profile).toBeTruthy();
    await page.route('**/api/credentials/state', route => route.fulfill({json:{enabled:true,profiles:[profile],credentials:[{id:'named-test',name:'Connection password',uses:[]}]}}));
    let authorization, intentMutation;
    await page.route('**/api/credentials/intents', route => {
        intentMutation = route.request().postDataJSON().mutation;
        return route.fulfill({json:{intent:'exact-target-intent'}});
    });
    await page.route('**/api/credentials/authorize-target', route => {
        authorization = route.request().postDataJSON();
        return route.fulfill({json:{credential_target_token:'exact-target-token'}});
    });
    await page.evaluate(id => {
        window.ProfileManager.selectProfile(id);
        window.ModalManager.open(document.getElementById('connectionModal'));
    }, profile.id);
    await page.locator('#passwordInput').fill('manual-draft');
    await page.locator('#authTypeSelect').selectOption('saved-password');
    await page.locator('#savedPasswordSelect').selectOption('named-test');
    await expect(page.locator('.credential-picker-dialog')).toHaveCount(0);
    expect(authorization).toBeUndefined();
    await page.locator('#authTypeSelect').selectOption('password');
    await expect(page.locator('#passwordInput')).toHaveValue('manual-draft');
    await page.locator('#authTypeSelect').selectOption('saved-password');
    await page.locator('#savedPasswordSelect').selectOption('named-test');
    await installSshConnectTrap(page);
    await page.locator('#connectBtn').click();
    await expect.poll(async () => page.evaluate(() => window.__sshConnectAttempts.length)).toBe(1);
    const attempts = await page.evaluate(() => window.__sshConnectAttempts);
    expect(intentMutation.method).toBe('authorize_target');
    expect(intentMutation.target).toEqual(authorization.target);
    expect(authorization.intent).toBe('exact-target-intent');
    expect(authorization.credential_id).toBe('named-test');
    expect(authorization.target.host).toBe(profile.host);
    expect(authorization.target.auth_type).toBe('password');
    expect(attempts[0].payload.credential_id).toBe('named-test');
    expect(attempts[0].payload.credential_target_token).toBe('exact-target-token');
    expect(attempts[0].payload.auth_type).toBe('password');
    expect(attempts[0].payload.profile_id).toBe(profile.id);
    expect(attempts[0].payload).not.toHaveProperty('password');
    await assertNoExternalRequests(page);
});
