// M1 acceptance: a passkey is registered with a virtual authenticator and
// signs in without a password. WebAuthn needs a secure context, so the
// spec uses http://localhost (the configured relying party).
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure, kind} = require('./backend');
const ui = require('./ui');

const admin = {username: 'm1passkey', password: 'M1-passkey-admin-password-9'};

let backend;

test.beforeAll(async () => {
    backend = freshBackend('passkey');
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start();
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

test('a registered passkey signs in without the password', async ({browser}) => {
    test.fixme(kind === 'go', 'Passkeys come with package D1 (internal/auth/webauthn), which is not merged yet.');
    const context = await browser.newContext({baseURL: backend.localhostURL});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
            hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
        },
    });
    try {
        await ui.signIn(page, admin.username, admin.password);
        await page.goto('/settings#factors');
        await page.locator('#passkeyAddBtn').click();
        await expect(page.locator('#securityConfirmationModal')).toHaveClass(/show/);
        await page.locator('#securityConfirmationLabel').fill('M1 passkey');
        await page.locator('#securityConfirmationSubmit').click();
        await expect(page.locator('#securityConfirmationPasswordGroup')).not.toHaveClass(/hidden/);
        await page.locator('#securityConfirmationPassword').fill(admin.password);
        await page.locator('#securityConfirmationSubmit').click();
        await expect(page.locator('#passkeyList')).toContainText('M1 passkey');
        const {credentials} = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
        expect(credentials).toHaveLength(1);

        await ui.signOut(page);
        await page.locator('.auth-method-option[data-auth-mode="passkey"]').click();
        await expect(page.locator('#passkeyLoginMode')).toBeVisible();
        const options = page.waitForResponse(response => response.url().endsWith('/api/webauthn/auth/options'));
        await page.locator('#passkeyLoginBtn').click();
        expect((await options).ok()).toBe(true);
        await expect(page).toHaveURL(/\/$/);
        await ui.dismissTour(page);
        await expect(page.locator('#accountBtnHeader')).toContainText(admin.username);
        const after = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
        expect(after.credentials[0].signCount).toBeGreaterThan(credentials[0].signCount);
    } finally {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', {authenticatorId});
        await cdp.send('WebAuthn.disable');
    }
    expect(errors).toEqual([]);
    await context.close();
});
