// ID1 acceptance: LDAP sign-in against the OpenLDAP server of the test lab,
// with auto-provisioning, the administrator's identity view, unlink with a
// new local password and a new link. Runs against Python by default and
// against the Go server through WEBSSH_E2E_M1_SERVER_COMMAND
// (tests/e2e/README.md).
const fs = require('node:fs');
const path = require('node:path');
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure} = require('../m1/backend');
const {loadLab} = require('../m1/lab');
const ui = require('../m1/ui');

const admin = {username: 'm2admin', password: 'M2-ldap-admin-password-7'};
const localPassword = 'Alice-local-password-9';

let backend;
let lab;

// The directory files of the secret volume, with the modes the secret
// rules require (the lab writes 0644).
function ldapEnvironment() {
    const ldap1 = lab.service('ldap1');
    const dir = path.join(backend.root, 'webssh-auth');
    fs.mkdirSync(dir, {mode: 0o700});
    const passwordFile = path.join(dir, 'ldap_bind_password');
    fs.writeFileSync(passwordFile, `${lab.secret(ldap1.bind.password_file)}\n`, {mode: 0o600});
    const caFile = path.join(dir, 'ldap_ca.pem');
    fs.copyFileSync(lab.caFile, caFile);
    return {
        LDAP_ENABLED: 'true', LDAP_AUTO_PROVISION: 'true', LDAP_PROVIDER_ID: 'lab-directory',
        LDAP_URL: `ldap://${ldap1.host}:${ldap1.port}`, LDAP_BASE_DN: ldap1.base_dn, LDAP_BIND_DN: ldap1.bind.dn,
        LDAP_BIND_PASSWORD_FILE: passwordFile, LDAP_CA_FILE: caFile, LDAP_USER_FILTER: ldap1.user_filter,
        LDAP_UNIQUE_ID_ATTRIBUTE: ldap1.unique_id_attribute, LDAP_LOGIN_RATE_LIMIT: '100 per minute',
    };
}

// The directory form is shown first while LDAP is on; the local form is
// one choice away (ui.signIn expects the local form).
async function signInLocally(page, username, password) {
    await page.goto('/login');
    await page.locator('#authenticationSource').selectOption('local');
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#localLoginForm button[type="submit"]').click();
}

async function signInWithDirectory(page, username, password) {
    await page.goto('/login');
    await page.locator('#authenticationSource').selectOption('ldap');
    await page.locator('#ldapUsername').fill(username);
    await page.locator('#ldapPassword').fill(password);
    await page.locator('#ldapLoginForm button[type="submit"]').click();
}

async function openLdapAction(page, username) {
    await page.goto('/admin');
    const row = page.locator('#adminUsersBody tr').filter({hasText: username});
    await expect(row).toBeVisible();
    await row.locator('.admin-action-menu > summary').click();
    await row.locator('button[data-act="ldap-link"]').click();
    await expect(page.locator('#securityActionModal')).toHaveClass(/show/);
    await page.locator('#securityActionConfirmation').fill(username);
}

test.beforeAll(async () => {
    lab = loadLab();
    backend = freshBackend('ldap');
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

test('a directory user signs in, is unlinked to a local account and linked again', async ({browser}) => {
    const alicePassword = lab.password('ldap1', 0);

    await test.step('the server starts with LDAP from the secret volume', async () => {
        const result = await backend.createAdmin(admin.username, admin.password);
        expect(result.code, result.output).toBe(0);
        await backend.start(ldapEnvironment());
    });

    const adminContext = await browser.newContext({baseURL: backend.baseURL});
    const adminPage = await adminContext.newPage();
    await signInLocally(adminPage, admin.username, admin.password);
    await expect(adminPage).toHaveURL(/\/$/);
    await ui.dismissTour(adminPage);

    const aliceContext = await browser.newContext({baseURL: backend.baseURL});
    const alice = await aliceContext.newPage();

    await test.step('a wrong directory password is refused under the directory form', async () => {
        await signInWithDirectory(alice, 'alice', 'not-the-password');
        await expect(alice.locator('#ldapLoginForm')).toContainText('Invalid username or password');
        await expect(alice.locator('#authenticationSource')).toHaveValue('ldap');
    });

    await test.step('the directory password signs alice in and provisions her account', async () => {
        await signInWithDirectory(alice, ' alice ', alicePassword);
        await expect(alice).toHaveURL(/\/$/);
        await ui.dismissTour(alice);
    });

    await test.step('the administrator sees the LDAP identity and unlinks it with a new password', async () => {
        await openLdapAction(adminPage, 'alice');
        await expect(adminPage.locator('#securityActionDirectoryUsername')).toHaveValue('alice');
        await expect(adminPage.locator('#securityActionNewPasswordGroup')).not.toHaveClass(/hidden/);
        await adminPage.locator('#securityActionNewPassword').fill(localPassword);
        await adminPage.locator('#submitSecurityAction').click();
        expect(await ui.answerStepUp(adminPage, admin.password, {timeout: 10_000})).toBe(true);
        await expect(adminPage.locator('.notification, .toast, [role="status"]').filter({hasText: 'LDAP identity unlinked'}).first()).toBeVisible();
    });

    await test.step('the unlink ended alice\'s session; she signs in with the local password', async () => {
        await alice.goto('/');
        await expect(alice).toHaveURL(/\/login/);
        await signInLocally(alice, 'alice', localPassword);
        await expect(alice).toHaveURL(/\/$/);
        await ui.dismissTour(alice);
        await ui.signOut(alice);
    });

    await test.step('the administrator links the directory identity again', async () => {
        await openLdapAction(adminPage, 'alice');
        await expect(adminPage.locator('#securityActionNewPasswordGroup')).toHaveClass(/hidden/);
        await adminPage.locator('#securityActionDirectoryUsername').fill('alice');
        await adminPage.locator('#submitSecurityAction').click();
        expect(await ui.answerStepUp(adminPage, admin.password, {timeout: 10_000})).toBe(true);
        await expect(adminPage.locator('.notification, .toast, [role="status"]').filter({hasText: 'LDAP identity linked'}).first()).toBeVisible();
    });

    await test.step('the local password stops working, the directory password works', async () => {
        await signInLocally(alice, 'alice', localPassword);
        await expect(alice.locator('body')).toContainText('Invalid username or password');
        await signInWithDirectory(alice, 'alice', alicePassword);
        await expect(alice).toHaveURL(/\/$/);
    });

    await adminContext.close();
    await aliceContext.close();
});
