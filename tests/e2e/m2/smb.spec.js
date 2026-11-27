// FS3 acceptance: SMB shares of the test lab's Samba through the file
// workspace of the Go server: a wrong password, an encrypted share with
// write access, a folder created and removed on the server, the read-only
// share and a saved definition without its password.
//
// The lab's Samba listens on a published port instead of 445, so the spec
// needs the end-to-end build, which points SMB connections at that port
// (WEBSSH_E2E_SMB_PORT, cmd/webssh/e2e.go):
//   WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh-e2e serve' \
//   WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh-e2e' \
//   npx playwright test -c tests/e2e/m2/playwright.config.js smb.spec.js
const crypto = require('node:crypto');
const {test, expect} = require('playwright/test');
const {kind, freshBackend, attachLogOnFailure} = require('../m1/backend');
const {loadLab} = require('../m1/lab');
const ui = require('../m1/ui');

const admin = {username: 'm2smb', password: 'M2-smb-admin-password-7'};

let backend;
let lab;
let samba;

test.skip(kind !== 'go', 'the lab Samba is reachable only through the SMB port of the Go end-to-end build');

test.beforeAll(async () => {
    lab = loadLab();
    samba = lab.service('samba');
    backend = freshBackend('smb');
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start({
        SMB_ENABLED: 'true', SMB_ALLOWED_TARGETS: samba.host, WEBSSH_E2E_SMB_PORT: String(samba.port),
        SMB_CONNECT_RATELIMIT: '100 per minute',
    });
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

const smbUser = () => samba.users.find(user => user.username === 'smbuser');
const smbPassword = () => lab.secret(smbUser().password_file);

// Opens the file workspace and the SMB dialog of the left pane.
async function openSmbDialog(page) {
    await page.evaluate(() => openFileManager());
    await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
    const launcher = page.locator('#fmNewSmbSource');
    await expect(launcher).toBeEnabled();
    await launcher.click();
    await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
}

async function fillShare(page, share, password) {
    await page.locator('#smbSourceHost').fill(samba.host);
    await page.locator('#smbSourceShare').fill(share);
    await page.locator('#smbSourceDomain').fill(smbUser().domain);
    await page.locator('#smbSourceUsername').fill(smbUser().username);
    await page.locator('#smbSourcePassword').fill(password);
}

test('a Samba share opens encrypted, takes a folder and stays read-only where the server says so', async ({browser}) => {
    const context = await browser.newContext({baseURL: backend.baseURL});
    const page = await context.newPage();
    await ui.signIn(page, admin.username, admin.password);
    const folder = `e2e-smb-${crypto.randomBytes(4).toString('hex')}`;

    await test.step('a wrong password is refused and the field is cleared', async () => {
        await openSmbDialog(page);
        await fillShare(page, 'Secure', 'not-the-password');
        await page.locator('#smbSourceConnect').click();
        await expect(page.locator('#smbSourceStatus')).toContainText('Authentication failed');
        await expect(page.locator('#smbSourcePassword')).toHaveValue('');
    });

    await test.step('the right password opens the share with SMB 3.1.1 and write access', async () => {
        await page.locator('#smbSourcePassword').fill(smbPassword());
        await page.locator('#smbSourceConnect').click();
        await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
        await expect(page.locator('#fmLeftTabs')).toContainText('Secure');
        await expect(page.locator('#fmLeftIdentity')).toContainText('Write access at share root');
        const source = await page.evaluate(() => window.sftpFileManager.panes.left.source);
        expect(source.kind).toBe('smb');
        expect(source.security).toMatchObject({encrypted: true, signed: true, secureNegotiate: true});
        expect(source.ephemeral).toBe(true);
    });

    await test.step('a new folder is created on the server and removed again', async () => {
        // The New menu offers the folder dialog (createNewFolder).
        await page.evaluate(() => window.sftpFileManager.createNewFolder());
        const dialog = page.locator('dialog.fm-mutation-dialog');
        await dialog.locator('[name="filename"]').fill(folder);
        await dialog.getByRole('button', {name: 'Create folder', exact: true}).click();
        const row = page.locator('#fmLeftList .fm-file-item').filter({hasText: folder});
        await expect(row).toBeVisible();
        await row.locator('.fm-file-name, span').filter({hasText: folder}).first().click();
        page.once('dialog', confirmation => confirmation.accept());
        await page.evaluate(() => window.sftpFileManager.deleteSelected());
        await expect(row).toHaveCount(0);
    });

    await test.step('the read-only share shows its access and offers no root mutations', async () => {
        await openSmbDialog(page);
        await fillShare(page, 'ReadOnly', smbPassword());
        await page.locator('#smbSourceConnect').click();
        await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
        await expect(page.locator('#fmLeftIdentity')).toContainText('Read-only at share root');
        await expect(page.locator('#fmNewFolder')).toBeDisabled();
    });

    await context.close();
});

test('a saved share keeps no password and reopens from the source launcher after a reload', async ({browser}) => {
    const context = await browser.newContext({baseURL: backend.baseURL});
    const page = await context.newPage();
    await ui.signIn(page, admin.username, admin.password);
    const name = `Lab files ${crypto.randomBytes(3).toString('hex')}`;

    await openSmbDialog(page);
    await fillShare(page, 'Plain', smbPassword());
    await page.locator('#smbSourceName').fill(name);
    await page.locator('#smbSourceSave').click();
    await expect(page.locator('#smbSourceSaved')).toContainText(name);
    await page.keyboard.press('Escape');

    await page.reload();
    await ui.dismissTour(page);
    await page.evaluate(() => openFileManager());
    await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
    const shares = await page.evaluate(() => window.sftpFileManager.savedSmbShares);
    const saved = shares.find(share => share.name === name);
    expect(saved).toMatchObject({host: samba.host, share: 'Plain', domain: smbUser().domain, username: smbUser().username});
    expect(JSON.stringify(shares)).not.toContain(smbPassword());
    const row = page.locator(`[data-source-key="smb-saved:${saved.id}"]`);
    await expect(row).toContainText(name);
    await row.click();
    await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
    await expect(page.locator('#smbSourceShare')).toHaveValue('Plain');
    await expect(page.locator('#smbSourcePassword')).toHaveValue('');

    await test.step('the saved definition opens with the password typed now', async () => {
        await page.locator('#smbSourcePassword').fill(smbPassword());
        await page.locator('#smbSourceConnect').click();
        await expect(page.locator('#smbSourceModal')).not.toHaveClass(/show/);
        await expect(page.locator('#fmLeftTabs')).toContainText('Plain');
    });

    await test.step('deleting the definition removes it from the launcher', async () => {
        await page.evaluate(() => window.sftpFileManager.openSourceLauncher('left'));
        await page.locator(`[data-source-key="smb-saved:${saved.id}"]`).click();
        page.once('dialog', dialog => dialog.accept());
        await page.locator('#smbSourceDeleteSaved').click();
        await expect(page.locator('#smbSourceSaved')).not.toContainText(name);
    });

    await context.close();
});
