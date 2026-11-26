// M1 acceptance: a new installation from the first administrator to SSH
// sessions on the test lab. Runs against Python by default and against the
// Go server through WEBSSH_E2E_SERVER_COMMAND (tests/e2e/README.md).
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure, kind} = require('./backend');
const {loadLab} = require('./lab');
const ui = require('./ui');

const admin = {username: 'm1admin', password: 'M1-fresh-admin-password-7'};

let backend;
let lab;

test.beforeAll(async () => {
    lab = loadLab();
    backend = freshBackend('fresh');
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

test('a new installation goes from create-admin to key-based SSH through a bastion', async ({browser}) => {
    const usedSteps = new Set();
    let totpSecret;

    await test.step('create-admin prepares the first administrator before the first start', async () => {
        const result = await backend.createAdmin(admin.username, admin.password);
        expect(result.code, result.output).toBe(0);
        expect(result.output).toContain(`Administrator created: ${admin.username}`);
        await backend.start();
    });

    const context = await browser.newContext({baseURL: backend.baseURL});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await test.step('the administrator signs in with the password', async () => {
        await ui.signIn(page, admin.username, admin.password);
    });

    await test.step('TOTP is activated, enrolled and required at the next sign-in', async () => {
        await ui.enableSecurityFeature(page, 'totp', admin.password);
        totpSecret = await ui.enrolTotp(page, admin.password, usedSteps);
        await ui.signOut(page);
        await ui.signIn(page, admin.username, admin.password, {totpSecret, usedSteps});
    });

    const modern = lab.service('ssh-modern');
    const pwPassword = lab.password('ssh-modern', 'pwuser');
    let firstSession;

    await test.step('a saved host on ssh-modern asks for its host key once and runs a shell', async () => {
        await ui.createHost(page, {name: 'Lab modern', host: modern.host, port: modern.port, username: 'pwuser'});
        await ui.watchHostKeyPrompts(page);
        firstSession = await ui.connectSavedHost(page, 'Lab modern', {
            password: pwPassword, acceptHostKeys: 1, fingerprints: lab.fingerprints('ssh-modern'),
        });
        const prompts = await ui.hostKeyPrompts(page);
        expect(prompts).toHaveLength(1);
        expect(prompts[0]).toMatchObject({host: modern.host, port: modern.port});
        await ui.shellRoundTrip(page, firstSession, 'm1-first');
    });

    await test.step('a reload resumes the running session', async () => {
        await page.reload();
        await expect.poll(() => ui.sessionIds(page), {timeout: 20_000}).toContain(firstSession);
        await expect.poll(() => ui.terminalText(page, firstSession), {timeout: 20_000}).toContain('m1-first-42');
        await ui.shellRoundTrip(page, firstSession, 'm1-resumed');
    });

    await test.step('closing the session ends it', async () => {
        await ui.closeSessionTab(page, firstSession);
        await page.reload();
        await ui.dismissTour(page);
        expect(await ui.sessionIds(page)).not.toContain(firstSession);
    });

    await test.step('the second connection trusts the stored host key without asking', async () => {
        await ui.watchHostKeyPrompts(page);
        const session = await ui.connectSavedHost(page, 'Lab modern', {password: pwPassword});
        expect(await ui.hostKeyPrompts(page)).toEqual([]);
        await ui.shellRoundTrip(page, session, 'm1-second');
        await ui.closeSessionTab(page, session);
    });

    await test.step('an uploaded key connects through ssh-bastion to the internal host', async () => {
        const steppedUp = await ui.uploadKey(page, {
            name: 'Lab ed25519', content: lab.clientKey('ed25519'), password: admin.password,
        });
        // The Go server asks for a fresh confirmation before it stores a key
        // (step-up action key.upload); Python accepts a signed-in upload.
        if (kind === 'go') expect(steppedUp).toBe(true);
        const bastion = lab.service('ssh-bastion');
        const inner = lab.service('ssh-inner');
        await ui.createJumpHost(page, {
            name: 'Lab bastion', host: bastion.host, port: bastion.port, username: 'keyuser', key: 'Lab ed25519',
        });
        await ui.createHost(page, {
            name: 'Lab inner', host: inner.internal_host, port: inner.internal_port, username: 'keyuser',
            auth: 'key', key: 'Lab ed25519', jumpHost: 'Lab bastion',
        });
        await ui.watchHostKeyPrompts(page);
        const session = await ui.connectSavedHost(page, 'Lab inner', {
            acceptHostKeys: 2, fingerprints: [...lab.fingerprints('ssh-bastion'), ...lab.fingerprints('ssh-inner')],
        });
        const prompts = await ui.hostKeyPrompts(page);
        expect(prompts.map(prompt => prompt.context).sort()).toEqual(['jump_host', 'target']);
        await ui.shellRoundTrip(page, session, 'm1-inner');
        await expect.poll(() => ui.terminalText(page, session)).toMatch(/ssh-inner/);
        await ui.closeSessionTab(page, session);
    });

    expect(errors).toEqual([]);
    await context.close();
});
