// VA1 acceptance (W2F-3): saved passwords against the test lab's
// ssh-modern. The server hands a saved password to a connection only when
// the browser reached it over HTTPS (connection_password, CredentialGuard),
// so the spec puts a TLS-terminating proxy in front of the backend
// (https-proxy.js) and trusts it as a homelab installation trusts Caddy or
// nginx. Over HTTPS a saved host and a Quick Connect target with a saved
// password open a shell without a typed password. Refused, with the
// message of the interface and without a session: a target changed after
// the page authorized it, and the same backend reached over plain HTTP.
// Runs against Python by default and against the Go server through
// WEBSSH_E2E_M1_SERVER_COMMAND (tests/e2e/README.md).
const {test, expect} = require('playwright/test');
const {kind, freshBackend, attachLogOnFailure} = require('../m1/backend');
const {loadLab} = require('../m1/lab');
const {startHttpsProxy} = require('./https-proxy');
const ui = require('../m1/ui');

const admin = {username: 'm2vault', password: 'M2-vault-admin-password-7'};
const hostName = 'Lab saved password';

let backend;
let proxy;
let lab;
let modern;
// The connection target the page sent for the saved host over HTTPS: its
// saved password and the target token the page received for it.
let authorized;

// The tests build on each other: the first saves the password the others use.
test.describe.configure({mode: 'serial'});

test.beforeAll(async () => {
    lab = loadLab();
    modern = lab.service('ssh-modern');
    backend = freshBackend('vault');
    proxy = await startHttpsProxy(backend.root, () => backend.port);
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start({
        TRUSTED_PROXIES: '1',
        TRUSTED_PROXY_CIDRS: '127.0.0.1/32',
        CORS_ORIGINS: `http://127.0.0.1:${backend.port},http://localhost:${backend.port},${proxy.url}`,
    });
});

test.afterAll(async () => {
    await proxy?.close();
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

// The connection targets the page sends, read from the socket frames:
// the target of terminal.open on Go, the ssh_connect payload of Socket.IO
// on Python. Go marks a saved password with saved_password.
function recordConnectTargets(page) {
    const opens = [];
    page.on('websocket', socket => socket.on('framesent', ({payload}) => {
        if (typeof payload !== 'string') return;
        try {
            if (payload.startsWith('{')) {
                const frame = JSON.parse(payload);
                if (frame.t === 'terminal.open') opens.push(frame.p.target);
                return;
            }
            const socketIO = /^42(?:\/[^,]*,)?(\[.*)$/s.exec(payload);
            if (!socketIO) return;
            const [event, data] = JSON.parse(socketIO[1]);
            if (event === 'ssh_connect') opens.push(data);
        } catch {
            // Not a frame of either protocol.
        }
    }));
    return opens;
}

// What every target sent with a saved password carries on both servers.
function expectSavedPasswordTarget(target, fields) {
    expect(target).toMatchObject(fields);
    expect(target.credential_id).toEqual(expect.any(String));
    if (kind === 'go') expect(target.saved_password).toBe(true);
    expect(target).not.toHaveProperty('password');
}

async function signedIn(browser, baseURL) {
    const context = await browser.newContext({baseURL, ignoreHTTPSErrors: true});
    const page = await context.newPage();
    const opens = recordConnectTargets(page);
    await ui.signIn(page, admin.username, admin.password);
    return {context, page, opens};
}

// Turns on "Save passwords" in the Settings Center (credentials_enabled,
// off on a new installation); the switch asks for a step-up.
async function allowSavedPasswords(page) {
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingCredentials');
    await expect(toggle).toBeEnabled();
    if (!await toggle.isChecked()) {
        await toggle.check();
        await ui.answerStepUp(page, admin.password, {timeout: 10_000});
    }
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    await page.goto('/');
    await ui.dismissTour(page);
}

// Drives a connection whose form already names a saved password: the
// review is confirmed as it is (no password typed), the account password
// answers the step-up that authorizes the saved password for this target
// once, and the lab host key is accepted. Returns the new session id.
async function connectWithSavedPassword(page) {
    const before = await ui.sessionIds(page);
    const modal = page.locator('#connectionModal');
    const fingerprints = lab.fingerprints('ssh-modern');
    let created = [];
    await expect.poll(async () => {
        created = (await ui.sessionIds(page)).filter(session => !before.includes(session));
        if (created.length) return 'connected';
        if (await ui.answerStepUp(page, admin.password, {timeout: 200})) return null;
        const hostKey = page.locator('#sshHostKeyModal');
        if (await hostKey.isVisible()) {
            const shown = await page.locator('#sshHostKeyFingerprint').textContent();
            expect(fingerprints.some(value => shown.includes(value)), shown).toBe(true);
            await page.locator('#sshHostKeyAccept').click();
            return null;
        }
        if (/\bshow\b/.test(await modal.getAttribute('class') || '')) {
            await expect(page.locator('#passwordInput')).toHaveValue('');
            await page.locator('#connectBtn').click({timeout: 2000}).catch(() => {});
        }
        return null;
    }, {timeout: 45_000, intervals: [500]}).toBe('connected');
    return created[0];
}

function notifications(page) {
    return page.locator('#notificationContainer');
}

test('over HTTPS a saved host signs in with its saved password and nothing is typed', async ({browser}) => {
    const {context, page, opens} = await signedIn(browser, proxy.url);
    const password = lab.password('ssh-modern', 'pwuser');
    await allowSavedPasswords(page);

    await test.step('the host is saved with a new saved password', async () => {
        await ui.openHosts(page);
        await page.locator('#newProfileBtn').click();
        await ui.fillHostEditor(page, {name: hostName, host: modern.host, port: modern.port, username: 'pwuser', auth: 'password'});
        const choice = page.locator('#profileEditorCredential');
        await expect(choice).toBeVisible();
        await choice.selectOption('__new');
        await page.locator('#profileEditorCredentialName').fill('Lab pwuser');
        await page.locator('#profileEditorCredentialPassword').fill(password);
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        await ui.answerStepUp(page, admin.password);
        await expect(ui.hostRow(page, hostName)).toBeVisible();
    });

    await test.step('the host connects without a password prompt', async () => {
        await ui.openHosts(page);
        const id = await ui.hostRow(page, hostName).getAttribute('data-profile-id');
        await page.locator(`button.profile-row-connect[data-profile-id="${id}"]`).click();
        const sessionId = await connectWithSavedPassword(page);
        await ui.shellRoundTrip(page, sessionId, 'va1-saved');
        const target = opens.at(-1);
        expectSavedPasswordTarget(target, {profile_id: id, host: modern.host, username: 'pwuser'});
        expect(Number(target.port)).toBe(modern.port);
        expect(JSON.stringify(opens)).not.toContain(password);
        authorized = target;
    });
    await context.close();
});

// Opens an empty Quick Connect form from the header.
async function openQuickConnect(page) {
    await page.locator('#shellConnectBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
}

async function fillQuickConnectWithSavedPassword(page) {
    await page.locator('#hostInput').fill(modern.host);
    await page.locator('#portInput').fill(String(modern.port));
    await page.locator('#usernameInput').fill('pwuser');
    await page.locator('#authTypeSelect').selectOption('saved-password');
    await expect(page.locator('#savedPasswordSelect option', {hasText: 'Lab pwuser'})).toHaveCount(1);
    await page.locator('#savedPasswordSelect').selectOption({label: 'Lab pwuser'});
}

test('over HTTPS a Quick Connect target signs in with a saved password chosen for it', async ({browser}) => {
    const {context, page, opens} = await signedIn(browser, proxy.url);
    await openQuickConnect(page);
    await fillQuickConnectWithSavedPassword(page);
    await expect(page.locator('#passwordInput')).toHaveValue('');
    await page.locator('#connectBtn').click();
    const sessionId = await connectWithSavedPassword(page);
    await ui.shellRoundTrip(page, sessionId, 'va1-quick');
    const target = opens.at(-1);
    expectSavedPasswordTarget(target, {credential_id: authorized.credential_id, host: modern.host, username: 'pwuser'});
    expect(target.credential_target_token).toEqual(expect.any(String));
    expect(target.profile_id ?? null).toBeNull();
    await context.close();
});

test('a target changed after the page authorized it gets no saved password', async ({browser}) => {
    const {context, page, opens} = await signedIn(browser, proxy.url);
    await openQuickConnect(page);
    await fillQuickConnectWithSavedPassword(page);
    // The page authorizes the saved password for pwuser; the request that
    // leaves it names another account of the same server with that token.
    await page.evaluate(() => {
        const emit = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, payload, ...rest) => emit(event,
            event === 'ssh_connect' ? {...payload, username: 'kiuser'} : payload, ...rest);
    });
    const before = await ui.sessionIds(page);
    await page.locator('#connectBtn').click();
    await ui.answerStepUp(page, admin.password);
    await expect(notifications(page)).toContainText('Saved credentials no longer match this connection. Review it and try again.', {timeout: 30_000});
    const target = opens.at(-1);
    expectSavedPasswordTarget(target, {username: 'kiuser', credential_id: authorized.credential_id});
    expect(target.credential_target_token).toEqual(expect.any(String));
    expect(await ui.sessionIds(page)).toEqual(before);
    await expect(page.locator('#sshHostKeyModal')).toBeHidden();
    await context.close();
});

test('over plain HTTP saved passwords are unavailable and the server sends none', async ({browser}) => {
    const {context, page, opens} = await signedIn(browser, backend.localhostURL);

    await test.step('the form says that saved passwords need HTTPS', async () => {
        await openQuickConnect(page);
        await page.locator('#hostInput').fill(modern.host);
        await page.locator('#portInput').fill(String(modern.port));
        await page.locator('#usernameInput').fill('pwuser');
        await page.locator('#authTypeSelect').selectOption('saved-password');
        await expect(page.locator('#savedPasswordGroup [role="status"]')).toHaveText('Password management requires HTTPS.');
        await expect(page.locator('#savedPasswordSelect option', {hasText: 'Lab pwuser'})).toHaveCount(0);
        await page.locator('#closeConnectionModal').click();
        await expect(page.locator('#connectionModal')).not.toHaveClass(/\bshow\b/);
    });

    await test.step('a request with the saved password and its token is refused', async () => {
        const before = await ui.sessionIds(page);
        // What the HTTPS page sent for the saved host, now over HTTP: the
        // server must not resolve the password, whatever the page claims.
        // The page shows connection errors only for the attempt its form
        // started, so the answer is read from the socket event.
        const answer = await page.evaluate(target => new Promise(resolve => {
            const requestId = `va1-http-${Date.now()}`;
            // A host key question or a session means the server signed in.
            const events = ['ssh_error', 'ssh_host_key', 'ssh_connected'];
            const listeners = events.map(event => [event, data => {
                if (event === 'ssh_error' && data?.client_request_id !== requestId) return;
                for (const [name, listener] of listeners) window.socket.off(name, listener);
                resolve({event, data});
            }]);
            for (const [name, listener] of listeners) window.socket.on(name, listener);
            window.socket.emit('ssh_connect', {
                client_request_id: requestId, host: target.host, port: target.port, username: target.username,
                auth_type: 'password', profile_id: target.profile_id, credential_id: target.credential_id,
                credential_target_token: target.credential_target_token,
            });
        }), authorized);
        expect(answer.event).toBe('ssh_error');
        // Python's CredentialGuard refuses before connection_password and
        // names the sign-in; Go names the missing HTTPS.
        expect(answer.data).toMatchObject(kind === 'go'
            ? {code: 'https_required', error: 'Saved passwords require HTTPS.'}
            : {code: 'authentication_required', error: 'Sign in again to use saved passwords.'});
        expectSavedPasswordTarget(opens.at(-1), {credential_id: authorized.credential_id, profile_id: authorized.profile_id});
        expect(await ui.sessionIds(page)).toEqual(before);
        await expect(page.locator('#sshHostKeyModal')).toBeHidden();
    });
    await context.close();
});
