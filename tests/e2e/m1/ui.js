// User journeys through the real interface, shared by the M1 specs. They
// only use what a person sees and does; checks on socket events read the
// browser's own connection object, which both servers provide.
const {expect} = require('playwright/test');
const {waitForInventory, openProfileManagement, openKeyManagement, openWorkspace} = require('../helpers');
const {freshTotp} = require('./totp');

// Signs in through /login, answers the TOTP challenge when one is asked
// for and closes the first-run tour. Ends on the workspace with the
// inventory loaded.
async function signIn(page, username, password, {totpSecret, usedSteps} = {}) {
    await page.goto('/login');
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('form button[type="submit"]').click();
    const totpPanel = page.locator('#totpMfaPanel');
    await expect(page.locator('#totpMfaPanel:visible, body[data-primary-workspace]').first()).toBeVisible();
    if (await totpPanel.isVisible()) {
        if (!totpSecret) throw new Error(`${username} was asked for a TOTP code`);
        await page.locator('#totpMfaCode').fill(await freshTotp(totpSecret, usedSteps));
        await page.locator('#submitTotpMfa').click();
    } else if (totpSecret) {
        throw new Error(`${username} signed in without the expected TOTP challenge`);
    }
    await expect(page).toHaveURL(/\/$/);
    await dismissTour(page);
    await waitForInventory(page);
}

async function dismissTour(page) {
    const tour = page.locator('.intro-tour');
    const state = await page.evaluate(async () => {
        const response = await fetch('/api/account/tour', {credentials: 'same-origin'});
        return response.ok ? (await response.json()).state : null;
    });
    if (state === 'new') {
        await expect(tour).toBeVisible();
        await tour.getByRole('button', {name: 'Skip tour', exact: true}).click();
    }
    await expect(tour).toHaveCount(0);
}

async function signOut(page) {
    if (new URL(page.url()).pathname !== '/') await page.goto('/');
    const button = page.locator('#accountBtnHeader');
    await expect(page.locator('#accountBtnHeader, #mobileMoreBtn').first()).toBeVisible();
    if (!await button.isVisible()) await page.locator('#mobileMoreBtn').click();
    await button.click();
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#logoutBtn').click();
    await expect(page).toHaveURL(/\/login$/);
}

// Completes a step-up prompt with the account password if one is shown.
// Returns whether the server asked for it.
// Answers a step-up with the account password: the administrator dialog
// (#stepUpModal) or the account confirmation that account actions such as
// a key upload open (a credential question dialog). Returns false when
// none appears within the timeout.
async function answerStepUp(page, password, {timeout = 3000} = {}) {
    const admin = page.locator('#stepUpModal');
    const account = page.locator('dialog.credential-question[open]');
    try {
        await expect(admin.or(account)).toBeVisible({timeout});
    } catch {
        return false;
    }
    if (await admin.isVisible()) {
        await page.locator('#stepUpPassword').fill(password);
        await page.locator('#stepUpSubmit').click();
        await expect(admin).toBeHidden();
        return true;
    }
    await account.locator('input[type="password"]').fill(password);
    await account.locator('button.btn-primary').click();
    await expect(account).toHaveCount(0);
    return true;
}

// Activates an admin-controlled security feature in the Settings Center.
async function enableSecurityFeature(page, feature, password) {
    await page.goto('/settings#authentication');
    const toggle = page.locator(`input[data-security-feature="${feature}"]`);
    await expect(toggle).toBeEnabled();
    if (await toggle.isChecked()) return;
    await toggle.check();
    expect(await answerStepUp(page, password, {timeout: 10_000})).toBe(true);
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
}

// Enrols an authenticator app and returns its secret.
async function enrolTotp(page, password, usedSteps) {
    await page.goto('/settings#factors');
    // From another Settings section the hash change keeps the old document;
    // load it again so it reflects features activated meanwhile.
    await page.reload();
    await page.locator('#totpAddBtn').click();
    await expect(page.locator('#securityConfirmationModal')).toHaveClass(/show/);
    await page.locator('#securityConfirmationLabel').fill('M1 authenticator');
    await page.locator('#securityConfirmationSubmit').click();
    await expect(page.locator('#securityConfirmationPasswordGroup')).not.toHaveClass(/hidden/);
    await page.locator('#securityConfirmationPassword').fill(password);
    await page.locator('#securityConfirmationSubmit').click();
    await expect(page.locator('#totpEnrollment')).not.toHaveClass(/hidden/);
    const secret = (await page.locator('#totpSecret').textContent()).trim();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    await page.locator('#totpActivationCode').fill(await freshTotp(secret, usedSteps));
    await page.locator('#totpActivateBtn').click();
    await expect(page.locator('#totpRecoveryCodes')).toContainText('will not be shown again');
    await expect(page.locator('#totpList')).toContainText('M1 authenticator');
    return secret;
}

// Counts host-key prompts the browser receives from now on.
async function watchHostKeyPrompts(page) {
    await page.evaluate(() => {
        if (window.__m1HostKeyPrompts) return;
        window.__m1HostKeyPrompts = [];
        window.socket.on('ssh_host_key', data => window.__m1HostKeyPrompts.push({
            host: data?.host, port: data?.port, context: data?.context, fingerprint: data?.fingerprint,
        }));
    });
}

async function hostKeyPrompts(page) {
    return page.evaluate(() => window.__m1HostKeyPrompts || []);
}

async function openHosts(page) {
    await openProfileManagement(page);
}

// Fills the host editor; fields left undefined keep their value.
async function fillHostEditor(page, {name, host, port, username, auth, key, jumpHost}) {
    if (name !== undefined) await page.locator('#profileEditorName').fill(name);
    if (host !== undefined) await page.locator('#profileEditorHost').fill(host);
    if (port !== undefined) await page.locator('#profileEditorPort').fill(String(port));
    if (username !== undefined) await page.locator('#profileEditorUsername').fill(username);
    if (auth !== undefined) await page.locator('#profileEditorAuthType').selectOption(auth);
    if (key !== undefined) await selectOptionContaining(page.locator('#profileEditorKeySelect'), key);
    if (jumpHost !== undefined) {
        const advanced = page.locator('#profileAdvancedSettingsCard');
        if (await advanced.getAttribute('open') === null) await advanced.locator('> summary').click();
        await selectOptionContaining(page.locator('#profileEditorJumpHostSelect'), jumpHost);
    }
}

function hostRow(page, name) {
    return page.locator('.profile-inspect-button').filter({hasText: new RegExp(`^${escapeRegExp(name)}$`)});
}

// Creates a saved host through the host manager; returns its id.
async function createHost(page, fields) {
    await openHosts(page);
    await page.locator('#newProfileBtn').click();
    await fillHostEditor(page, fields);
    await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
    const row = hostRow(page, fields.name);
    await expect(row).toBeVisible();
    return row.getAttribute('data-profile-id');
}

// Starts a saved host from its row in the host manager, answers the
// connection review and accepts the host keys the server asks about.
// Returns the new session id.
async function connectSavedHost(page, name, {password, acceptHostKeys = 0, fingerprints = []} = {}) {
    await openHosts(page);
    const before = await sessionIds(page);
    const id = await hostRow(page, name).getAttribute('data-profile-id');
    await page.locator(`button.profile-row-connect[data-profile-id="${id}"]`).click();
    const modal = page.locator('#connectionModal');
    if (password !== undefined) {
        await expect(modal).toHaveClass(/show/);
        await page.locator('#passwordInput').fill(password);
        await page.locator('#connectBtn').click();
    } else {
        // A host whose key and route are complete starts at once; confirm
        // the review only if the interface asks for one.
        let state;
        await expect.poll(async () => {
            if (/\bshow\b/.test(await modal.getAttribute('class') || '')) state = 'review';
            else if (await page.locator('#sshHostKeyModal').isVisible()) state = 'host-key';
            else if ((await sessionIds(page)).some(session => !before.includes(session))) state = 'connected';
            else state = null;
            return state;
        }, {timeout: 20_000}).not.toBeNull();
        if (state === 'review') await page.locator('#connectBtn').click();
    }
    for (let index = 0; index < acceptHostKeys; index++) {
        const prompt = page.locator('#sshHostKeyModal');
        await expect(prompt).toBeVisible({timeout: 20_000});
        const shown = await page.locator('#sshHostKeyFingerprint').textContent();
        if (fingerprints.length) expect(fingerprints.some(value => shown.includes(value)), shown).toBe(true);
        await page.locator('#sshHostKeyAccept').click();
        await expect(prompt).toBeHidden();
    }
    let created = [];
    await expect.poll(async () => {
        created = (await sessionIds(page)).filter(session => !before.includes(session));
        return created.length;
    }, {timeout: 30_000}).toBe(1);
    await expect(page.locator('#sshHostKeyModal')).toBeHidden();
    return created[0];
}

async function sessionIds(page) {
    // SessionManager and TerminalManager are global bindings of the page
    // scripts, not window properties.
    return page.evaluate(() => Object.keys(typeof SessionManager === 'undefined' ? {} : SessionManager.sessions || {}));
}

function terminalText(page, sessionId) {
    return page.evaluate(id => {
        const terminal = typeof TerminalManager === 'undefined' ? undefined : TerminalManager.terminals?.[id];
        if (!terminal) return null;
        const buffer = terminal.buffer.active;
        const lines = [];
        for (let index = 0; index < buffer.length; index++) lines.push(buffer.getLine(index).translateToString(true));
        return lines.join('\n');
    }, sessionId);
}

// Types a command into the session's terminal and waits for its output. The
// expected text is computed by the remote shell, so a local echo of the
// typed line cannot satisfy the check.
async function shellRoundTrip(page, sessionId, marker) {
    if (await page.locator('body').getAttribute('data-primary-workspace') !== 'workspaces') await openWorkspace(page);
    await page.evaluate(id => SessionManager.switchSession(id), sessionId);
    const term = page.locator(`#terminal-${cssEscape(sessionId)} .xterm-helper-textarea`);
    await term.focus();
    await page.keyboard.type(`echo ${marker}-$((40+2))\n`);
    await expect.poll(() => terminalText(page, sessionId), {timeout: 15_000}).toContain(`${marker}-42`);
}

async function closeSessionTab(page, sessionId) {
    await page.locator(`#tab-${cssEscape(sessionId)} .tab-close`).click();
    await expect.poll(() => sessionIds(page)).not.toContain(sessionId);
}

// Uploads a private key in the key manager; a step-up prompt is answered
// with the account password. Returns whether one was asked for.
async function uploadKey(page, {name, content, password}) {
    await openKeyManagement(page);
    const newButton = page.locator('#keyResourceNew');
    if (await newButton.isVisible()) await newButton.click();
    await page.locator('#keyNameInput').fill(name);
    await page.locator('#keyContentInput').fill(content);
    await page.locator('#keyUploadForm button[type="submit"]').click();
    const steppedUp = await answerStepUp(page, password);
    await expect(page.locator('#keysList')).toContainText(name, {timeout: 15_000});
    return steppedUp;
}

async function createJumpHost(page, {name, host, port, username, key}) {
    await openHosts(page);
    await page.locator('#profileManagementModal .connection-asset-nav [data-connection-asset="jump-hosts"]').click();
    await page.locator('#jumpResourceNew').click();
    await page.locator('#jhNameInput').fill(name);
    await page.locator('#jhHostInput').fill(host);
    await page.locator('#jhPortInput').fill(String(port));
    await page.locator('#jhUsernameInput').fill(username);
    if (key) {
        await page.locator('input[name="jhAuthType"][value="key"]').check();
        await selectOptionContaining(page.locator('#jhKeySelect'), key);
    }
    await page.locator('#jumpHostForm button[type="submit"]').click();
    await expect(page.locator('#jumpHostsList .key-item').filter({hasText: name})).toBeVisible();
}

// Selects the option whose label contains the text (labels add details
// such as the key type).
async function selectOptionContaining(select, text) {
    let value;
    await expect.poll(async () => {
        value = await select.evaluate((element, wanted) => [...element.options]
            .find(option => option.textContent.includes(wanted))?.value ?? null, text);
        return value;
    }).not.toBeNull();
    await select.selectOption(value);
}

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function cssEscape(value) {
    return value.replace(/[^a-zA-Z0-9_-]/g, character => `\\${character}`);
}

module.exports = {
    signIn, signOut, dismissTour, answerStepUp, enableSecurityFeature, enrolTotp,
    watchHostKeyPrompts, hostKeyPrompts, openHosts, fillHostEditor, hostRow, createHost,
    connectSavedHost, sessionIds, terminalText, shellRoundTrip, closeSessionTab, uploadKey,
    createJumpHost,
};
