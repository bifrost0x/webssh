// TM1 acceptance (D6): a persistent tmux session on ssh-modern of the test
// lab survives a restart of the server. After the restart the page lists
// it, the user reattaches with the password and finds the shell state of
// before. Startup commands run once, in the new session, and not on the
// reattach. Runs against Python by default and against the Go server
// through WEBSSH_E2E_M1_SERVER_COMMAND (tests/e2e/README.md).
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure} = require('../m1/backend');
const {loadLab} = require('../m1/lab');
const ui = require('../m1/ui');

const admin = {username: 'm2tmux', password: 'M2-tmux-admin-password-7'};

let backend;
let lab;

test.beforeAll(async () => {
    lab = loadLab();
    backend = freshBackend('tmux');
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

// Counts the lines of the terminal that equal text exactly; tmux may
// redraw a screen, so a line can appear more than once.
async function linesEqual(page, sessionId, text) {
    const all = await ui.terminalText(page, sessionId) || '';
    return all.split('\n').filter(line => line.trim() === text).length;
}

test('a persistent tmux session is listed and reattached after a restart', async ({browser}) => {
    const modern = lab.service('ssh-modern');
    const password = lab.password('ssh-modern', 'pwuser');
    const marker = `tm1-${Date.now().toString(36)}`;

    await test.step('the server starts', async () => {
        const result = await backend.createAdmin(admin.username, admin.password);
        expect(result.code, result.output).toBe(0);
        await backend.start();
    });

    let context = await browser.newContext({baseURL: backend.baseURL});
    let page = await context.newPage();
    let first;

    await test.step('a saved host with tmux and a startup command opens a tmux session', async () => {
        await ui.signIn(page, admin.username, admin.password);
        await ui.openHosts(page);
        await page.locator('#newProfileBtn').click();
        await ui.fillHostEditor(page, {name: 'Lab tmux', host: modern.host, port: modern.port, username: 'pwuser'});
        await page.locator('#profileAdvancedSettingsCard > summary').click();
        await page.locator('#profileEditorUseTmux').check();
        await page.locator('#profileEditorPostConnectMode').selectOption('free_text');
        await page.locator('#profileEditorStartupCommands').fill(`export TM1MARK=${marker}; echo run >> /tmp/${marker}; echo START-$((40+2))`);
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        await expect(ui.hostRow(page, 'Lab tmux')).toBeVisible();
        first = await ui.connectSavedHost(page, 'Lab tmux', {
            password, acceptHostKeys: 1, fingerprints: lab.fingerprints('ssh-modern'),
        });
        await expect.poll(() => linesEqual(page, first, 'START-42'), {timeout: 20_000}).toBeGreaterThan(0);
        const session = await page.evaluate(id => SessionManager.sessions[id], first);
        expect(session.useTmux).toBe(true);
        expect(session.tmuxSessionName).toMatch(/^[A-Za-z0-9_]{1,190}$/);
        await ui.shellRoundTrip(page, first, 'tm1-before');
    });

    const tmuxName = await page.evaluate(id => SessionManager.sessions[id].tmuxSessionName, first);
    await context.close();

    await test.step('the server restarts', async () => {
        await backend.stop();
        await backend.start();
    });

    context = await browser.newContext({baseURL: backend.baseURL});
    page = await context.newPage();
    let second;

    await test.step('the page lists the persistent session and reattaches to it', async () => {
        await ui.signIn(page, admin.username, admin.password);
        await expect.poll(() => page.evaluate(() => Object.values(SessionManager.sessions)
            .filter(s => s.isPersistentCandidate).map(s => s.tmuxSessionName)), {timeout: 20_000}).toEqual([tmuxName]);
        const before = await ui.sessionIds(page);
        await page.evaluate(id => SessionManager.requestReconnect(id), first);
        const modal = page.locator('#connectionModal');
        await expect(modal).toHaveClass(/show/);
        await expect(page.locator('#useTmuxCheck')).toBeChecked();
        await page.locator('#passwordInput').fill(password);
        await page.locator('#connectBtn').click();
        await expect.poll(async () => {
            const ids = (await ui.sessionIds(page)).filter(id => !before.includes(id));
            second = ids[0];
            return ids.length;
        }, {timeout: 30_000}).toBe(1);
        expect(await page.evaluate(id => SessionManager.sessions[id].tmuxSessionName, second)).toBe(tmuxName);
    });

    await test.step('the shell state is that of before and the startup command did not run again', async () => {
        await ui.shellRoundTrip(page, second, 'tm1-after');
        const term = page.locator(`#terminal-${second} .xterm-helper-textarea`);
        await term.focus();
        // Every run of the startup command appends a line to the file.
        await page.keyboard.type(`echo "M=$TM1MARK RUNS=$(wc -l < /tmp/${marker})"; rm -f /tmp/${marker}\n`);
        await expect.poll(() => linesEqual(page, second, `M=${marker} RUNS=1`), {timeout: 15_000}).toBeGreaterThan(0);
    });

    await test.step('closing the tab ends the persistent session', async () => {
        await ui.closeSessionTab(page, second);
        await page.reload();
        await ui.dismissTour(page);
        await expect.poll(() => page.evaluate(() => Object.values(SessionManager.sessions)
            .filter(s => s.isPersistentCandidate).length), {timeout: 10_000}).toBe(0);
    });
    await context.close();
});
