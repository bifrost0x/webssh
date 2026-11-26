// M1 acceptance: a DATA_DIR written by the Python release through its own
// interface (python-data-dir.js) is taken over. Against the Go server this
// is the first-start migration; against Python it is the same release
// starting again on its data, which keeps the journey checked on main.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {test, expect} = require('playwright/test');
const {backendFromDataDir, removeScratch, attachLogOnFailure, kind} = require('./backend');
const {createPythonDataDir} = require('./python-data-dir');
const {loadLab} = require('./lab');
const ui = require('./ui');

test.describe.configure({mode: 'serial'});

// Paths of DATA_DIR that are not legacy data (migration spec, section 2):
// the Go directory and runtime state.
const notLegacy = name => ['go', 'logs', 'tmp', '.access-revocations', '.ldap-revocation-fences'].includes(name)
    || name.startsWith('.webssh-ready-');

function legacyListing(dataDir) {
    const listing = {};
    const walk = (directory, prefix) => {
        for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
            if (!prefix && notLegacy(entry.name)) continue;
            const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
            const full = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(full, relative);
            else listing[relative] = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
        }
    };
    walk(dataDir, '');
    return listing;
}

let fixture;
let backend;
let before;

test.beforeAll(async ({browser}) => {
    test.setTimeout(300_000);
    fixture = await createPythonDataDir(browser);
    backend = backendFromDataDir('migrated', fixture.dataDir);
    removeScratch(fixture.root);
    before = legacyListing(backend.dataDir);
    await backend.start();
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

test('the previous password and TOTP sign in, and hosts, key and host key are there', async ({browser}) => {
    const lab = loadLab();
    const context = await browser.newContext({baseURL: backend.baseURL});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    await ui.signIn(page, fixture.username, fixture.password, {totpSecret: fixture.totpSecret, usedSteps: fixture.usedSteps});

    await ui.openHosts(page);
    await expect(ui.hostRow(page, fixture.hosts.key)).toBeVisible();
    await expect(ui.hostRow(page, fixture.hosts.password)).toBeVisible();
    await ui.hostRow(page, fixture.hosts.key).click();
    await expect(page.locator('#profileEditorUsername')).toHaveValue('keyuser');
    await expect(page.locator('#profileEditorAuthType')).toHaveValue('key');
    await expect(page.locator('#profileEditorKeySelect option:checked')).toContainText(fixture.keyName);
    await page.reload();
    await ui.dismissTour(page);

    await ui.watchHostKeyPrompts(page);
    const session = await ui.connectSavedHost(page, fixture.hosts.key);
    expect(await ui.hostKeyPrompts(page)).toEqual([]);
    await ui.shellRoundTrip(page, session, 'm1-migrated');
    await expect.poll(() => ui.terminalText(page, session)).toMatch(/ssh-modern/);
    await ui.closeSessionTab(page, session);
    expect(lab.fingerprints('ssh-modern').length).toBeGreaterThan(0);
    expect(errors).toEqual([]);
    await context.close();
});

test('the migration report records the taken-over data and what stays in place', async () => {
    test.skip(kind !== 'go', 'the migration report is written by the Go server');
    const goDirectory = path.join(backend.dataDir, 'go');
    const reports = fs.readdirSync(goDirectory).filter(name => /^migration-report-.+\.json$/.test(name));
    expect(reports).toHaveLength(1);
    const file = path.join(goDirectory, reports[0]);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    const report = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(report).toMatchObject({format: 'webssh-migration-report', version: 1, result: 'completed', error: null});
    expect(report.legacy_untouched.equal).toBe(true);

    const written = Object.fromEntries(report.entities.map(entry => [entry.entity, entry.written]));
    // E01 account, E08 TOTP, E19 hosts, E23 key; the accepted host key is
    // per user (E24) in the Python release.
    expect(written.E01).toBeGreaterThanOrEqual(1);
    expect(written.E08).toBeGreaterThanOrEqual(1);
    expect(written.E19).toBeGreaterThanOrEqual(2);
    expect(written.E23).toBeGreaterThanOrEqual(1);
    expect((written.E24 || 0) + (written.E17 || 0)).toBeGreaterThanOrEqual(1);

    const covered = new Map(report.coverage.map(entry => [entry.entity, entry.kind]));
    for (const entity of ['E01', 'E08', 'E19', 'E23']) expect(covered.get(entity), entity).toBe('step');
    for (const pending of report.pending) {
        expect(pending.entity).toMatch(/^E\d+$/);
        expect(pending.phase).toMatch(/\S/);
        expect(pending.count).toBeGreaterThanOrEqual(0);
        expect(covered.get(pending.entity), pending.entity).toBe('keep_in_place_pending');
        expect(written[pending.entity] ?? 0, pending.entity).toBe(0);
    }
    // The report never carries secrets of the fixture account.
    const text = fs.readFileSync(file, 'utf8');
    for (const secret of [fixture.password, fixture.totpSecret]) expect(text).not.toContain(secret);
});

test('the legacy data is left unchanged', async () => {
    test.skip(kind !== 'go', 'the Python release keeps writing its own data');
    expect(legacyListing(backend.dataDir)).toEqual(before);
});
