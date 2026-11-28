// T4: a saved host, jump host or SOCKS5 proxy that uses an existing saved
// password binds that secret to a new destination, so the server asks for
// the account confirmation (step-up for credentials.vault). The
// confirmation comes before anything is saved: cancelling it stores
// nothing and keeps the form with its input; confirming it stores the
// record with its assignment. Saved passwords need HTTPS, so the spec puts
// the TLS proxy of saved-password.spec.js in front of a fresh backend. It
// needs no lab host: nothing connects. Runs against Python by default and
// against the Go server through WEBSSH_E2E_M1_SERVER_COMMAND.
const {test, expect} = require('playwright/test');
const {kind, freshBackend, attachLogOnFailure} = require('../m1/backend');
const {startHttpsProxy} = require('./https-proxy');
const ui = require('../m1/ui');

const admin = {username: 'm2order', password: 'M2-order-admin-password-7'};
const shared = 'Shared lab password';
const second = 'Second lab password';

let backend;
let proxy;

test.describe.configure({mode: 'serial'});

test.beforeAll(async () => {
    backend = freshBackend('order');
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

async function signedIn(browser) {
    const context = await browser.newContext({baseURL: proxy.url, ignoreHTTPSErrors: true});
    const page = await context.newPage();
    await ui.signIn(page, admin.username, admin.password);
    return {context, page};
}

// What the server holds: every resource of the credentials page with the
// password assigned to it, and the saved passwords.
async function serverState(page) {
    return page.evaluate(() => window.NativeCredentials.api('/api/credentials/state'));
}

async function resourcesNamed(page, name) {
    return (await serverState(page)).profiles.filter(resource => resource.name === name);
}

// Exactly one resource of the name, with the shared password assigned. The
// Python release assigns after the record is saved, so the check waits.
async function expectAssigned(page, name) {
    await expect.poll(async () => {
        const state = await serverState(page);
        const credential = state.credentials.find(item => item.name === shared);
        return state.profiles.filter(resource => resource.name === name)
            .map(resource => [resource.credential_id === credential.id, resource.credential_status]);
    }, {timeout: 10_000}).toEqual([[true, 'ready']]);
}

const stepUpDialog = page => page.locator('dialog.credential-question[open]');

async function cancelStepUp(page) {
    const dialog = stepUpDialog(page);
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', {name: 'Cancel', exact: true}).click();
    await expect(dialog).toHaveCount(0);
}

test('saved passwords are on and one saved password exists', async ({browser}) => {
    const {context, page} = await signedIn(browser);
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingCredentials');
    await expect(toggle).toBeEnabled();
    if (!await toggle.isChecked()) {
        await toggle.check();
        await ui.answerStepUp(page, admin.password, {timeout: 10_000});
    }
    await expect(toggle).toBeChecked();
    await page.goto('/');
    await ui.dismissTour(page);
    // A new password without a destination binds nothing and needs no
    // confirmation.
    await page.evaluate(names => Promise.all(names.map(name =>
        window.NativeCredentials.mutate('create', {name, username: 'lab', password: 'synthetic-lab-pw'}))), [shared, second]);
    expect((await serverState(page)).credentials.map(item => item.name).sort()).toEqual([second, shared].sort());
    await context.close();
});

test('a saved password name in use is refused at the name field', async ({browser}) => {
    test.fail(kind === 'python', 'the Python release allows duplicate names (U74)');
    const {context, page} = await signedIn(browser);
    const before = (await serverState(page)).credentials.map(item => item.id);
    try {
        await page.evaluate(() => window.openConnectionAssetManager('passwords'));
        await page.locator('[data-credential-new]').click();
        const detail = page.locator('[data-credential-detail]');
        await detail.locator('[name=name]').fill(`  ${shared.toUpperCase()} `);
        await detail.locator('[name=password]').fill('another-synthetic-pw');
        await detail.getByRole('button', {name: 'Save', exact: true}).click();
        await expect(detail.locator('.form-error')).toHaveText('This name is already in use. Choose another name.');
        await expect(detail.locator('[name=name]')).toBeFocused();
        expect((await serverState(page)).credentials).toHaveLength(2);
    } finally {
        // What a backend without the rule stored must not reach the next tests.
        await page.evaluate(async keep => {
            const state = await window.NativeCredentials.api('/api/credentials/state');
            for (const item of state.credentials.filter(entry => !keep.includes(entry.id))) {
                await window.NativeCredentials.mutate('delete', {}, item.id);
            }
        }, before);
        await context.close();
    }
});

for (const button of ['Save', 'Save & connect']) {
    test(`${button}: cancelling the confirmation stores no host and keeps the form`, async ({browser}) => {
        const {context, page} = await signedIn(browser);
        const name = `Order host ${button}`;
        await ui.openHosts(page);
        await page.locator('#newProfileBtn').click();
        await ui.fillHostEditor(page, {name, host: 'order.example.test', port: 22, username: 'lab', auth: 'password'});
        await expect(page.locator(`#profileEditorCredential option`, {hasText: shared})).toHaveCount(1);
        await page.locator('#profileEditorCredential').selectOption({label: shared});
        await page.locator('#profileEditorForm').getByRole('button', {name: button, exact: true}).click();
        await expect(stepUpDialog(page)).toBeVisible();
        // Nothing is stored while the confirmation is open.
        expect(await resourcesNamed(page, name)).toEqual([]);
        await cancelStepUp(page);
        await expect(page.locator('#profileEditorView')).toBeVisible();
        await expect(page.locator('#profileEditorName')).toHaveValue(name);
        await expect(page.locator('#profileEditorHost')).toHaveValue('order.example.test');
        await expect(page.locator('#profileEditorCredential')).toHaveValue(
            await page.locator('#profileEditorCredential option', {hasText: shared}).getAttribute('value'));
        await expect(page.locator('#profileEditorForm').getByRole('button', {name: button, exact: true})).toBeEnabled();
        expect(await resourcesNamed(page, name)).toEqual([]);
        await page.reload();
        await ui.dismissTour(page);
        expect(await resourcesNamed(page, name)).toEqual([]);
        await context.close();
    });
}

test('confirming stores the host with its saved password in one step', async ({browser}) => {
    const {context, page} = await signedIn(browser);
    const name = 'Order host confirmed';
    await ui.openHosts(page);
    await page.locator('#newProfileBtn').click();
    await ui.fillHostEditor(page, {name, host: 'order.example.test', port: 2222, username: 'lab', auth: 'password'});
    await page.locator('#profileEditorCredential').selectOption({label: shared});
    await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
    expect(await ui.answerStepUp(page, admin.password, {timeout: 10_000})).toBe(true);
    await expect(page.locator('#profileEditorView')).toBeHidden();
    await expect(ui.hostRow(page, name)).toBeVisible();
    await expectAssigned(page, name);
    await context.close();
});

const routes = [
    {kind: 'jump', asset: 'jump-hosts', form: '#jumpHostForm', prefix: 'jh', list: '#jumpHostsList', name: 'Order bastion',
        fill: async page => {
            await page.locator('#jhNameInput').fill('Order bastion');
            await page.locator('#jhHostInput').fill('bastion.example.test');
            await page.locator('#jhPortInput').fill('22');
            await page.locator('#jhUsernameInput').fill('lab');
        }},
    {kind: 'socks', asset: 'socks-proxies', form: '#socksProxyForm', prefix: 'sp', list: '#socksProxiesList', name: 'Order proxy',
        fill: async page => {
            await page.locator('#spNameInput').fill('Order proxy');
            await page.locator('#spHostInput').fill('proxy.example.test');
            await page.locator('#spPortInput').fill('1080');
            await page.locator('input[name="spAuthType"][value="password"]').check();
            await page.locator('#spUsernameInput').fill('lab');
        }},
];

for (const route of routes) {
    test(`${route.kind}: the confirmation comes before the record is stored`, async ({browser}) => {
        // The Python release cannot assign an existing saved password to a
        // new SOCKS5 proxy at all (the assignment ends in "Resource saved,
        // but password assignment failed", with or without this change).
        test.fail(kind === 'python' && route.kind === 'socks', 'Python fails the SOCKS5 assignment itself');
        const {context, page} = await signedIn(browser);
        await ui.openHosts(page);
        await page.locator(`#profileManagementModal .connection-asset-nav [data-connection-asset="${route.asset}"]`).click();
        await page.locator(`#${route.kind}ResourceNew`).click();
        await route.fill(page);
        await page.locator(`#${route.prefix}CredentialExisting`).selectOption({label: shared});
        const save = page.locator(`${route.form} button[type="submit"]`);
        await save.click();
        await expect(stepUpDialog(page)).toBeVisible();
        expect(await resourcesNamed(page, route.name)).toEqual([]);
        await cancelStepUp(page);
        expect(await resourcesNamed(page, route.name)).toEqual([]);
        await expect(page.locator(`#${route.prefix}NameInput`)).toHaveValue(route.name);
        await expect(save).toBeEnabled();

        await save.click();
        expect(await ui.answerStepUp(page, admin.password, {timeout: 10_000})).toBe(true);
        await expect(page.locator(`${route.list} .key-item`).filter({hasText: route.name})).toBeVisible();
        await expectAssigned(page, route.name);
        await context.close();
    });
}

// Answers the dialogs a save opens: confirmations of the target or of a
// replaced password are accepted; the account confirmation (step-up) is
// cancelled or answered. Returns once the step-up was handled.
async function throughConfirmations(page, stepUp) {
    for (let i = 0; i < 4; i++) {
        const dialog = stepUpDialog(page);
        await expect(dialog).toBeVisible();
        if (await dialog.locator('input[type="password"]').isVisible()) {
            if (stepUp === 'cancel') await cancelStepUp(page);
            else expect(await ui.answerStepUp(page, admin.password)).toBe(true);
            return;
        }
        // The next confirmation may open at once, so wait for this one.
        const current = await dialog.elementHandle();
        await dialog.locator('button.btn-primary').click();
        await current.waitForElementState('hidden');
    }
    throw new Error('no account confirmation');
}

async function stored(page, name) {
    const state = await serverState(page);
    const byId = Object.fromEntries(state.credentials.map(item => [item.id, item.name]));
    return state.profiles.filter(resource => resource.name === name)
        .map(resource => ({host: resource.host, password: byId[resource.credential_id] || null}));
}

// T4 for edits: changing the destination and the assigned password of a
// record is one change. Cancelling the confirmation changes nothing;
// confirming it stores both.
const edits = [
    {kind: 'ssh', name: 'Order host confirmed', from: 'order.example.test', to: 'edited.example.test',
        open: async page => {
            await ui.openHosts(page);
            await ui.hostRow(page, 'Order host confirmed').click();
            await expect(page.locator('#profileEditorView')).toBeVisible();
        },
        host: '#profileEditorHost', choose: page => page.locator('#profileEditorCredential').selectOption({label: second}),
        save: page => page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click(),
        done: page => expect(page.locator('#profileEditorView')).toBeHidden()},
    ...routes.map(route => ({kind: route.kind, name: route.name, from: route.kind === 'jump' ? 'bastion.example.test' : 'proxy.example.test',
        to: `edited-${route.kind}.example.test`,
        open: async page => {
            await ui.openHosts(page);
            await page.locator(`#profileManagementModal .connection-asset-nav [data-connection-asset="${route.asset}"]`).click();
            await page.locator(`${route.list} .key-item`).filter({hasText: route.name}).getByRole('button', {name: 'Edit', exact: true}).click();
            await expect(page.locator(`#${route.prefix}NameInput`)).toHaveValue(route.name);
        },
        host: `#${route.prefix}HostInput`, choose: page => page.locator(`#${route.prefix}CredentialExisting`).selectOption({label: second}),
        save: page => page.locator(`${route.form} button[type="submit"]`).click(),
        done: page => expect(page.locator(`#${route.prefix}NameInput`)).not.toHaveValue(route.name)})),
];

for (const edit of edits) {
    test(`${edit.kind}: an edit and its password change are stored together or not at all`, async ({browser}) => {
        test.fail(kind === 'python' && edit.kind === 'socks', 'Python fails the SOCKS5 assignment itself');
        const {context, page} = await signedIn(browser);
        expect(await stored(page, edit.name)).toEqual([{host: edit.from, password: shared}]);
        await edit.open(page);
        await page.locator(edit.host).fill(edit.to);
        await edit.choose(page);
        await edit.save(page);
        await throughConfirmations(page, 'cancel');
        expect(await stored(page, edit.name)).toEqual([{host: edit.from, password: shared}]);
        await expect(page.locator(edit.host)).toHaveValue(edit.to);

        await edit.save(page);
        await throughConfirmations(page, 'answer');
        await edit.done(page);
        await expect.poll(() => stored(page, edit.name), {timeout: 10_000}).toEqual([{host: edit.to, password: second}]);
        await context.close();
    });
}

// One request carries the edit and the assignment: when it fails, the
// host keeps its destination as well as its password. The request is cut
// off in the browser; the transaction on the server is covered by the Go
// tests.
test('ssh: an edit whose assignment request fails changes nothing', async ({browser}) => {
    test.fail(kind === 'python', 'the Python release saves the host before the assignment');
    const {context, page} = await signedIn(browser);
    const name = 'Order host confirmed';
    const before = await stored(page, name);
    expect(before).toEqual([{host: 'edited.example.test', password: second}]);
    await page.route('**/api/credentials/assign', route => route.abort());
    await ui.openHosts(page);
    await ui.hostRow(page, name).click();
    await page.locator('#profileEditorHost').fill('third.example.test');
    await page.locator('#profileEditorCredential').selectOption('');
    await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
    await expect(page.locator('#notificationContainer [role="alert"]').first()).toBeVisible();
    await page.unroute('**/api/credentials/assign');
    expect(await stored(page, name)).toEqual(before);
    await expect(page.locator('#profileEditorView')).toBeVisible();
    await context.close();
});
