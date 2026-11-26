// M1 acceptance: saved hosts are created, edited and deleted through the
// host manager, and every change survives a reload.
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure} = require('./backend');
const ui = require('./ui');

const admin = {username: 'm1hosts', password: 'M1-hosts-admin-password-3'};

let backend;

test.beforeAll(async () => {
    backend = freshBackend('hosts');
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start();
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

test('a saved host is created, edited and deleted without opening a connection', async ({browser}) => {
    const context = await browser.newContext({baseURL: backend.baseURL});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await ui.signIn(page, admin.username, admin.password);
    await ui.watchHostKeyPrompts(page);
    const connects = [];
    page.on('websocket', socket => socket.on('framesent', frame => {
        if (typeof frame.payload === 'string' && /ssh_connect|terminal\.open/.test(frame.payload)) connects.push(frame.payload);
    }));

    let id;
    await test.step('create', async () => {
        id = await ui.createHost(page, {name: 'Staging web', host: 'staging.example.test', port: 2222, username: 'deploy'});
        expect(id).toBeTruthy();
        await expect(ui.hostRow(page, 'Staging web').locator('..')).toContainText('deploy@staging.example.test');
    });

    await test.step('edit', async () => {
        await ui.hostRow(page, 'Staging web').click();
        await expect(page.locator('#profileEditorId')).toHaveValue(id);
        await ui.fillHostEditor(page, {name: 'Staging api', port: 2200, username: 'release'});
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        await expect(ui.hostRow(page, 'Staging api').locator('..')).toContainText('release@staging.example.test');
        await expect(ui.hostRow(page, 'Staging web')).toHaveCount(0);
        await page.reload();
        await ui.openHosts(page);
        await ui.hostRow(page, 'Staging api').click();
        await expect(page.locator('#profileEditorId')).toHaveValue(id);
        await expect(page.locator('#profileEditorHost')).toHaveValue('staging.example.test');
        await expect(page.locator('#profileEditorPort')).toHaveValue('2200');
        await expect(page.locator('#profileEditorUsername')).toHaveValue('release');
    });

    await test.step('delete', async () => {
        const menu = page.locator(`[data-profile-action="delete"][data-profile-id="${id}"]`);
        const details = menu.locator('xpath=ancestor::details[1]');
        if (await details.count()) await details.locator('> summary').click();
        page.once('dialog', dialog => dialog.accept());
        await menu.click();
        await expect(ui.hostRow(page, 'Staging api')).toHaveCount(0);
        await page.reload();
        await ui.openHosts(page);
        await expect(ui.hostRow(page, 'Staging api')).toHaveCount(0);
    });

    expect(await ui.sessionIds(page)).toEqual([]);
    expect(await ui.hostKeyPrompts(page)).toEqual([]);
    expect(connects).toEqual([]);
    expect(errors).toEqual([]);
    await context.close();
});
