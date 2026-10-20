const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

async function setup(page, {enabled = true, password = false} = {}) {
    const calls = [];
    await page.route('**/api/server-operations/**', async route => {
        const request = route.request();
        const endpoint = new URL(request.url()).pathname.split('/').at(-1);
        const body = request.method() === 'POST' ? request.postDataJSON() : {};
        calls.push({endpoint, body});
        let result;
        if (endpoint === 'ops') result = {mutations_enabled: enabled};
        else if (endpoint === 'read') result = {
            status: 'completed', output: body.action === 'container.inspect'
                ? JSON.stringify({id: 'a'.repeat(64), name: '/database', state: 'running'})
                : 'Server output', error_output: ''
        };
        else if (endpoint === 'intents') result = {
            intent: 'server-intent', command: 'systemctl reboot', action: body.action,
            confirmation: body.action === 'system.reboot' ? 'example.test' : ''
        };
        else result = {status: 'requested', output: '', error_output: ''};
        await route.fulfill({json: result});
    });
    await page.route('**/api/account/step-up/**', async route => {
        const endpoint = new URL(route.request().url()).pathname.split('/').at(-1);
        calls.push({endpoint: `auth-${endpoint}`});
        await route.fulfill({json: password && endpoint === 'intents'
            ? {intent: 'account-intent', methods: ['password'], preferred_method: 'password'}
            : {grant: 'verified-grant'}});
    });
    await login(page);
    await page.evaluate(() => {
        SessionManager.sessions.ops = {connected: true, host: 'example.test', port: 22, username: 'deploy'};
        SessionManager.activeSessionId = 'ops';
    });
    return calls;
}

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('reboot requires typed host, explicit confirmation and reports only requested', async ({page}) => {
    const calls = await setup(page);
    await page.evaluate(() => window.ServerOperations.open('ops', 'system'));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^reboot$/i}).click();
    const confirm = dialog.getByRole('button', {name: 'Confirm and execute'});
    await expect(confirm).toBeDisabled();
    await expect(dialog.locator('pre').last()).toContainText('systemctl reboot');
    expect(calls.filter(call => call.endpoint === 'execute')).toHaveLength(0);
    await dialog.getByLabel(/Type the host/).fill('example.test');
    await confirm.click();
    await expect(dialog.getByRole('status')).toContainText('Reboot requested');
    expect(calls.filter(call => call.endpoint === 'execute')).toHaveLength(1);
});

test('switching sessions during reauthentication cannot execute', async ({page}) => {
    const calls = await setup(page, {password: true});
    await page.evaluate(() => window.ServerOperations.open('ops', 'service', {unit: 'sshd.service'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^restart$/i}).click();
    await dialog.getByRole('button', {name: 'Confirm and execute'}).click();
    await expect(dialog.getByLabel('Confirm with your WebSSH sign-in method')).toBeVisible();
    await page.evaluate(() => {
        SessionManager.activeSessionId = 'other';
        window.dispatchEvent(new CustomEvent('session-workspace-change'));
    });
    await expect(dialog.getByRole('status')).toContainText('active session changed');
    expect(calls.filter(call => call.endpoint === 'execute')).toHaveLength(0);
});

test('container actions use resolved immutable IDs and disabled deployments remain read-only', async ({page}) => {
    const calls = await setup(page);
    await page.evaluate(() => window.ServerOperations.open('ops', 'container', {name: 'database'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^stop$/i}).click();
    expect(calls.find(call => call.endpoint === 'intents').body.target).toEqual({container: 'a'.repeat(64)});
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await page.route('**/api/server-operations/ops', route => route.fulfill({json: {mutations_enabled: false}}));
    await page.evaluate(() => window.ServerOperations.open('ops', 'system'));
    await expect(dialog.getByText(/mutations are disabled/)).toBeVisible();
    await expect(dialog.getByRole('button', {name: /^reboot$/i})).toHaveCount(0);
});

test('lost execute response reports unknown outcome without retrying', async ({page}) => {
    await setup(page);
    let executions = 0;
    await page.route('**/api/server-operations/execute', async route => {
        executions++;
        await route.abort('failed');
    });
    await page.evaluate(() => window.ServerOperations.open('ops', 'service', {unit: 'sshd.service'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^restart$/i}).click();
    await dialog.getByRole('button', {name: 'Confirm and execute'}).click();
    await expect(dialog.getByRole('status')).toContainText('outcome is unknown');
    expect(executions).toBe(1);
});

test('dispatch disables cancellation and preserves the eventual result', async ({page}) => {
    await setup(page);
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    await page.route('**/api/server-operations/execute', async route => {
        await gate;
        await route.fulfill({json: {status: 'completed', output: 'done', error_output: ''}});
    });
    await page.evaluate(() => window.ServerOperations.open('ops', 'service', {unit: 'sshd.service'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^restart$/i}).click();
    await dialog.getByRole('button', {name: 'Confirm and execute'}).click();
    await expect(dialog.getByRole('button', {name: 'Cancel', exact: true})).toBeDisabled();
    release();
    await expect(dialog.getByRole('status')).toContainText('command completed');
});

test('sudo cannot invalidate a pending inspection', async ({page}) => {
    await setup(page);
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    await page.route('**/api/server-operations/read', async route => {
        await gate;
        await route.fulfill({json: {status: 'completed', output: 'ready', error_output: ''}});
    });
    await page.evaluate(() => window.ServerOperations.open('ops', 'system'));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await expect(dialog.getByRole('checkbox')).toBeDisabled();
    release();
    await expect(dialog.getByRole('checkbox')).toBeEnabled();
    await expect(dialog.getByRole('button', {name: /^reboot$/i})).toBeVisible();
});
