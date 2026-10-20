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
                : body.action === 'process.inspect' ? JSON.stringify({pid: body.target.pid, command: 'worker', start_time: '12345'})
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
        const model = window.SessionDiagnosticsModule.buildViewModel({
            sessionId: 'ops', status: 'ready', cpuPercent: 12,
            stats: {os_name: 'Linux', memory: {used_kib: 380, total_kib: 1000, available_kib: 620},
                processes: {total: 25, top_cpu: [{pid: '123', command: 'worker', user: 'deploy', cpu_percent: 12}], top_memory: []}}
        }, SessionManager.sessions.ops, {
            sessionId: 'ops', status: 'ready', inventory: {
                systemd: {total: 2, active: 1, failed: 1, services: [{unit: 'sshd.service', active: 'active', description: 'Secure shell'}, {unit: 'backup.service', active: 'failed', description: 'Backup'}]},
                docker: {total: 2, running: 1, containers: [{name: 'database', status: 'Up 2 hours'}, {name: 'cache', status: 'Exited'}]}
            }
        });
        window.ServerOperations.updateSnapshot('ops', SessionManager.sessions.ops, model);
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
    await page.evaluate(() => window.ServerOperations.open('ops', 'service', {unit: 'sshd.service'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await expect(dialog.getByRole('checkbox')).toBeDisabled();
    release();
    await expect(dialog.getByRole('checkbox')).toBeEnabled();
    await expect(dialog.getByRole('button', {name: /^restart$/i})).toBeVisible();
});

test('workspace opens on metrics, searches inventories and retains read-only navigation on small screens', async ({page}, testInfo) => {
    const calls = await setup(page, {enabled: false});
    await page.evaluate(() => window.ServerOperations.open('ops', 'system'));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await expect(dialog.locator('.server-management-card').getByText('12.0%', {exact: true})).toBeVisible();
    await dialog.screenshot({animations: 'disabled', path: testInfo.outputPath('overview.png')});
    expect(calls.filter(call => call.endpoint === 'read')).toHaveLength(0);
    await dialog.getByRole('tab', {name: 'Services', exact: true}).click();
    await dialog.getByRole('searchbox').fill('backup');
    await expect(dialog.getByRole('button', {name: /backup.service/})).toBeVisible();
    await expect(dialog.getByRole('button', {name: /sshd.service/})).toHaveCount(0);
    await dialog.getByRole('button', {name: /backup.service/}).click();
    await expect(dialog.getByRole('heading', {name: 'backup.service'})).toBeVisible();
    await expect(dialog.getByRole('button', {name: /^restart$/i})).toHaveCount(0);
    await dialog.screenshot({animations: 'disabled', path: testInfo.outputPath('services.png')});
    await dialog.getByRole('tab', {name: 'Containers', exact: true}).click();
    await expect(dialog.getByRole('button', {name: /database/})).toBeVisible();
    await dialog.getByRole('button', {name: /database/}).click();
    await expect(dialog.getByText('Immutable ID', {exact: true})).toBeVisible();
    await dialog.screenshot({animations: 'disabled', path: testInfo.outputPath('container.png')});
    await page.setViewportSize({width: 390, height: 844});
    await dialog.getByRole('button', {name: /database/}).click();
    await expect(dialog.getByRole('button', {name: 'Logs', exact: true})).toBeVisible();
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await dialog.screenshot({animations: 'disabled', path: testInfo.outputPath('mobile.png')});
    await dialog.getByRole('tab', {name: 'Processes', exact: true}).click();
    await expect(dialog.getByRole('button', {name: /123.*worker/})).toBeVisible();
});

test('changing selected resource invalidates an unexecuted confirmation', async ({page}) => {
    const calls = await setup(page);
    await page.evaluate(() => window.ServerOperations.open('ops', 'service', {unit: 'sshd.service'}));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await dialog.getByRole('button', {name: /^restart$/i}).click();
    await expect(dialog.getByRole('button', {name: 'Confirm and execute'})).toBeVisible();
    await dialog.getByRole('button', {name: /backup.service/}).click();
    await expect(dialog.getByRole('button', {name: 'Confirm and execute'})).toHaveCount(0);
    expect(calls.filter(call => call.endpoint === 'execute')).toHaveLength(0);
});

test('resource tabs support roving keyboard navigation and label their panel', async ({page}) => {
    await setup(page, {enabled: false});
    await page.evaluate(() => window.ServerOperations.open('ops', 'system'));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    const overview = dialog.getByRole('tab', {name: 'Overview', exact: true});
    await expect(dialog.getByRole('checkbox')).toBeHidden();
    await overview.focus();
    await overview.press('ArrowRight');
    const services = dialog.getByRole('tab', {name: 'Services', exact: true});
    await expect(services).toBeFocused();
    await expect(services).toHaveAttribute('aria-selected', 'true');
    await expect(overview).toHaveAttribute('tabindex', '-1');
    await expect(dialog.getByRole('tabpanel', {name: 'Services', exact: true})).toBeVisible();
    const resource = dialog.getByRole('button', {name: /sshd.service/});
    await resource.focus();
    await resource.press('Enter');
    await expect(dialog.getByRole('heading', {name: 'sshd.service', exact: true})).toBeFocused();
    await expect(dialog.getByRole('status')).toContainText('Read complete');
    await expect(dialog.getByRole('heading', {name: 'sshd.service', exact: true})).toBeFocused();
    await services.focus();
    await services.press('End');
    const processes = dialog.getByRole('tab', {name: 'Processes', exact: true});
    await expect(processes).toBeFocused();
    await processes.press('ArrowRight');
    await expect(overview).toBeFocused();
    await overview.press('ArrowLeft');
    await expect(processes).toBeFocused();
    await processes.press('Home');
    await expect(overview).toBeFocused();
});

test('inventory entry has no implicit read and sorts services and containers by actionable state', async ({page}) => {
    const calls = await setup(page);
    await page.evaluate(() => window.ServerOperations.open('ops', 'service'));
    const dialog = page.getByRole('dialog', {name: 'Server management', exact: true});
    await expect(dialog.locator('.server-management-row strong')).toHaveText(['backup.service', 'sshd.service']);
    await expect(dialog.locator('.server-management-detail h3')).toHaveText('Services');
    expect(calls.filter(call => call.endpoint === 'read')).toHaveLength(0);
    await dialog.getByRole('tab', {name: 'Containers', exact: true}).click();
    await expect(dialog.locator('.server-management-row strong')).toHaveText(['database', 'cache']);
    await dialog.getByRole('tab', {name: 'Processes', exact: true}).click();
    await expect(dialog.locator('.server-management-row small')).toHaveText(['CPU: 12.0%']);
    await dialog.locator('.server-management-row').click();
    await expect(dialog.locator('.server-management-facts')).toContainText('12345');
    expect(calls.find(call => call.body.action === 'process.inspect').body.target).toEqual({pid: 123});
    await expect(dialog.locator('.server-management-row')).toHaveAttribute('aria-pressed', 'true');
});
