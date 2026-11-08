const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
test.afterEach(async ({page}) => assertNoExternalRequests(page));

const step = (stdout, exit_code = 0, status = 'succeeded') => ({name: 'OpenSSL version', status, exit_code, duration: 0.2,
    reason: status === 'failed' ? 'nonzero_exit' : null, stdout, stderr: '', output_truncated: false});

test('a finished run compares hosts per step and renders remote output only as text', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace: false});
    const marker = '<img src=x onerror="window.injected=1">';
    const run = {id: 'compare-run', name: 'Inventory', created_at: '2026-11-08T10:00:00Z', status: 'failed', targets: [
        {name: 'web-01', host: 'web-01.invalid', username: 'ops', status: 'succeeded', steps: [step('OpenSSL 3.0.13\n')]},
        {name: 'web-02', host: 'web-02.invalid', username: 'ops', status: 'succeeded', steps: [step('OpenSSL 3.0.13')]},
        {name: 'legacy', host: 'legacy.invalid', username: 'ops', status: 'succeeded', steps: [step(`OpenSSL 1.1.1 ${marker}`)]},
        {name: 'broken', host: 'broken.invalid', username: 'ops', status: 'failed', steps: [step('', 127, 'failed')]},
    ]};
    await page.route('**/api/automation/runs', route => route.fulfill({json: {runs: [run]}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab="runs"]').click();
    const compare = page.locator('.automation-run-compare');
    await expect(compare.locator('summary')).toHaveText('Compare hosts: 1 step differs between hosts');
    await compare.locator('summary').click();
    const groups = compare.locator('.automation-compare-group');
    await expect(groups).toHaveCount(3);
    await expect(groups.first()).toContainText('2 hosts');
    await expect(groups.first()).toContainText('web-01, web-02');
    await expect(groups.first().locator('pre')).toHaveText('OpenSSL 3.0.13');
    await expect(groups.nth(1).locator('pre')).toHaveText(`OpenSSL 1.1.1 ${marker}`);
    await expect(groups.nth(2)).toHaveAttribute('data-state', 'failed');
    expect(await page.evaluate(() => window.injected)).toBeUndefined();
    expect(await compare.locator('img').count()).toBe(0);
    for (const width of [390, 1440]) {
        await page.setViewportSize({width, height: 900});
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await compare.screenshot({path: testInfo.outputPath(`compare-${width}.png`), animations: 'disabled'});
    }
});

test('a single-host run and active runs show no comparison', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    const runs = [
        {id: 'single', name: 'One host', created_at: '2026-11-08T10:00:00Z', status: 'succeeded',
            targets: [{name: 'solo', host: 'solo.invalid', username: 'ops', status: 'succeeded', steps: [step('ok')]}]},
        {id: 'active', name: 'Running', created_at: '2026-11-08T11:00:00Z', status: 'running', targets: [
            {name: 'a', host: 'a.invalid', username: 'ops', status: 'running', steps: [step('', null, 'running')]},
            {name: 'b', host: 'b.invalid', username: 'ops', status: 'queued', steps: [step('', null, 'queued')]}]},
    ];
    await page.route('**/api/automation/runs', route => route.fulfill({json: {runs}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab="runs"]').click();
    await expect(page.locator('.automation-run')).toHaveCount(2);
    await expect(page.locator('.automation-run-compare:visible')).toHaveCount(0);
});




test('compare hides identical steps by default', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    const ok = (name, stdout) => ({name, status: 'succeeded', exit_code: 0, duration: 0.1, reason: null, stdout, stderr: '', output_truncated: false});
    const run = {id: 'filter-run', name: 'Audit', created_at: '2026-11-08T10:00:00Z', status: 'succeeded', targets: ['a', 'b'].map(name => ({
        name, host: `${name}.invalid`, username: 'ops', status: 'succeeded', steps: [ok('Kernel', '6.1'), ok('OpenSSL', name === 'a' ? '3.0.13' : '3.0.2')]}))};
    await page.route('**/api/automation/runs', route => route.fulfill({json: {runs: [run]}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab="runs"]').click();
    const compare = page.locator('.automation-run-compare');
    await compare.locator('summary').click();
    await expect(compare.locator('.automation-compare-step:visible')).toHaveCount(1);
    await expect(compare.locator('.automation-compare-step:visible h5')).toHaveText('OpenSSL');
    await compare.locator('.automation-compare-filter input').uncheck();
    await expect(compare.locator('.automation-compare-step:visible')).toHaveCount(2);

});

test('the maintenance template keeps the exact probe through the editor', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.goto('/automation');
    await page.locator('#workflowTemplate').selectOption('maintenance');
    await page.locator('#useWorkflowTemplate').click();
    await page.locator('#runbookSteps > .automation-step').nth(1).locator('.automation-step-preview').click();
    const command = await page.locator('#automationStepDetail textarea').inputValue();
    expect(command).toBe(await page.evaluate(() => window.AutomationTemplates.MAINTENANCE_COMMAND));
});

