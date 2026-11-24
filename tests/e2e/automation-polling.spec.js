const {test, expect} = require('playwright/test');
const {login, openWorkspace} = require('./helpers');

// Polling follows what is visible: fast only while a run is active, slowly in
// the overview, and workflow state only while automation is open.
test('automation polls only what is visible and speeds up while a run is active', async ({page}) => {
    await page.clock.install();
    const calls = {state: 0, runs: 0};
    let status = 'succeeded';
    await page.route('**/api/automation/state', route => { calls.state += 1; return route.fulfill({json: {enabled: true, runbooks: [], profiles: []}}); });
    await page.route('**/api/automation/schedules', route => route.fulfill({json: {schedules: []}}));
    await page.route('**/api/automation/runs', route => {
        calls.runs += 1;
        return route.fulfill({json: {runs: [{id: 'r1', name: 'Nightly check', status, created_at: new Date().toISOString(), targets: []}]}});
    });
    const reset = () => { calls.state = 0; calls.runs = 0; };
    // Advance the page clock one polling tick at a time and let each request finish.
    const advance = async milliseconds => {
        for (let elapsed = 0; elapsed < milliseconds; elapsed += 3_000) {
            await page.clock.runFor(Math.min(3_000, milliseconds - elapsed));
            await page.waitForTimeout(150);
        }
    };

    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('#odActivity')).toContainText('Nightly check');

    // Overview without an active run: runs every 30 seconds, no workflow state.
    reset();
    await advance(61_000);
    expect(calls.state).toBe(0);
    expect(calls.runs).toBeGreaterThanOrEqual(1);
    expect(calls.runs).toBeLessThanOrEqual(3);

    // A running run is followed every 3 seconds.
    status = 'running';
    await advance(31_000);
    reset();
    await advance(15_000);
    expect(calls.runs).toBeGreaterThanOrEqual(4);
    expect(calls.state).toBe(0);

    // Another workspace: nothing is polled, even with an active run.
    await openWorkspace(page);
    await advance(3_000);
    reset();
    await advance(60_000);
    expect(calls).toEqual({state: 0, runs: 0});

    // Returning to the overview refreshes immediately.
    await page.locator('#overviewNavBtn').click();
    await expect.poll(() => calls.runs).toBeGreaterThanOrEqual(1);

    // Automation refreshes its state on entry and then every 15 seconds.
    status = 'succeeded';
    await page.locator('#automationNavBtn').click();
    await expect.poll(() => calls.state).toBeGreaterThanOrEqual(1);
    await advance(3_000);
    reset();
    await advance(31_000);
    expect(calls.state).toBeGreaterThanOrEqual(2);
    expect(calls.state).toBeLessThanOrEqual(3);
});

test('entering automation shows that an administrator disabled it', async ({page}) => {
    let disabled = false;
    await page.route('**/api/automation/state', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {enabled: true, runbooks: [], profiles: []}}));
    await page.route('**/api/automation/runs', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {runs: []}}));
    await page.route('**/api/automation/schedules', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {schedules: []}}));
    await login(page, 'e2e_admin', {workspace: false});
    disabled = true;
    await page.locator('#automationNavBtn').click();
    await expect(page.locator('#automationDisabled')).toBeVisible();
    await expect(page.locator('#automationApp')).toBeHidden();
});
