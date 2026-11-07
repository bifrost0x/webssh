const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));
const host = (id, supported = true) => ({id, name: id, host: `${id}.invalid`, port: 22, username: 'operator', group: 'Lab', auth_type: 'password', supported});
const state = profiles => ({enabled: true, runbooks: [], profiles, vault: {exists: true, unlocked: true, expires_in: 600, credentials: []}});

test('a stale polling response cannot restore targets after authorization expires', async ({page}) => {
    test.setTimeout(45000);
    await login(page, 'e2e_admin', {workspace: false});
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let pending;
    const requested = new Promise(resolve => { pending = resolve; });
    let calls = 0;
    await page.route('**/api/automation/state', async route => {
        calls += 1;
        if (calls === 2) { pending(); await gate; }
        await route.fulfill({json: state([host('first')])});
    });
    await page.goto('/automation');
    await page.locator('#newRunbook').click();
    await page.locator('#runbookName').fill('Keep this draft');
    await page.locator('[data-workspace-view=targets]').click();
    await expect(page.locator('#target-first')).toBeVisible();
    await requested;
    await page.route('**/api/automation/runs', route => route.fulfill({status:401,json:{code:'authentication_required'}}));
    await page.locator('[data-auto-tab=runs]').click();
    await expect(page.locator('#automationError')).toBeVisible();
    await expect(page.locator('#target-first')).toHaveCount(0);
    const lateResponse = page.waitForResponse('**/api/automation/state');
    release();
    await (await lateResponse).finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.locator('#target-first')).toHaveCount(0);
    await page.locator('[data-auto-tab=runbooks]').click();
    await expect(page.locator('#runbookName')).toHaveValue('Keep this draft');
});

test('polling refreshes host availability while preserving search and draft', async ({page}) => {
    test.setTimeout(45000);
    await login(page, 'e2e_admin', {workspace: false});
    let calls = 0;
    await page.route('**/api/automation/state', async route => {
        calls += 1;
        await route.fulfill({json: state(calls === 1 ? [host('first')] : [host('first', false), host('second')])});
    });
    await page.goto('/automation');
    await page.locator('#newRunbook').click();
    await page.locator('#runbookName').fill('Unsaved work');
    await page.locator('[data-workspace-view=targets]').click();
    await page.locator('#target-first').check();
    await page.locator('#targetGroups input').check();
    await page.locator('#targetSearch').fill('first');
    await expect(page.locator('#target-first')).toBeDisabled({timeout: 25000});
    await expect(page.locator('#target-first')).not.toBeChecked();
    await expect(page.locator('#targetGroups input')).not.toBeChecked();
    await expect(page.locator('#target-second')).toBeAttached();
    await expect(page.locator('#target-second')).toBeHidden();
    await expect(page.locator('#runbookName')).toHaveValue('Unsaved work');
    await expect(page.locator('#saveState')).toHaveText('Unsaved changes');
    await page.locator('#targetSearch').fill('second');
    await page.locator('#target-second').check();
    await expect(page.locator('#targetCount')).toHaveText('1 hosts');
});
