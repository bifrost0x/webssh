const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

for (const change of ['schedule', 'navigation', 'command']) {
    test(`delayed review rejects changed ${change} context`, async ({page}) => {
        await login(page, 'e2e_user', {workspace:false});
        await page.goto('/automation');
        await page.locator('#newRunbook').click();
        await page.locator('#runbookName').fill('Review context');
        await page.locator('[data-field=name]').fill('Identity');
        await page.locator('#automationStepDetail textarea').fill('id');
        await page.locator('[data-workspace-view=targets]').click();
        await page.locator('#targetGroups').getByLabel('Automation lab (1)', {exact:true}).check();
        const scheduled = change !== 'command';
        if (scheduled) {
            await page.locator('#openSchedule').click();
            await page.locator('#scheduleTimezone').fill('UTC');
        }
        let release, seen;
        const gate = new Promise(resolve => { release = resolve; });
        const received = new Promise(resolve => { seen = resolve; });
        await page.route(scheduled ? '**/api/automation/schedules/preview' : '**/api/automation/preview', async route => {
            const response = await route.fetch();
            expect(response.ok()).toBe(true);
            seen(); await gate; await route.fulfill({response});
        });
        if (scheduled) await page.locator('#scheduleForm button[type=submit]').click();
        else await page.locator('#reviewWorkspace').click();
        await received;
        if (change === 'schedule') await page.locator('#scheduleTime').fill('17:42');
        if (change === 'navigation') await page.locator('#overviewNavBtn').click();
        if (change === 'command') {
            await page.locator('[data-workspace-view=editor]').click();
            await page.locator('#automationStepDetail textarea').fill('pwd');
        }
        release();
        await expect(page.locator('body')).not.toHaveAttribute('aria-busy', 'true');
        await expect(page.locator(scheduled ? '#scheduleReview' : '#runPreview')).toBeHidden();
        if (change === 'schedule') await expect(page.locator('#scheduleTime')).toHaveValue('17:42');
        if (change === 'command') await expect(page.locator('#automationStepDetail textarea')).toHaveValue('pwd');
        if (change !== 'navigation') {
            await expect(page.locator('#automationError')).toContainText('changed while the preview was loading');
            if (scheduled) await page.locator('#scheduleForm button[type=submit]').click();
            else {
                await page.locator('[data-workspace-view=targets]').click();
                await page.locator('#reviewWorkspace').click();
            }
            await expect(page.locator(scheduled ? '#scheduleReview' : '#runPreview')).toBeVisible();
            await expect(page.locator(scheduled ? '#scheduleReviewContent' : '#automationPreviewContent')).toContainText(scheduled ? '17:42' : 'pwd');
        }
    });
}

test('existing schedule edits persist in place and can be paused after reapproval', async ({page}, info) => {
    test.setTimeout(90000);
    await login(page, 'e2e_user', {workspace:false});
    await page.goto('/automation');
    await page.locator('#newRunbook').click();
    const name = 'Schedule edit ' + Date.now();
    await page.locator('#runbookName').fill(name);
    await page.locator('[data-field=name]').fill('Identity');
    await page.locator('#automationStepDetail textarea').fill('id');
    await page.locator('[data-workspace-view=targets]').click();
    await page.locator('#targetGroups').getByLabel('Automation lab (1)', {exact:true}).check();
    await page.locator('#openSchedule').click();
    // A future annual slot avoids dispatching a background job during this UI test.
    await page.locator('#scheduleFrequency').selectOption('custom');
    await page.locator('#scheduleCron').fill('0 0 1 1 *');
    await page.locator('#scheduleTimezone').fill('UTC');
    async function approve() {
        await page.locator('#scheduleForm button[type=submit]').click();
        await page.locator('#scheduleConfirmation').fill('1');
        await page.locator('#scheduleStartForm button[type=submit]').click();
        const dialog = page.locator('#automationPrompt');
        await expect(dialog).toBeVisible();
        if (await page.locator('#promptSelect').isVisible()) {
            await page.locator('#promptSelect').selectOption('password');
            await dialog.getByRole('button', {name:'Continue',exact:true}).click();
        }
        await page.locator('#promptInput').fill('browser-password');
        await dialog.getByRole('button', {name:'Continue',exact:true}).click();
        await expect(page.locator('#scheduleReview')).toBeHidden();
        await expect(page.locator('#scheduleList')).toContainText(name);
    }
    await approve();
    const before = await page.request.get('/api/automation/schedules');
    const original = (await before.json()).schedules.find(item => item.name === name);
    const row = page.locator('#scheduleList > section').filter({hasText:name});
    await row.getByRole('button', {name:'Review schedule',exact:true}).click();
    await expect(page.locator('#scheduleCron')).toHaveValue('0 0 1 1 *');
    await page.locator('#scheduleCron').fill('15 3 2 1 *');
    await approve();
    const after = (await (await page.request.get('/api/automation/schedules')).json()).schedules.filter(item => item.name === name);
    expect(after).toHaveLength(1);
    expect(after[0].id).toBe(original.id);
    expect(after[0].cron).toBe('15 3 2 1 *');
    expect(after[0].enabled).toBe(true);
    await row.getByRole('button', {name:'Pause schedule',exact:true}).click();
    await expect(row).toContainText('Paused');
    await page.screenshot({path:info.outputPath('edited-paused-schedule.png'),fullPage:true});
});
