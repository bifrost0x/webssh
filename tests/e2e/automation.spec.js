const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });
async function authenticate(page) {
    const dialog = page.locator('#automationPrompt');
    await expect(dialog).toBeVisible();
    if (await page.locator('#promptSelect').isVisible()) {
        await page.locator('#promptSelect').selectOption('password');
        await dialog.getByRole('button', {name: 'Continue', exact:true}).click();
    }
    await expect(page.locator('#promptInput')).toBeVisible();
    await page.locator('#promptInput').fill('browser-password');
    await dialog.getByRole('button', {name: 'Continue', exact:true}).click();
    await expect(dialog).not.toBeVisible();
}

test('automation runbook, group review, execution and cancellation', async ({page}, testInfo) => {
    test.setTimeout(120000);
    await login(page, 'e2e_user', {workspace:false});
    await page.goto('/automation');
    await expect(page.locator('#newRunbook')).toBeVisible();
    await page.locator('#newRunbook').click();
    await page.locator('#runbookName').fill('Fleet readiness');
    await page.locator('[data-field="name"]').fill('Identity');
    await page.locator('#automationStepDetail textarea').fill('id');
    await page.locator('[data-workspace-view=targets]').click();
    await page.locator('#targetGroups').getByLabel('Automation lab (1)', {exact:true}).check();
    await page.locator('#reviewWorkspace').click();
    await expect(page.locator('#runPreview')).toBeVisible();
    await expect(page.locator('#automationPreviewContent')).toContainText('Automation fixture');
    await expect(page.locator('#automationPreviewContent pre')).toHaveText('id');
    await page.locator('#runConfirmation').fill('2');
    await page.locator('#startRun').click();
    await expect(page.locator('#automationPreviewError')).toBeVisible();
    await page.locator('#runConfirmation').fill('1');
    await page.locator('#startRun').click();
    await authenticate(page);
    await expect(page.locator('#runHistory .automation-run').first()).toContainText('Succeeded', {timeout:20000});
    await expect(page.locator('#runHistory')).not.toContainText('BEGIN RSA PRIVATE KEY');
    await page.screenshot({path:testInfo.outputPath('automation-runs-desktop.png'), fullPage:true});
    await page.locator('[data-auto-tab="runbooks"]').click();
    await page.locator('[data-workspace-view=editor]').click();
    await page.locator('#automationStepDetail textarea').fill('wait');
    await page.locator('#addStep').click();
    await page.locator('[data-field="name"]').nth(1).fill('Must not run after cancellation');
    await page.locator('#automationStepDetail textarea').fill('id');
    await page.locator('[data-workspace-view=targets]').click();
    await page.locator('#reviewWorkspace').click();
    await page.locator('#runConfirmation').fill('1');
    await page.locator('#startRun').click();
    await authenticate(page);
    await expect(page.locator('#runHistory .automation-run').first().locator('.automation-run-step[data-state="running"]')).toBeVisible();
    await page.locator('#runHistory .automation-run').first().getByRole('button', {name:'Stop remaining work'}).click();
    await expect(page.locator('#runHistory .automation-run').first()).toContainText('Unknown outcome', {timeout:20000});
    await expect(page.locator('#runHistory .automation-run').first().locator('.automation-run-step[data-state="skipped"]')).toContainText('Must not run after cancellation');

});

test('automation editor fits mobile, translates and keeps keyboard labels', async ({page}, testInfo) => {
    await page.setViewportSize({width:390,height:844});
    await login(page, 'e2e_admin', {workspace:false});
    await page.goto('/automation');
    await page.locator('#inventoryTemplate').click();
    await expect(page.locator('#runbookName')).toHaveValue('System inventory');
    await page.locator('#addStep').click();
    await expect(page.locator('.automation-step')).toHaveCount(2);
    await page.locator('[data-field="name"]').nth(1).fill('Second');
    await page.locator('#automationStepDetail textarea').fill('id');
    await page.locator('.automation-step').nth(1).getByRole('button',{name:'Move step up',exact:true}).click();
    await expect(page.locator('[data-field="name"]').first()).toHaveValue('Second');
    await page.evaluate(() => window.i18n.setLanguage('de'));
    await expect(page.locator('#automationNativeView h1')).toHaveText('Automatisierung');
    await expect(page.locator('[data-field="name"]').first()).toHaveValue('Second');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.locator('.automation-main').evaluate(element => { element.scrollTop = 0; });
    await page.screenshot({path:testInfo.outputPath('automation-editor-mobile.png')});
});

test('editing during a delayed save keeps unsaved changes visible', async ({page}) => {
    await login(page, 'e2e_admin', {workspace:false});
    await page.goto('/automation');
    await expect(page.locator('#automationApp')).not.toHaveAttribute('inert', '');
    await page.locator('[data-auto-tab=runbooks]').click();
    await page.locator('#runbookName').fill('Before save');
    await page.locator('[data-field="name"]').fill('Identity');
    await page.locator('#automationStepDetail textarea').fill('id');
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let seen;
    const saving = new Promise(resolve => { seen = resolve; });
    await page.route('**/api/automation/runbooks', async route => {
        seen(); await gate; await route.continue();
    });
    await page.locator('#saveRunbook').click();
    await saving;
    await page.locator('#runbookName').fill('Newer unsaved name');
    release();
    await expect(page.locator('#saveRunbook')).toBeEnabled();
    await expect(page.locator('#saveState')).toHaveText('Unsaved changes');
});
