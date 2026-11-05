const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

// The retired vault-lock controls have no native equivalent. Exercise the
// current account authorization boundary: cancelling must never dispatch work.
for (const cancel of ['button', 'escape']) {
    test(`cancelled run authorization via ${cancel} never starts work and permits fresh review`, async ({page}) => {
        await login(page, 'e2e_admin', {workspace:false});
        const book = {id:'book',name:'Check',steps:[{name:'Identity',command:'id',timeout:30}]};
        const target = {id:'host',name:'Host',host:'test.invalid',username:'operator',auth_type:'key',supported:true};
        let starts = 0;
        await page.route('**/api/automation/state', route => route.fulfill({json:{enabled:true,runbooks:[book],profiles:[target]}}));
        await page.route('**/api/automation/runbooks', route => route.fulfill({json:{runbook:book}}));
        await page.route('**/api/automation/preview', route => route.fulfill({json:{intent:'run-intent',confirmation:'1',runbook:book,targets:[target]}}));
        await page.route('**/api/account/step-up/intents', route => route.fulfill({json:{intent:'account-intent',methods:['password'],preferred_method:'password'}}));
        await page.route('**/api/automation/start', route => {starts++;return route.fulfill({json:{run:{id:'unexpected'}}});});
        await page.goto('/automation');
        await page.locator('[data-auto-tab=runbooks]').click();
        await page.locator('[data-workspace-view=targets]').click();
        await page.locator('#target-host').check();
        await page.locator('#reviewWorkspace').click();
        await expect(page.locator('#runPreview')).toBeVisible();
        await page.locator('#runConfirmation').fill('1');
        await page.locator('#startRun').click();
        await expect(page.locator('#promptInput')).toBeVisible();
        await page.locator('#promptInput').fill('discard-this-secret');
        if(cancel === 'button') await page.locator('#promptCancel').click();
        else await page.keyboard.press('Escape');
        await expect(page.locator('#automationPrompt')).toBeHidden();
        await expect(page.locator('body')).not.toHaveAttribute('aria-busy','true');
        await expect(page.locator('#promptInput')).toHaveValue('');
        expect(starts).toBe(0);
        await page.locator('#closePreview').click();
        await expect(page.locator('#target-host')).toBeChecked();
        await page.locator('#reviewWorkspace').click();
        await expect(page.locator('#runPreview')).toBeVisible();
        await expect(page.locator('#automationPreviewContent')).toContainText('Host');
        expect(starts).toBe(0);
    });
}
