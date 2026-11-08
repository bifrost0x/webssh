const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('GitHub configuration draft survives switching settings sections', async ({page}) => {
    await login(page);
    await page.goto('/settings#authentication');
    await expect(page.locator('#githubAuthStatus')).not.toHaveText('');
    await page.locator('#githubAuthClientId').fill('draft-client');
    await page.locator('#githubAuthClientSecret').fill('draft-only-not-saved');
    await page.locator('#githubAuthAllowedOrgs').fill('draft-org');
    await page.locator('[data-settings-section="registration"]').click();
    await expect(page.locator('#settingRegistration')).toBeVisible();
    await page.locator('[data-settings-section="authentication"]').click();
    await expect(page.locator('#githubAuthClientId')).toBeVisible();
    await page.waitForTimeout(300);
    await expect(page.locator('#githubAuthClientId')).toHaveValue('draft-client');
    await expect(page.locator('#githubAuthClientSecret')).toHaveValue('draft-only-not-saved');
    await expect(page.locator('#githubAuthAllowedOrgs')).toHaveValue('draft-org');
});

test('a delayed configuration read cannot overwrite edits made while loading', async ({page}) => {
    await login(page);
    let release;
    let started;
    const requestStarted = new Promise(resolve => { started = resolve; });
    const delay = new Promise(resolve => { release = resolve; });
    await page.route('**/admin/api/github-auth/config', async route => {
        started(); await delay;
        await route.fulfill({json:{configuration:{client_id:'server-value'}}});
    });
    await page.goto('/settings#authentication');
    await requestStarted;
    await page.locator('#githubAuthClientId').fill('new-draft');
    const response = page.waitForResponse('**/admin/api/github-auth/config');
    release(); await response;
    await page.waitForTimeout(100);
    await expect(page.locator('#githubAuthClientId')).toHaveValue('new-draft');
});

test('GitHub draft survives cancelled and failed saves, then persists on retry', async ({page}) => {
    await login(page);
    let saved = {client_id:'original', enabled:false};
    let failSave = true;
    let writes = 0;
    await page.route('**/admin/api/github-auth/config', async route => {
        if (route.request().method() === 'POST') {
            writes += 1;
            if (failSave) {
                await route.fulfill({status:503,json:{error:'Configuration temporarily unavailable'}});
                return;
            }
            const payload = route.request().postDataJSON();
            saved = {...payload, client_secret_configured:Boolean(payload.client_secret)};
            delete saved.client_secret;
        }
        await route.fulfill({json:{configuration:saved}});
    });
    await page.goto('/settings#authentication');
    const client = page.locator('#githubAuthClientId');
    const secret = page.locator('#githubAuthClientSecret');
    const save = page.locator('#githubAuthSave');
    await expect(client).toHaveValue('original');
    await client.fill('saved-draft');
    await secret.fill('fixture-only-secret');
    await save.click();
    await expect(save).toBeDisabled();
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await page.locator('#stepUpCancelButton').click();
    await expect(save).toBeEnabled();
    await expect(client).toHaveValue('saved-draft');
    await expect(secret).toHaveValue('fixture-only-secret');
    expect(writes).toBe(0);
    await save.click();
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(save).toBeEnabled();
    await expect(page.locator('#notificationContainer')).toContainText('Configuration temporarily unavailable');
    await expect(secret).toHaveValue('fixture-only-secret');
    expect(writes).toBe(1);
    failSave = false;
    await save.click();
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(save).toBeEnabled();
    await expect(secret).toHaveValue('');
    await expect(client).toHaveValue('saved-draft');
    expect(writes).toBe(2);
    await page.reload();
    await expect(client).toHaveValue('saved-draft');
    await expect(secret).toHaveValue('');
});
