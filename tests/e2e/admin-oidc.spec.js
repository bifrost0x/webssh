const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

test('admin can inspect, unlink, and add an OIDC identity', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    const targetRow = page.locator('#adminUsersBody tr').filter({
        hasText: 'e2e_user',
    });
    await targetRow.locator('button[data-act="oidc-link"]').click();
    const modal = page.locator('#securityActionModal');
    await expect(modal).toHaveClass(/show/);
    await expect(modal.getByText('existing-e2e-subject')).toBeVisible();

    await page.locator('#securityActionPassword').fill('browser-password');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    page.once('dialog', dialog => dialog.accept());
    await modal.locator('button[data-oidc-identity-id]').click();
    await expect(modal.getByText('existing-e2e-subject')).toHaveCount(0);
    await expect(page.locator('#securityActionPassword')).toHaveValue('');
    await expect(page.locator('#securityActionConfirmation')).toHaveValue('');

    await page.locator('#securityActionPassword').fill('browser-password');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#securityActionSubject').fill('replacement-e2e-subject');
    await page.locator('#submitSecurityAction').click();
    await expect(modal.getByText('replacement-e2e-subject')).toBeVisible();
    await expect(page.locator('#securityActionPassword')).toHaveValue('');
    await expect(page.locator('#securityActionConfirmation')).toHaveValue('');
});

test('a delayed recovery response cannot populate another user modal', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    let releaseResponse;
    let markRequestStarted;
    const responseGate = new Promise(resolve => { releaseResponse = resolve; });
    const requestStarted = new Promise(resolve => { markRequestStarted = resolve; });
    await page.route('**/admin/api/users/*/recovery', async route => {
        markRequestStarted();
        await responseGate;
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ codes: ['recovery-code-for-e2e-user'] })
        });
    });

    const userRow = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_user' });
    await userRow.locator('button[data-act="recovery"]').click();
    await page.locator('#securityActionPassword').fill('browser-password');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await requestStarted;

    await page.locator('#closeSecurityAction').click();
    const adminRow = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_admin' });
    await adminRow.locator('button[data-act="recovery"]').click();
    await expect(page.locator('#securityActionHint')).toContainText('e2e_admin');

    const responseFinished = page.waitForResponse(response => (
        response.url().includes('/admin/api/users/')
        && response.url().endsWith('/recovery')
        && response.request().method() === 'POST'
    ));
    releaseResponse();
    await responseFinished;
    await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 0)));

    await expect(page.locator('#securityActionResult')).toHaveValue('');
    await expect(page.locator('#securityActionResultGroup')).toHaveClass(/hidden/);
});

test('recovery submission is single-flight and clears reauthentication fields', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    let releaseResponse;
    let markRequestStarted;
    let requestCount = 0;
    const responseGate = new Promise(resolve => { releaseResponse = resolve; });
    const requestStarted = new Promise(resolve => { markRequestStarted = resolve; });
    await page.route('**/admin/api/users/*/recovery', async route => {
        requestCount += 1;
        markRequestStarted();
        await responseGate;
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ codes: ['single-valid-recovery-code'] })
        });
    });

    const userRow = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_user' });
    await userRow.locator('button[data-act="recovery"]').click();
    await page.locator('#securityActionPassword').fill('browser-password');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await requestStarted;

    await expect(page.locator('#submitSecurityAction')).toBeDisabled();
    await page.locator('#submitSecurityAction').click({ force: true });
    expect(requestCount).toBe(1);

    releaseResponse();
    await expect(page.locator('#securityActionResult')).toHaveValue('single-valid-recovery-code');
    await expect(page.locator('#securityActionPassword')).toHaveValue('');
    await expect(page.locator('#securityActionConfirmation')).toHaveValue('');
    await expect(page.locator('#submitSecurityAction')).toBeEnabled();
});

test('closing and reopening cannot overlap recovery rotations', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    let releaseResponse;
    let markRequestStarted;
    let requestCount = 0;
    const responseGate = new Promise(resolve => { releaseResponse = resolve; });
    const requestStarted = new Promise(resolve => { markRequestStarted = resolve; });
    await page.route('**/admin/api/users/*/recovery', async route => {
        requestCount += 1;
        markRequestStarted();
        await responseGate;
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ codes: ['stale-first-recovery-code'] })
        });
    });

    const userRow = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_user' });
    await userRow.locator('button[data-act="recovery"]').click();
    await page.locator('#securityActionPassword').fill('browser-password');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await requestStarted;

    await page.locator('#closeSecurityAction').click();
    await userRow.locator('button[data-act="recovery"]').click();
    await expect(page.locator('#submitSecurityAction')).toBeDisabled();
    await page.locator('#submitSecurityAction').click({ force: true });
    expect(requestCount).toBe(1);

    releaseResponse();
    await expect(page.locator('#submitSecurityAction')).toBeEnabled();
    await expect(page.locator('#securityActionResult')).toHaveValue('');
    await expect(page.locator('#securityActionResultGroup')).toHaveClass(/hidden/);
});
