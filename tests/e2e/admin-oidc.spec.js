const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

async function completePasswordStepUp(page) {
    const modal = page.locator('#stepUpModal');
    await expect(modal).toHaveClass(/show/);
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(modal).not.toHaveClass(/show/);
}

async function clickUserAction(row, action) {
    await row.locator('.admin-action-menu > summary').click();
    await row.locator(`button[data-act="${action}"]`).click();
}

test('admin can inspect, unlink, and add an OIDC identity', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    const targetRow = page.locator('#adminUsersBody tr').filter({
        hasText: 'e2e_user',
    });
    await clickUserAction(targetRow, 'oidc-link');
    const modal = page.locator('#securityActionModal');
    await expect(modal).toHaveClass(/show/);
    await expect(modal.getByText('existing-e2e-subject')).toBeVisible();

    await page.locator('#securityActionConfirmation').fill('e2e_user');
    page.once('dialog', dialog => dialog.accept());
    await modal.locator('button[data-oidc-identity-id]').click();
    await completePasswordStepUp(page);
    await expect(modal.getByText('existing-e2e-subject')).toHaveCount(0);
    await expect(page.locator('#securityActionConfirmation')).toHaveValue('');

    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#securityActionSubject').fill('replacement-e2e-subject');
    await page.locator('#submitSecurityAction').click();
    await completePasswordStepUp(page);
    await expect(modal.getByText('replacement-e2e-subject')).toBeVisible();
    await expect(page.locator('#securityActionConfirmation')).toHaveValue('');
});

test('admin navigation and users become readable cards on a mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    await login(page);
    await page.goto('/admin');

    await expect(page.locator('.admin-tabs')).toBeHidden();
    const mobileSelect = page.locator('#settingsMobileSection');
    await expect(page.locator('.settings-mobile-navigation')).toBeVisible();
    await expect(mobileSelect).toBeVisible();
    await expect(mobileSelect).toHaveValue('users');
    const navigation = await mobileSelect.evaluate(element => {
        const rect = element.getBoundingClientRect();
        return {
            bounds: { left: rect.left, right: rect.right },
            optionLabels: [...element.options].map(option => option.textContent.trim()),
            viewportWidth: window.innerWidth,
        };
    });
    expect(navigation.bounds.left).toBeGreaterThanOrEqual(0);
    expect(navigation.bounds.right).toBeLessThanOrEqual(navigation.viewportWidth);
    expect(navigation.optionLabels).toContain('Preferences');
    expect(navigation.optionLabels).toContain('Users');
    expect(navigation.optionLabels).toContain('Backup & Restore');

    const compactLayout = await page.evaluate(() => {
        const header = document.querySelector('header .header-content').getBoundingClientRect();
        const brand = document.querySelector('.settings-brand').getBoundingClientRect();
        const back = document.querySelector('.settings-back-link').getBoundingClientRect();
        const search = document.querySelector('.admin-search-field').getBoundingClientRect();
        const filter = document.querySelector('.admin-user-filter-field').getBoundingClientRect();
        return {
            headerHeight: header.height,
            headerAligned: brand.top < back.bottom && back.top < brand.bottom,
            searchHeight: search.height,
            filterGap: filter.top - search.bottom,
        };
    });
    expect(compactLayout.headerHeight).toBeLessThanOrEqual(64);
    expect(compactLayout.headerAligned).toBe(true);
    expect(compactLayout.searchHeight).toBeLessThanOrEqual(70);
    expect(compactLayout.filterGap).toBeLessThanOrEqual(12);

    const row = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_user' });
    await expect(row).toBeVisible();
    const state = await row.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const cells = [...element.querySelectorAll('td')];
        const actions = element.querySelector('.admin-actions')?.getBoundingClientRect();
        return {
            display: getComputedStyle(element).display,
            labels: cells.map(cell => cell.dataset.label || ''),
            bounds: { left: bounds.left, right: bounds.right },
            actions: actions ? { left: actions.left, right: actions.right } : null,
            viewportWidth: window.innerWidth,
        };
    });

    expect(state.display).toBe('grid');
    expect(state.labels).toEqual([
        'ID',
        'User',
        'Role',
        'Status',
        'Created',
        'Last login',
        'Actions',
    ]);
    expect(state.bounds.left).toBeGreaterThanOrEqual(0);
    expect(state.bounds.right).toBeLessThanOrEqual(state.viewportWidth);
    expect(state.actions).not.toBeNull();
    expect(state.actions.left).toBeGreaterThanOrEqual(0);
    expect(state.actions.right).toBeLessThanOrEqual(state.viewportWidth);
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
    await clickUserAction(userRow, 'recovery');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await completePasswordStepUp(page);
    await requestStarted;

    await page.locator('#closeSecurityAction').click();
    const adminRow = page.locator('#adminUsersBody tr').filter({ hasText: 'e2e_admin' });
    await clickUserAction(adminRow, 'recovery');
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
    await clickUserAction(userRow, 'recovery');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await completePasswordStepUp(page);
    await requestStarted;

    await expect(page.locator('#submitSecurityAction')).toBeDisabled();
    await page.locator('#submitSecurityAction').click({ force: true });
    expect(requestCount).toBe(1);

    releaseResponse();
    await expect(page.locator('#securityActionResult')).toHaveValue('single-valid-recovery-code');
    await expect(page.locator('#stepUpPassword')).toHaveValue('');
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
    await clickUserAction(userRow, 'recovery');
    await page.locator('#securityActionConfirmation').fill('e2e_user');
    await page.locator('#submitSecurityAction').click();
    await completePasswordStepUp(page);
    await requestStarted;

    await page.locator('#closeSecurityAction').click();
    await clickUserAction(userRow, 'recovery');
    await expect(page.locator('#submitSecurityAction')).toBeDisabled();
    await page.locator('#submitSecurityAction').click({ force: true });
    expect(requestCount).toBe(1);

    releaseResponse();
    await expect(page.locator('#submitSecurityAction')).toBeEnabled();
    await expect(page.locator('#securityActionResult')).toHaveValue('');
    await expect(page.locator('#securityActionResultGroup')).toHaveClass(/hidden/);
});
