const { test, expect } = require('playwright/test');
const { login, openProfileManagement } = require('./helpers');

test('logout confirmation cancels safely and submits the existing protected logout', async ({ page }) => {
    await login(page);
    const logoutRequests = [];
    page.on('request', request => {
        if (new URL(request.url()).pathname === '/logout') logoutRequests.push(request);
    });
    await page.locator('#accountBtnHeader').click();
    page.once('dialog', dialog => dialog.dismiss());
    await page.locator('#logoutBtn').click();
    await expect(page).toHaveURL(/\/$/);
    expect(logoutRequests).toHaveLength(0);

    if (!(await page.locator('#logoutBtn').isVisible())) {
        await page.locator('#accountBtnHeader').click();
    }
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#logoutBtn').click();
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator('#username')).toBeVisible();
    expect(logoutRequests).toHaveLength(1);
    expect(logoutRequests[0].method()).toBe('POST');
    expect(new URLSearchParams(logoutRequests[0].postData()).get('csrf_token')).toBeTruthy();
});

test('account menu opens the Settings Center and persists close confirmation', async ({ page }) => {
    await login(page);
    const currentTheme = await page.locator('body').getAttribute('data-theme');

    await page.locator('#accountBtnHeader').click();
    const dropdown = page.locator('#accountDropdownHeader');
    await expect(dropdown).toBeVisible();
    for (const selector of [
        '#accountProfileCard',
        '#accountWorkspacePulse',
        '#accountSettingsBtn',
        '#accountShortcutsBtn',
        '#logoutBtn',
    ]) {
        await expect(page.locator(selector)).toBeVisible();
    }
    await expect(page.locator('#accountPulseSessions')).toHaveText('0');
    await expect(page.locator('#accountPulsePanes')).toHaveText('0');
    await expect(page.locator('#accountThemeBtn')).toHaveCount(0);
    await expect(page.locator('#accountLanguageBtn')).toHaveCount(0);
    await expect(page.locator('#changePasswordBtn')).toHaveCount(0);
    await expect(page.locator('#accountPreferencesToggle')).toHaveCount(0);
    await expect(page.locator('#accountConnectionsToggle')).toHaveCount(0);
    await expect(page.locator('#accountSecurityToggle')).toHaveCount(0);

    await page.locator('#accountSettingsBtn').click();
    const closeConfirmation = page.locator('#confirmSessionCloseInput');
    await expect(page).toHaveURL(/\/settings#preferences$/);
    await expect(page.getByText('Settings Center', { exact: true })).toBeVisible();
    await expect(page.locator('[data-account-panel="preferences"]')).toBeVisible();
    await expect(page.locator('#settingsThemeSelect')).toHaveValue(currentTheme);
    await expect(page.locator('#settingsLanguageSelect')).not.toHaveValue('');
    await expect(page.locator('#scrollbackInput')).toHaveValue('500');
    await expect(closeConfirmation).not.toBeChecked();
    const signInDuration = page.locator('#authenticationSessionDurationSelect');
    const initialDuration = await signInDuration.inputValue();
    expect(['30', '60', '120', '240', '480']).toContain(initialDuration);

    await signInDuration.selectOption('120');
    await expect(signInDuration).not.toBeDisabled();
    await expect(page.locator('body')).toHaveAttribute(
        'data-authentication-session-duration-minutes',
        '120',
    );

    await closeConfirmation.check();
    await expect(closeConfirmation).not.toBeDisabled();
    await expect(page.locator('body')).toHaveAttribute('data-confirm-session-close', 'true');

    await page.reload();
    await expect(page.locator('body')).toHaveAttribute('data-confirm-session-close', 'true');
    await expect(page.locator('[data-account-panel="preferences"]')).toBeVisible();
    await expect(closeConfirmation).toBeChecked();
    await expect(signInDuration).toHaveValue('120');
    await closeConfirmation.uncheck();
    await expect(closeConfirmation).not.toBeDisabled();
    await signInDuration.selectOption(initialDuration);
    await expect(signInDuration).not.toBeDisabled();

    await page.getByRole('link', { name: 'Back to Terminal' }).click();
    await page.locator('#accountBtnHeader').click();
    await expect(page.locator('#accountSettingsBtn')).toHaveAttribute('href', /\/settings#preferences$/);
});

test('hosts, jump hosts, and SSH keys switch through one asset navigation', async ({ page }) => {
    await login(page);
    await openProfileManagement(page);

    await expect(page.locator('#profileManagementModal [aria-current="page"]'))
        .toHaveAttribute('data-connection-asset', 'hosts');
    await page.locator('#profileManagementModal [data-connection-asset="keys"]').click();
    await expect(page.locator('#profileManagementModal')).not.toHaveClass(/show/);
    await expect(page.locator('#keyManagementModal')).toHaveClass(/show/);

    await page.locator('#keyManagementModal [data-connection-asset="jump-hosts"]').click();
    await expect(page.locator('#keyManagementModal')).not.toHaveClass(/show/);
    await expect(page.locator('#jumpHostManagementModal')).toHaveClass(/show/);

    await page.locator('#jumpHostManagementModal [data-connection-asset="hosts"]').click();
    await expect(page.locator('#jumpHostManagementModal')).not.toHaveClass(/show/);
    await expect(page.locator('#profileManagementModal')).toHaveClass(/show/);
});

test('account menu and settings stay inside a mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);

    await page.locator('#mobileMoreBtn').click();
    await page.locator('#accountBtnHeader').click();

    const dropdown = page.locator('#accountDropdownHeader');
    const bounds = await dropdown.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
    await expect(page.locator('#accountSettingsBtn')).toBeVisible();
    await expect(page.locator('#logoutBtn')).toBeVisible();
    const version = page.locator('#accountDropdownHeader [data-webssh-version]');
    await version.scrollIntoViewIfNeeded();
    await expect(version).toBeVisible();
    await expect(version).toHaveText(/^\d+\.\d+\.\d+( \([0-9a-f]{7}\))?$/);
    const support = page.locator('#accountSupportLink');
    await expect(support).toBeVisible();
    await expect(support).toHaveAttribute('href', 'https://github.com/bifrost0x/webssh?sponsor=1');
    await expect(support).toHaveAttribute('target', '_blank');
    await expect(support).toHaveAttribute('rel', 'noopener noreferrer');
    const versionBounds = await version.boundingBox();
    expect(versionBounds.x + versionBounds.width).toBeLessThanOrEqual(390);

    await page.locator('#accountSettingsBtn').click();
    await expect(page).toHaveURL(/\/settings#preferences$/);
    await expect(page.locator('[data-account-panel="preferences"]')).not.toHaveClass(/\bhidden\b/);
    await expect(page.locator('#scrollbackInput')).toBeVisible();
    await expect(page.locator('#confirmSessionCloseInput')).toBeVisible();
    await expect(page.locator('#authenticationSessionDurationSelect')).toBeVisible();
    const layout = await page.evaluate(() => ({
        viewport: window.innerWidth,
        document: document.documentElement.scrollWidth,
    }));
    expect(layout.document).toBeLessThanOrEqual(layout.viewport);
});

test('settings side panel lists the support links below the account facts', async ({ page }) => {
    await page.setViewportSize({ width: 1600, height: 1000 });
    await login(page, 'e2e_user', { workspace: false });
    await page.goto('/settings');

    const rail = page.locator('.settings-context-rail');
    const support = rail.locator('.settings-support-card');
    await expect(support).toBeVisible();
    const links = support.getByRole('link');
    await expect(links).toHaveCount(3);
    for (const [index, name] of ['GitHub Sponsors', 'Patreon', 'Buy Me a Coffee'].entries()) {
        await expect(links.nth(index)).toHaveAccessibleName(name);
    }
    const accountBounds = await rail.locator('.settings-account-card').boundingBox();
    const supportBounds = await support.boundingBox();
    expect(supportBounds.y).toBeGreaterThan(accountBounds.y + accountBounds.height);

    // Answer the new tab locally; the test must not reach the real site.
    await page.context().route('https://github.com/**', route => route.fulfill({ body: 'sponsors' }));
    const opened = page.context().waitForEvent('page');
    await support.getByRole('link', { name: 'GitHub Sponsors' }).click();
    const popup = await opened;
    expect(popup.url()).toBe('https://github.com/sponsors/bifrost0x');
    expect(await popup.evaluate(() => window.opener)).toBeNull();
    await popup.close();
    await expect(page).toHaveURL(/\/settings/);
});

test('administrators can hide the support links for all users', async ({ page }) => {
    async function setSupportLinks(enabled) {
        await page.goto('/settings#integrations');
        const toggle = page.locator('#settingSupportLinks');
        await expect(toggle).toBeEnabled();
        if ((await toggle.isChecked()) === enabled) return;
        await toggle.setChecked(enabled);
        await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
        await page.locator('#stepUpPassword').fill('browser-password');
        await page.locator('#stepUpSubmit').click();
        await expect(toggle).toBeEnabled();
        await expect(toggle).toBeChecked({ checked: enabled });
    }

    await page.setViewportSize({ width: 1600, height: 1000 });
    await login(page);
    await expect(page.locator('#settingSupportLinks')).toHaveCount(0);
    try {
        await setSupportLinks(false);
        await page.reload();
        await expect(page.locator('#settingSupportLinks')).not.toBeChecked();
        await expect(page.locator('.settings-support-card')).toHaveCount(0);
        await page.goto('/');
        await expect(page.locator('#accountSupportLink')).toHaveCount(0);
    } finally {
        await setSupportLinks(true);
    }
    await page.reload();
    await expect(page.locator('.settings-support-card')).toBeVisible();
});
