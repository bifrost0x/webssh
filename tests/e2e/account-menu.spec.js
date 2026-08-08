const { test, expect } = require('playwright/test');
const { login, openProfileManagement } = require('./helpers');

test('account menu exposes workspace pulse and persists close confirmation', async ({ page }) => {
    await login(page);

    await page.locator('#accountBtnHeader').click();
    const dropdown = page.locator('#accountDropdownHeader');
    await expect(dropdown).toBeVisible();
    for (const selector of [
        '#accountProfileCard',
        '#accountWorkspacePulse',
        '#accountSettingsBtn',
        '#securityCenterBtn',
        '#accountShortcutsBtn',
        '#adminPanelBtn',
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
    const settingsModal = page.locator('#settingsModal');
    const closeConfirmation = page.locator('#confirmSessionCloseInput');
    await expect(settingsModal).toHaveClass(/show/);
    await expect(dropdown).toBeHidden();
    await expect(page.locator('#settingsThemeSelect')).toHaveValue('glass');
    await expect(page.locator('#settingsLanguageSelect')).not.toHaveValue('');
    await expect(page.locator('#scrollbackInput')).toHaveValue('150');
    await expect(closeConfirmation).toBeChecked();

    await closeConfirmation.uncheck();
    await expect(closeConfirmation).not.toBeDisabled();
    await expect(page.locator('body')).toHaveAttribute('data-confirm-session-close', 'false');

    await page.reload();
    await expect(page.locator('body')).toHaveAttribute('data-confirm-session-close', 'false');
    await page.locator('#accountBtnHeader').click();
    await page.locator('#accountSettingsBtn').click();
    await expect(closeConfirmation).not.toBeChecked();
    await closeConfirmation.check();
    await expect(closeConfirmation).not.toBeDisabled();
    await page.locator('#closeSettingsModal').click();
    await expect(page.locator('#accountBtnHeader')).toBeFocused();
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

    await page.locator('#mobileMenuBtn').click();
    await page.locator('#accountBtnHeader').click();

    const dropdown = page.locator('#accountDropdownHeader');
    const bounds = await dropdown.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
    await expect(page.locator('#accountSettingsBtn')).toBeVisible();
    await expect(page.locator('#logoutBtn')).toBeVisible();

    await page.locator('#accountSettingsBtn').click();
    await expect(page.locator('#settingsModal')).toHaveClass(/show/);
    await expect(page.locator('#scrollbackInput')).toBeVisible();
    await expect(page.locator('#confirmSessionCloseInput')).toBeVisible();
});
