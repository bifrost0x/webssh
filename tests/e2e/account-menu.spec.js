const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

test('account menu keeps one accessible group open and preserves nested actions', async ({ page }) => {
    await login(page);

    await page.locator('#accountBtnHeader').click();
    const dropdown = page.locator('#accountDropdownHeader');
    const preferencesToggle = page.locator('#accountPreferencesToggle');
    const connectionsToggle = page.locator('#accountConnectionsToggle');
    const securityToggle = page.locator('#accountSecurityToggle');
    const preferencesGroup = page.locator('#accountPreferencesGroup');
    const connectionsGroup = page.locator('#accountConnectionsGroup');
    const securityGroup = page.locator('#accountSecurityGroup');

    await expect(dropdown).toBeVisible();
    await expect(preferencesGroup).toBeHidden();
    await expect(connectionsGroup).toBeHidden();
    await expect(securityGroup).toBeHidden();

    await preferencesToggle.focus();
    await preferencesToggle.press('Enter');
    await expect(preferencesToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(preferencesGroup).toBeVisible();

    await connectionsToggle.click();
    await expect(preferencesToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(preferencesGroup).toBeHidden();
    await expect(connectionsToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(connectionsGroup).toBeVisible();

    await securityToggle.click();
    await expect(connectionsToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(connectionsGroup).toBeHidden();
    await expect(securityToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(securityGroup).toBeVisible();

    await connectionsToggle.click();
    await page.locator('#manageKeysBtn').click();
    await expect(page.locator('#keyManagementModal')).toHaveClass(/show/);
    await expect(dropdown).toBeHidden();

    await page.locator('#closeKeyModal').click();
    await page.locator('#accountBtnHeader').click();
    await expect(preferencesGroup).toBeHidden();
    await expect(connectionsGroup).toBeHidden();
    await expect(securityGroup).toBeHidden();
    await expect(preferencesToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(connectionsToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(securityToggle).toHaveAttribute('aria-expanded', 'false');
});

test('account menu stays inside a mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);

    await page.locator('#mobileMenuBtn').click();
    await page.locator('#accountBtnHeader').click();
    await page.locator('#accountPreferencesToggle').click();

    const dropdown = page.locator('#accountDropdownHeader');
    const bounds = await dropdown.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
    await expect(page.locator('#scrollbackInput')).toBeVisible();
    await expect(page.locator('#logoutBtn')).toBeVisible();
});
