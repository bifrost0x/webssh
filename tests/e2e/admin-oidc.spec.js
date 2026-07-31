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
