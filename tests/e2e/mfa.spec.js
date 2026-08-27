const crypto = require('node:crypto');
const { test, expect } = require('playwright/test');

function decodeBase32(value) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const character of value.replace(/=+$/, '').toUpperCase()) {
        const index = alphabet.indexOf(character);
        if (index < 0) throw new Error('Invalid base32 secret');
        bits += index.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
        bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
    }
    return Buffer.from(bytes);
}

function totp(secret, timestamp) {
    const step = Math.floor(timestamp / 30_000);
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const digest = crypto.createHmac('sha1', decodeBase32(secret))
        .update(counter)
        .digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = (
        ((digest[offset] & 0x7f) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    );
    return String(binary % 1_000_000).padStart(6, '0');
}

test('enrolls optional TOTP and completes password plus MFA login', async ({
    page,
}) => {
    await page.goto('/login');
    await page.locator('#username').fill('e2e_mfa');
    await page.locator('#password').fill('browser-password');
    await page.locator('form button[type="submit"]').click();
    await expect(page).toHaveURL(/\/$/);

    await page.goto('/settings#factors');
    await expect(page.locator('#totpAddBtn')).toBeVisible();
    await page.locator('#totpAddBtn').click();
    await expect(page.locator('#securityConfirmationModal')).toHaveClass(/show/);
    await expect(page.locator('#securityConfirmationLabelGroup')).not.toHaveClass(/hidden/);
    await expect(page.locator('#securityConfirmationPasswordGroup')).toHaveClass(/hidden/);
    await page.locator('#securityConfirmationLabel').fill('E2E authenticator');
    await page.locator('#securityConfirmationSubmit').click();

    await expect(page.locator('#securityConfirmationPasswordGroup')).not.toHaveClass(/hidden/);
    await expect(page.locator('#securityConfirmationPassword')).toHaveAttribute(
        'type',
        'password',
    );
    await page.locator('#securityConfirmationPassword').fill('browser-password');
    await page.locator('#securityConfirmationSubmit').click();

    await expect(page.locator('#totpEnrollment')).not.toHaveClass(/hidden/);
    const secret = (await page.locator('#totpSecret').textContent()).trim();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    await page.locator('#totpActivationCode').fill(totp(secret, Date.now() - 30_000));
    await page.locator('#totpActivateBtn').click();
    await expect(page.locator('#totpRecoveryCodes')).toContainText(
        'will not be shown again',
    );
    await expect(page.locator('#totpList')).toContainText('E2E authenticator');
    await page.locator('[data-account-section="security-overview"]').click();
    await expect(page.locator('#securityMfaStatus')).toHaveText('MFA enabled');
    await expect(page.locator('#accountDisableMfaBtn')).toBeVisible();

    const browserStorage = await page.evaluate(() => ({
        local: Object.entries(localStorage),
        session: Object.entries(sessionStorage),
    }));
    expect(JSON.stringify(browserStorage)).not.toContain(secret);

    const logoutStatus = await page.evaluate(async () => {
        const csrf = document.querySelector('meta[name="csrf-token"]').content;
        const response = await fetch('/logout', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrf },
        });
        return response.status;
    });
    expect(logoutStatus).toBe(200);

    await page.goto('/login');
    await page.locator('#username').fill('e2e_mfa');
    await page.locator('#password').fill('browser-password');
    await page.locator('form button[type="submit"]').click();
    await expect(page.locator('#totpMfaPanel')).toBeVisible();
    await expect(page.locator('#authMfaMethodSwitcher')).toBeVisible();
    await expect(page.locator('#recoveryMfaPanel')).toBeHidden();
    await expect(page.locator('#passwordAuthenticationForms')).toHaveClass(/hidden/);
    await page.locator('[data-auth-mode="recovery"]').click();
    await expect(page.locator('#totpMfaPanel')).toBeHidden();
    await expect(page.locator('#recoveryMfaPanel')).toBeVisible();
    await page.locator('[data-auth-mode="totp"]').click();
    await expect(page.locator('#totpMfaPanel')).toBeVisible();
    await expect(page.locator('#recoveryMfaPanel')).toBeHidden();
    await page.locator('#totpMfaCode').fill(totp(secret, Date.now()));
    await page.locator('#submitTotpMfa').click();
    await expect(page).toHaveURL(/\/$/);

    await page.goto('/settings#factors');
    await expect(page.locator('#totpList')).toContainText('E2E authenticator');
    await page.locator('[data-account-section="security-overview"]').click();
    const dialogPromise = page.waitForEvent('dialog');
    const disableClick = page.locator('#accountDisableMfaBtn').click();
    const dialog = await dialogPromise;
    expect(dialog.message()).toContain('remove all authenticator apps');
    await dialog.accept();
    await disableClick;
    await expect(page.locator('#securityMfaStatus')).toHaveText('MFA optional');
    await expect(page.locator('#accountDisableMfaBtn')).toBeHidden();
    await page.locator('[data-account-section="factors"]').click();
    await expect(page.locator('#totpList')).toContainText(
        'No authenticator app is enrolled.',
    );
});

test('shows mixed MFA methods one at a time', async ({ page }) => {
    await page.goto('/login');
    await page.locator('#username').fill('e2e_mixed_mfa');
    await page.locator('#password').fill('browser-password');
    await page.locator('form button[type="submit"]').click();

    await expect(page.locator('#authMfaMethodSwitcher')).toBeVisible();
    await expect(page.locator('.auth-header')).toContainText('Two-factor authentication');
    await expect(page.locator('#cancelMfaLogin')).toBeVisible();
    await expect(page.locator('#totpMfaPanel > h2')).toHaveCount(0);
    await expect(page.locator('#totpMfaPanel > p')).toHaveCount(0);
    await expect(
        page.locator('[data-auth-mode-panel]:visible'),
    ).toHaveCount(1);

    await page.locator('[data-auth-mode="passkey"]').click();
    await expect(page.locator('#totpMfaPanel')).toBeHidden();
    await expect(page.locator('#passkeyLoginMode')).toBeVisible();
    await expect(
        page.locator('[data-auth-mode-panel]:visible'),
    ).toHaveCount(1);

    await page.locator('#cancelMfaLogin').click();
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator('#username')).toBeVisible();
});
