const { test, expect } = require('playwright/test');

test('registers a passkey and signs in with a virtual authenticator', async ({
    page,
    context,
}) => {
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport: 'internal',
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });

    try {
        const origin = `http://localhost:${process.env.WEBSSH_E2E_PORT || '4173'}`;
        await page.goto(origin + '/login');
        await page.locator('#username').fill('e2e_user');
        await page.locator('#password').fill('browser-password');
        await page.locator('form button[type="submit"]').click();
        await expect(page).toHaveURL(/\/$/);

        await page.goto(origin + '/security');
        const ceremony = Promise.race([
            page.locator('#passkeyList').getByText('E2E passkey').waitFor()
                .then(() => 'registered'),
            page.locator('.notification-error').waitFor()
                .then(async () => page.locator('.notification-error').textContent()),
            page.waitForEvent('pageerror').then(error => error.message),
        ]);
        await page.locator('#passkeyAddBtn').click();
        await expect(page.locator('#securityConfirmationModal')).toHaveClass(/show/);
        await page.locator('#securityConfirmationPassword').fill('browser-password');
        await page.locator('#securityConfirmationLabel').fill('E2E passkey');
        await page.locator('#securityConfirmationSubmit').click();
        expect(await ceremony).toBe('registered');

        const logoutStatus = await page.evaluate(async () => {
            const csrf = document.querySelector('meta[name="csrf-token"]').content;
            const response = await fetch('/logout', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrf },
            });
            return response.status;
        });
        expect(logoutStatus).toBe(200);
        await page.goto(origin + '/login');
        const authentication = Promise.race([
            page.waitForURL(/\/$/).then(() => 'authenticated'),
            page.waitForEvent('dialog').then(async dialog => {
                const message = dialog.message();
                await dialog.dismiss();
                return message;
            }),
        ]);
        const optionsResponse = page.waitForResponse(
            response => response.url().endsWith('/api/webauthn/auth/options'),
        );
        await page.locator('#passkeyLoginBtn').click();
        const response = await optionsResponse;
        if (!response.ok()) {
            throw new Error(`Authentication options failed: ${await response.text()}`);
        }
        expect(await authentication).toBe('authenticated');
    } finally {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
        await cdp.send('WebAuthn.disable');
    }
});
