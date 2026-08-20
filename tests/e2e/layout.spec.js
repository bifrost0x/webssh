const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

test('login alternatives remain reachable in a 720px-high viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto('/login');
    const initialCardTop = await page.locator('.auth-card').evaluate(
        element => element.getBoundingClientRect().top
    );
    const oidcLogin = page.locator('#oidcLoginBtn');
    await oidcLogin.scrollIntoViewIfNeeded();
    await expect(oidcLogin).toBeVisible();
    await expect(page.locator('#recoveryLoginBtn')).toHaveCount(0);
    const layout = await page.evaluate(() => {
        const rect = document.querySelector('#oidcLoginBtn').getBoundingClientRect();
        return {
            viewportHeight: window.innerHeight,
            bodyClientHeight: document.body.clientHeight,
            bodyScrollHeight: document.body.scrollHeight,
            alternativeTop: rect.top,
            alternativeBottom: rect.bottom,
            htmlOverflowY: getComputedStyle(document.documentElement).overflowY,
            bodyOverflowY: getComputedStyle(document.body).overflowY,
        };
    });

    expect(initialCardTop).toBeGreaterThanOrEqual(0);
    expect(layout.alternativeTop).toBeGreaterThanOrEqual(0);
    expect(layout.alternativeBottom).toBeLessThanOrEqual(layout.viewportHeight);
    expect(layout.htmlOverflowY).not.toBe('hidden');
    expect(layout.bodyOverflowY).not.toBe('hidden');
});

test('admin remains horizontally contained on a 390px viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);
    await page.goto('/admin');

    const layout = await page.evaluate(() => {
        const main = document.querySelector('.admin-main').getBoundingClientRect();
        return {
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            bodyWidth: document.body.scrollWidth,
            mainLeft: main.left,
            mainRight: main.right,
        };
    });

    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.bodyWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.mainLeft).toBeGreaterThanOrEqual(0);
    expect(layout.mainRight).toBeLessThanOrEqual(layout.viewportWidth);
});

test('admin audit logs remain mouse-scrollable in a short desktop viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 320 });
    await login(page);
    await page.goto('/admin');
    await page.locator('.admin-tab[data-tab="audit"]').click();
    await expect(page.locator('#adminAuditBody tr')).not.toHaveCount(0);

    const main = page.locator('.admin-main');
    const layout = await main.evaluate(element => ({
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
        overflowY: getComputedStyle(element).overflowY,
    }));

    expect(layout.scrollHeight).toBeGreaterThan(layout.clientHeight);
    expect(['auto', 'scroll']).toContain(layout.overflowY);

    await main.hover();
    await page.mouse.wheel(0, 600);
    await expect.poll(() => main.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
});

test('admin security actions and empty host trust use user-facing copy', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    await expect(page.locator('button[data-act="recovery"]').first()).toHaveText('Recovery');
    await page.locator('.admin-tab[data-tab="settings"]').click();
    await expect(page.locator('#globalHostKeyList')).toContainText(
        'No global host keys stored.'
    );
    await expect(page.locator('#globalHostKeyList td')).toHaveAttribute('colspan', '5');
});

test('new login, security, and admin controls honor the stored locale', async ({ page }) => {
    await page.goto('/login');
    await page.evaluate(() => localStorage.setItem('language', 'de'));
    await page.reload();

    await expect(page.locator('#passkeyLoginBtn')).toHaveText('Mit Passkey anmelden');
    await expect(page.locator('#oidcLoginBtn')).toHaveText('Mit Identitätsanbieter anmelden');
    await expect(page.locator('#recoveryLoginBtn')).toHaveCount(0);

    await login(page);
    await page.goto('/security');
    await expect(page.locator('h1')).toContainText('Sicherheit');
    await expect(page.locator('#hostKeyRefresh')).toHaveText('Aktualisieren');
    await expect(page.locator('#passkeyAddBtn')).toHaveText('Passkey hinzufügen');
    await expect(page.locator('#recoveryGenerateBtn')).toHaveText(
        'Wiederherstellungscodes erstellen'
    );
    await page.locator('#passkeyAddBtn').click();
    await expect(page.locator('#securityConfirmationTitle')).toHaveText(
        'Sicherheitsaktion bestätigen'
    );
    await expect(page.locator('#securityConfirmationSubmit')).toHaveText('Weiter');
    await page.locator('#securityConfirmationCancel').click();

    await page.goto('/admin');
    await page.locator('.admin-tab[data-tab="settings"]').click();
    await expect(page.locator('label[for="auditRetention"]')).toContainText(
        'Audit-Aufbewahrungssicherungen'
    );
    await expect(page.locator('#globalHostKeyRefresh')).toHaveText('Aktualisieren');
    await expect(page.locator('#globalHostKeyList')).toContainText(
        'Keine globalen Host-Schlüssel gespeichert.'
    );
});
