const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

async function authGeometry(page) {
    return page.evaluate(() => {
        const dock = document.querySelector('.auth-access-dock');
        const dockRect = dock.getBoundingClientRect();
        const contextRect = document.querySelector('.auth-context-panel')
            ?.getBoundingClientRect();
        const formRect = document.querySelector('.auth-form-panel')
            ?.getBoundingClientRect();
        const visibleChildren = Array.from(dock.querySelectorAll('*')).filter(element => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return style.display !== 'none'
                && style.visibility !== 'hidden'
                && rect.width > 0
                && rect.height > 0;
        });
        const escapedChildren = visibleChildren.filter(element => {
            const rect = element.getBoundingClientRect();
            return rect.left < dockRect.left - 1
                || rect.right > dockRect.right + 1;
        }).map(element => ({
            id: element.id,
            className: element.className,
            text: element.textContent.trim().slice(0, 80),
        }));
        return {
            viewportWidth: innerWidth,
            viewportHeight: innerHeight,
            documentWidth: document.documentElement.scrollWidth,
            bodyWidth: document.body.scrollWidth,
            documentHeight: document.documentElement.scrollHeight,
            bodyHeight: document.body.scrollHeight,
            dock: {
                left: dockRect.left,
                right: dockRect.right,
                top: dockRect.top,
                bottom: dockRect.bottom,
                width: dockRect.width,
                height: dockRect.height,
            },
            context: contextRect ? {
                left: contextRect.left,
                right: contextRect.right,
                top: contextRect.top,
                bottom: contextRect.bottom,
                width: contextRect.width,
            } : null,
            form: formRect ? {
                left: formRect.left,
                right: formRect.right,
                top: formRect.top,
                bottom: formRect.bottom,
                width: formRect.width,
            } : null,
            escapedChildren,
        };
    });
}

async function expectAuthContained(page, { allowVerticalScroll = false } = {}) {
    const layout = await authGeometry(page);
    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.bodyWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.dock.left).toBeGreaterThanOrEqual(0);
    expect(layout.dock.right).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.escapedChildren).toEqual([]);
    if (!allowVerticalScroll) {
        expect(layout.dock.top).toBeGreaterThanOrEqual(0);
        expect(layout.dock.bottom).toBeLessThanOrEqual(layout.viewportHeight);
        expect(layout.documentHeight).toBeLessThanOrEqual(layout.viewportHeight);
        expect(layout.bodyHeight).toBeLessThanOrEqual(layout.viewportHeight);
    }
    return layout;
}

test('authentication family fits a 1280x720 viewport without page scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });

    await page.goto('/login');
    await expect(page.locator('#localLoginForm')).toBeVisible();
    await expectAuthContained(page);

    await page.goto('/register');
    await expect(page.locator('#registerForm')).toBeVisible();
    await expectAuthContained(page);

    await login(page);
    await page.goto('/change-password');
    await expect(page.locator('#changePasswordForm')).toBeVisible();
    await expectAuthContained(page);
});

test('auth workbench uses seventy percent of desktop width and keeps two clear columns', async ({ page }) => {
    await page.setViewportSize({ width: 3440, height: 1440 });
    await page.goto('/login');

    const layout = await expectAuthContained(page);
    expect(layout.dock.width / layout.viewportWidth).toBeGreaterThanOrEqual(0.69);
    expect(layout.dock.width / layout.viewportWidth).toBeLessThanOrEqual(0.71);
    expect(layout.dock.height / layout.viewportHeight).toBeGreaterThanOrEqual(0.69);
    expect(layout.dock.height / layout.viewportHeight).toBeLessThanOrEqual(0.71);
    expect(layout.context).not.toBeNull();
    expect(layout.form).not.toBeNull();
    expect(layout.context.right).toBeLessThanOrEqual(layout.form.left + 1);
    expect(layout.context.width).toBeGreaterThanOrEqual(layout.dock.width * 0.34);
    expect(layout.form.width).toBeGreaterThanOrEqual(layout.dock.width * 0.5);
    await expect(page.locator('.auth-product-logo')).toBeVisible();
    await expect(page.locator('.auth-product-version')).toHaveCount(0);
    await expect(page.locator('[data-auth-mode="password"]')).toBeVisible();
    await expect(page.locator('[data-auth-mode="passkey"]')).toBeVisible();
    await expect(page.locator('[data-auth-mode="oidc"]')).toBeVisible();
});

test('mobile login keeps every sign-in method and the primary action in the first viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });

    await page.goto('/login');
    await expectAuthContained(page);
    await expect(page.locator('.auth-product-logo')).toBeVisible();
    await expect(page.locator('.auth-context-copy')).toBeHidden();
    const signInMethods = page.locator('.auth-method-option');
    await expect(signInMethods).toHaveCount(3);
    for (const method of await signInMethods.all()) {
        await expect(method).toBeVisible();
    }
    await expect(page.locator('#localLoginForm .btn-primary')).toBeVisible();

    await page.goto('/register');
    await expectAuthContained(page, { allowVerticalScroll: true });
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

    await expect(page.locator('#passkeyLoginBtn')).toContainText('Mit Passkey anmelden');
    await expect(page.locator('#oidcLoginBtn')).toContainText('Mit Identitätsanbieter anmelden');
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
