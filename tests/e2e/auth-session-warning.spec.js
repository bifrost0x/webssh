const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

for (const [language, closeLabel] of Object.entries({
    en: 'Close', vi: 'Đóng', de: 'Schließen', fr: 'Fermer', es: 'Cerrar', zh: '关闭',
})) {
    test(`authentication expiry warnings can be dismissed without delaying expiry in ${language}`, async ({ page }) => {
        await page.setViewportSize({ width: language === 'de' ? 390 : 1440, height: 900 });
        await login(page);
        const message = await page.evaluate(lang => {
            window.i18n.setLanguage(lang);
            let now = 1000;
            const timers = [];
            const guard = window.AuthSessionGuard.create({
                expiresAt: 301000, serverNow: 1000, now: () => now,
                setTimeout: (callback, delay) => { timers.push({ callback, delay }); return timers.length; },
            });
            window.__advanceAuthWarning = () => {
                const timer = timers.shift();
                now += timer.delay;
                timer.callback();
            };
            window.__authWarningTimers = timers;
            guard.schedule();
            return window.i18n.t('authSession.expiringFive');
        }, language);
        const notices = page.locator('#notificationContainer .notification');
        const first = notices.filter({ hasText: message });
        await expect(first).toBeVisible();
        await first.getByRole('button', { name: closeLabel, exact: true }).click();
        await expect(first).toHaveCount(0);
        await expect(page).toHaveURL(/\/$/);
        expect(await page.evaluate(() => window.__authWarningTimers[0].delay)).toBe(240000);

        const finalMessage = await page.evaluate(() => {
            window.__advanceAuthWarning();
            return window.i18n.t('authSession.expiringOne');
        });
        const final = notices.filter({ hasText: finalMessage });
        await expect(final).toBeVisible();
        await final.getByRole('button', { name: closeLabel, exact: true }).focus();
        await page.keyboard.press('Enter');
        await expect(final).toHaveCount(0);
        expect(await page.evaluate(() => window.__authWarningTimers[0].delay)).toBe(60000);
        await expect(page).toHaveURL(/\/$/);
        await assertNoExternalRequests(page);
    });
}
