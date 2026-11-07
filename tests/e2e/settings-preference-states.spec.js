const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test('boolean preference labels follow persisted state, language and failed saves', async ({page}) => {
    await login(page);
    await page.goto('/settings#preferences');
    const input = page.locator('#confirmSessionCloseInput');
    const label = input.locator('..').locator('span');
    await expect(input).not.toBeChecked();
    await expect(label).toHaveText('Disabled');
    try {
    await input.check();
    await expect(input).toBeEnabled();
    await expect(label).toHaveText('Enabled');
    await page.locator('#settingsLanguageSelect').selectOption('de');
    await expect(label).toHaveText('Aktiviert');
    await page.route('**/api/account/preferences', route => route.fulfill({
        status: 503, contentType: 'application/json', body: JSON.stringify({error: 'Temporarily unavailable'}),
    }));
    // A rejected write can restore the checkbox before uncheck() verifies its
    // postcondition. Assert the attempted mutation and the rollback separately.
    const rejectedWrite = page.waitForRequest(request => request.url().endsWith('/api/account/preferences') && request.method() === 'POST');
    await input.click();
    expect((await rejectedWrite).postDataJSON().confirm_session_close).toBe(false);
    await expect(input).toBeEnabled();
    await expect(input).toBeChecked();
    await expect(label).toHaveText('Aktiviert');
    await expect(page.locator('#settingsPreferenceStatus')).toHaveClass(/text-error/);
    await page.unroute('**/api/account/preferences');
    await input.uncheck();
    await expect(input).toBeEnabled();
    await expect(label).toHaveText('Deaktiviert');
    await page.reload();
    await expect(input).not.toBeChecked();
    await expect(label).toHaveText('Deaktiviert');
    await assertNoExternalRequests(page);
    } finally {
        await page.unroute('**/api/account/preferences');
        const restored = await page.evaluate(async () => {
            const response = await fetch('/api/account/preferences', {
                method:'POST', headers:{'Content-Type':'application/json',
                    'X-CSRFToken':document.querySelector('meta[name="csrf-token"]').content},
                body:JSON.stringify({confirm_session_close:false}),
            });
            return response.ok;
        });
        expect(restored).toBe(true);
    }
});

test('scrollback storage failure preserves the saved value and allows retry', async ({page}) => {
    await login(page);
    await page.goto('/settings#preferences');
    const input = page.locator('#scrollbackInput');
    const status = page.locator('#settingsPreferenceStatus');
    await input.fill('750');
    await input.press('Tab');
    await expect(status).toHaveText('Scrollback saved in this browser.');
    await page.evaluate(() => {
        window.restoreAuditStorage = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key, value) {
            if (key === 'terminalScrollback') throw new DOMException('Storage full', 'QuotaExceededError');
            return window.restoreAuditStorage.call(this, key, value);
        };
    });
    await input.fill('900');
    await input.press('Tab');
    await expect(status).toHaveClass(/text-error/);
    await expect(input).toHaveValue('750');
    expect(await page.evaluate(() => localStorage.getItem('terminalScrollback'))).toBe('750');
    await page.evaluate(() => { Storage.prototype.setItem = window.restoreAuditStorage; });
    await input.fill('900');
    await input.press('Tab');
    await expect(status).toHaveText('Scrollback saved in this browser.');
    await page.reload();
    await expect(input).toHaveValue('900');
    await assertNoExternalRequests(page);
});

test('cancelled admin authentication is localized and leaves backup creation usable', async ({page}) => {
    await login(page);
    await page.goto('/settings#preferences');
    await page.locator('#settingsLanguageSelect').selectOption('de');
    await page.goto('/settings#backup');
    await page.locator('#backupCreateBtn').click();
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await page.locator('#stepUpCancelButton').click();
    await expect(page.locator('#stepUpModal')).not.toBeVisible();
    await expect(page.locator('#backupCreateStatus')).toHaveText('Zusätzliche Authentifizierung wurde abgebrochen');
    await expect(page.locator('#backupCreateBtn')).toBeEnabled();
    await expect(page.locator('#backupDownloadBtn')).toBeDisabled();
    await page.locator('#backupCreateBtn').click();
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await expect(page.locator('#stepUpPassword')).toHaveValue('');
    await page.locator('#stepUpCancel').click();
    await expect(page.locator('#backupCreateBtn')).toBeEnabled();
    await assertNoExternalRequests(page);
});
