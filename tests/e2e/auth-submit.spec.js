const {test, expect} = require('playwright/test');

for (const mode of ['totp', 'recovery', 'switch']) test(`MFA pending request prevents repeated submission: ${mode}`, async ({page}) => {
    await page.goto('/login');
    await page.setContent('<input id="totpMfaCode"><button id="submitTotpMfa">Verify</button><p id="totpMfaError"></p><input id="recoveryMfaCode"><button id="submitRecoveryMfa">Recover</button><p id="recoveryMfaError"></p>');
    await page.addScriptTag({url: '/static/js/auth.js'});
    await page.evaluate(() => document.dispatchEvent(new Event('DOMContentLoaded')));
    let count = 0;
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    await page.route(/\/api\/(totp\/auth\/verify|auth\/recovery)$/, async route => {
        count += 1;
        await gate;
        await route.fulfill({status: 400, json: {error: 'Fixture rejected'}});
    });
    const input = page.locator(mode === 'recovery' ? '#recoveryMfaCode' : '#totpMfaCode');
    await input.fill(mode === 'recovery' ? 'fixture-code' : '123456');
    await input.press('Enter');
    await expect.poll(() => count).toBe(1);
    if (mode === 'switch') {
        await page.locator('#recoveryMfaCode').fill('fixture-code');
        await page.locator('#recoveryMfaCode').press('Enter');
    } else await input.press('Enter');
    release();
    await expect(page.locator(mode === 'recovery' ? '#recoveryMfaError' : '#totpMfaError')).toHaveText('Fixture rejected');
    expect(count).toBe(1);
    await expect(page.locator('#submitTotpMfa')).toBeEnabled();
    await expect(page.locator('#submitRecoveryMfa')).toBeEnabled();
});
