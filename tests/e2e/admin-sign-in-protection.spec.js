const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

async function completeStepUp(page) {
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(page.locator('#stepUpModal')).toBeHidden();
}

async function openAuthenticationSettings(page) {
    await page.goto('/settings#authentication');
    await expect(page.locator('#signInProtection')).toBeVisible();
    await expect(page.locator('#signInProtectionSave')).toBeEnabled();
}

test('sign-in protection values persist across a reload', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    const prefix = page.locator('#signInIpv6Prefix');
    const globalLimit = page.locator('#signInUsernameGlobalLimit');
    const perSource = page.locator('#signInUsernameLimit');
    const original = {
        prefix: await prefix.inputValue(),
        globalLimit: await globalLimit.inputValue(),
    };
    // The browser cases share this server; only raise generous values.
    expect(Number(await perSource.inputValue())).toBeGreaterThanOrEqual(10);
    try {
        await prefix.fill('96');
        await globalLimit.fill('999');
        await page.locator('#signInProtectionSave').click();
        await completeStepUp(page);
        await expect(page.locator('#signInProtectionStatus')).toHaveText('Settings saved');

        await page.reload();
        await expect(page.locator('#signInProtectionSave')).toBeEnabled();
        await expect(prefix).toHaveValue('96');
        await expect(globalLimit).toHaveValue('999');
    } finally {
        await openAuthenticationSettings(page);
        await prefix.fill(original.prefix);
        await globalLimit.fill(original.globalLimit);
        await page.locator('#signInProtectionSave').click();
        await completeStepUp(page);
        await expect(page.locator('#signInProtectionStatus')).toHaveText('Settings saved');
    }
});

test('an out-of-range value shows an inline error without asking for reauthentication', async ({page}) => {
    await login(page);
    let writes = 0;
    page.on('request', request => {
        if (request.method() === 'POST' && request.url().includes('/admin/api/settings')) { writes += 1; }
    });
    await openAuthenticationSettings(page);
    const prefix = page.locator('#signInIpv6Prefix');
    const error = page.locator('#signInIpv6PrefixError');
    const saved = await prefix.inputValue();

    await prefix.fill('40');
    await page.locator('#signInProtectionSave').click();

    await expect(error).toBeVisible();
    await expect(error).toHaveText('Enter a whole number from 48 to 128.');
    await expect(prefix).toHaveAttribute('aria-invalid', 'true');
    await expect(prefix).toBeFocused();
    await expect(page.locator('#stepUpModal')).toBeHidden();
    expect(writes).toBe(0);

    await page.reload();
    await expect(page.locator('#signInProtectionSave')).toBeEnabled();
    await expect(prefix).toHaveValue(saved);
    await expect(error).toBeHidden();
    await expect(prefix).not.toHaveAttribute('aria-invalid', 'true');
});

test('help lines name the defaults and the tailnet setting states whether it applies', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    await expect(page.locator('#signInUsernameLimitHint')).toContainText('Default 10.');
    await expect(page.locator('#signInUsernameGlobalLimitHint')).toContainText('Default 100');
    await expect(page.locator('#signInIpv6PrefixHint')).toContainText('Default 128:');
    await expect(page.locator('#signInProtection [role="alert"]')).toHaveCount(0);
    await page.goto('/settings#integrations');
    // The E2E server runs with Tailscale SSH enabled.
    await expect(page.locator('#tailnetRestrictionState'))
        .toHaveText('Tailscale SSH is enabled on this server, so this setting is in effect.');
});

test('rejected and throttled reauthentication is answered inside the open dialog', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    const answers = [
        {status: 429, json: {error: 'Too many attempts. Try again in 30 seconds.', code: 'rate_limited', retry_after: 30}},
        {status: 403, json: {error: 'Step-up authentication failed', code: 'invalid_value'}},
    ];
    await page.route('**/api/step-up/password', route => {
        const answer = answers.shift();
        return answer ? route.fulfill(answer) : route.fallback();
    });
    await page.locator('#signInProtectionSave').click();
    await expect(page.locator('#stepUpModal')).toBeVisible();
    const password = page.locator('#stepUpPassword');
    const error = page.locator('#stepUpError');

    await password.fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(error).toHaveText('Too many attempts. Try again in 30 s.');
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await expect(password).toHaveValue('');
    await expect(password).toBeFocused();

    await password.fill('wrong-password');
    await page.locator('#stepUpSubmit').click();
    await expect(error).toHaveText('Authentication failed. Check the value and try again.');
    await expect(page.locator('#stepUpModal')).toBeVisible();

    await password.fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(page.locator('#stepUpModal')).toBeHidden();
    await expect(page.locator('#signInProtectionStatus')).toHaveText('Settings saved');
    await expect(error).toBeHidden();
});

test('a reauthentication refusal that a new value cannot fix ends the dialog', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    let attempts = 0;
    await page.route('**/api/step-up/password', route => {
        attempts += 1;
        return route.fulfill({status: 403, json: {error: 'Step-up authentication failed', code: 'step_up_failed'}});
    });
    await page.locator('#signInProtectionSave').click();
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(page.locator('#stepUpModal')).toBeHidden();
    await expect(page.locator('#signInProtectionStatus')).toHaveText(
        'Additional authentication is not available for this account right now. Reload the page and try again.'
    );
    expect(attempts).toBe(1);
});

test('a ceiling below the per-source limit is rejected before reauthentication', async ({page}) => {
    await login(page);
    let writes = 0;
    page.on('request', request => {
        if (request.method() === 'POST' && request.url().includes('/admin/api/settings')) { writes += 1; }
    });
    await openAuthenticationSettings(page);
    const perSource = page.locator('#signInUsernameLimit');
    const ceiling = page.locator('#signInUsernameGlobalLimit');
    await ceiling.fill(String(Number(await perSource.inputValue()) - 1));
    await page.locator('#signInProtectionSave').click();

    await expect(page.locator('#signInUsernameGlobalLimitError'))
        .toHaveText('Attempts from all sources must be at least the attempts per source.');
    await expect(ceiling).toHaveAttribute('aria-invalid', 'true');
    await expect(ceiling).toBeFocused();
    await expect(page.locator('#stepUpModal')).toBeHidden();
    expect(writes).toBe(0);
});

test('a server-side conflict is shown as a translated field error', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    await page.route('**/admin/api/settings', route => {
        if (route.request().method() !== 'POST') { return route.fallback(); }
        return route.fulfill({status: 400, json: {
            error: 'login_username_global_limit must not be lower than login_username_limit',
            code: 'global_limit_below_source_limit', setting: 'login_username_global_limit',
        }});
    });
    const ceiling = page.locator('#signInUsernameGlobalLimit');
    const draft = await ceiling.inputValue();
    await page.locator('#signInProtectionSave').click();
    await completeStepUp(page);

    await expect(page.locator('#signInUsernameGlobalLimitError'))
        .toHaveText('Attempts from all sources must be at least the attempts per source.');
    await expect(page.locator('#signInProtectionStatus'))
        .toHaveText('Attempts from all sources must be at least the attempts per source.');
    await expect(ceiling).toHaveValue(draft);
});

test('an unsaved draft survives a settings reload from switching sections', async ({page}) => {
    await login(page);
    await openAuthenticationSettings(page);
    const prefix = page.locator('#signInIpv6Prefix');
    const perSource = page.locator('#signInUsernameLimit');
    const saved = await perSource.inputValue();
    await prefix.fill('40');
    await page.locator('#signInProtectionSave').click();
    await expect(page.locator('#signInIpv6PrefixError')).toBeVisible();

    const reloaded = page.waitForResponse(response => response.url().includes('/admin/api/settings')
        && response.request().method() === 'GET');
    await page.locator('.admin-tab[data-settings-section="registration"]').click();
    await reloaded;
    const reloadedAgain = page.waitForResponse(response => response.url().includes('/admin/api/settings')
        && response.request().method() === 'GET');
    await page.locator('.admin-tab[data-settings-section="authentication"]').click();
    await reloadedAgain;

    await expect(prefix).toHaveValue('40');
    await expect(page.locator('#signInIpv6PrefixError')).toBeVisible();
    await expect(prefix).toHaveAttribute('aria-invalid', 'true');
    await expect(perSource).toHaveValue(saved);
});

test('the tailnet restriction toggle persists across a reload', async ({page}) => {
    await login(page);
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingTailnetRestriction');
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    try {
        await toggle.setChecked(false);
        await completeStepUp(page);
        await expect(toggle).toBeEnabled();
        await page.reload();
        await expect(toggle).toBeEnabled();
        await expect(toggle).not.toBeChecked();
    } finally {
        if (!(await toggle.isChecked())) {
            await toggle.setChecked(true);
            await completeStepUp(page);
            await expect(toggle).toBeEnabled();
            await expect(toggle).toBeChecked();
        }
    }
});

test('sign-in protection fits a phone screen', async ({page}) => {
    await page.setViewportSize({width: 375, height: 812});
    await login(page);
    await openAuthenticationSettings(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    for (const id of ['#signInUsernameLimit', '#signInUsernameGlobalLimit', '#signInIpv6Prefix']) {
        const box = await page.locator(id).boundingBox();
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(375);
    }
});
