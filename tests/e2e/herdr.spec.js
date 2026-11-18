const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

/** Serve the global settings from memory and record what the page writes. */
async function mockSettings(page, values, answer = body => body) {
    const writes = [];
    await page.route('**/admin/api/settings', route => {
        const request = route.request();
        if (request.method() === 'POST') {
            const body = request.postDataJSON();
            writes.push(body);
            Object.assign(values, answer(body));
        }
        return route.fulfill({json: values});
    });
    return writes;
}

async function confirmStepUp(page) {
    await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
}

test('Herdr switch shows the stored setting', async ({page}) => {
    await login(page);
    await mockSettings(page, {registration_enabled: true, herdr_enabled: true});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    await expect(toggle).toHaveAccessibleName('Herdr Enabled');
    await expect(toggle).toHaveAccessibleDescription(/Disabled by default\. Disabling stops all Herdr queries/);
});

test('enabling Herdr sends only that setting after additional authentication', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    await toggle.check();
    await confirmStepUp(page);
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    expect(writes).toEqual([{herdr_enabled: true}]);
});

test('Herdr switch follows the server answer instead of the click', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false}, () => ({herdr_enabled: false}));
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await toggle.check();
    await confirmStepUp(page);
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    expect(writes).toHaveLength(1);
});

test('cancelled authentication restores the Herdr switch and writes nothing', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await toggle.check();
    await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
    await expect(toggle).toBeDisabled();
    await page.locator('#stepUpCancelButton').click();
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    expect(writes).toEqual([]);
});
