const {test, expect} = require('playwright/test');
const {assertNoExternalRequests, login, openProfileManagement} = require('./helpers');

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

/** Switch the real integration setting through the protected admin control. */
async function setIntegration(page, enabled) {
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    if (await toggle.isChecked() !== enabled) {
        await toggle.setChecked(enabled);
        await confirmStepUp(page);
        await expect(toggle).toBeEnabled();
    }
    await expect(toggle).toBeChecked({checked: enabled});
    await page.goto('/');
    await expect(page.locator('meta[name="herdr-enabled"]')).toHaveAttribute('content', String(enabled));
}

async function openHostEditor(page, name) {
    await openProfileManagement(page);
    if (name) {
        await page.locator('.profile-management-item').filter({hasText: name}).locator('.profile-inspect-button').click();
    } else {
        await page.locator('#newProfileBtn').click();
    }
    await expect(page.locator('#profileEditorForm')).toBeVisible();
    const advanced = page.locator('#profileAdvancedSettingsCard');
    if (!await advanced.evaluate(element => element.open)) await advanced.locator('summary').click();
}

const savedHost = (page, name) => page.evaluate(hostName => {
    const host = ProfileManager.profiles.find(profile => profile.name === hostName);
    return host ? {herdr: host.herdr, use_herdr: host.use_herdr, use_tmux: host.use_tmux} : null;
}, name);

for (const width of [390, 1440]) {
    test(`host editor offers Herdr as the only alternative to tmux at ${width}px`, async ({page}) => {
        const name = `Herdr host ${width}`;
        await page.setViewportSize({width, height: 900});
        await login(page);
        try {
            await setIntegration(page, true);
            await openHostEditor(page);
            const option = page.locator('#profileEditorHerdr');
            const herdrMode = page.locator('#profileEditorModeHerdr');
            const reason = page.locator('#profileEditorHerdrModeReason');
            await expect(page.locator('#profileEditorTmuxGroup')).toBeHidden();
            await expect(option).not.toBeChecked();
            await expect(herdrMode).toBeDisabled();
            await expect(reason).toContainText('Turn on “Herdr on this host”');

            await page.locator('#profileEditorName').fill(name);
            await page.locator('#profileEditorHost').fill('fixture.invalid');
            await page.locator('#profileEditorUsername').fill('test');
            await option.check();
            await expect(reason).toBeHidden();
            await herdrMode.check();
            await expect(page.locator('#profileEditorModeTmux')).not.toBeChecked();

            await page.locator('#profileEditorPostConnectMode').selectOption('free_text');
            await expect(herdrMode).toBeDisabled();
            await expect(page.locator('#profileEditorModeShell')).toBeChecked();
            await expect(reason).toContainText('cannot be combined with “Run after connecting”');
            await page.locator('#profileEditorPostConnectMode').selectOption('none');
            await herdrMode.check();

            await page.locator('#profileEditorForm button[type="submit"]').first().click();
            await expect.poll(() => savedHost(page, name)).toEqual({herdr: true, use_herdr: true, use_tmux: false});

            await page.reload();
            await openHostEditor(page, name);
            await expect(option).toBeChecked();
            await expect(herdrMode).toBeChecked();
            await expect(herdrMode).toBeEnabled();

            await setIntegration(page, false);
            await openHostEditor(page, name);
            await expect(page.locator('#profileEditorHerdrDisabled')).toBeVisible();
            await expect(option).toBeChecked();
            await expect(option).toBeDisabled();
            await expect(herdrMode).toBeChecked();
            await expect(herdrMode).toBeDisabled();
            await page.locator('#profileEditorModeShell').check();
            await page.locator('#profileEditorForm button[type="submit"]').first().click();
            await expect.poll(() => savedHost(page, name)).toEqual({herdr: true, use_herdr: false, use_tmux: false});
            await assertNoExternalRequests(page);
        } finally {
            await setIntegration(page, false);
        }
    });
}

test('host editor is unchanged while the Herdr integration is off', async ({page}) => {
    await login(page);
    await expect(page.locator('meta[name="herdr-enabled"]')).toHaveAttribute('content', 'false');
    await openHostEditor(page);
    await expect(page.locator('#profileEditorHerdrBlock')).toBeHidden();
    await expect(page.locator('#profileEditorUseTmux')).toBeVisible();
});
