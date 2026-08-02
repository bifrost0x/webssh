const { test, expect } = require('playwright/test');
const {
    assertNoExternalRequests,
    installSshConnectTrap,
    launchProfile,
    login,
    openProfileManagement,
    restoreSshConnect,
    sshAttempts,
} = require('./helpers');

test.beforeEach(async ({ page }) => {
    await login(page);
    await installSshConnectTrap(page);
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('projects all post-connect modes with exact parameter and stale-field semantics', async ({ page }) => {
    const cases = [
        ['Post none', { startup_mode: 'none' }, [
            'startup_commands', 'command_id', 'parameters_override', 'command_set_id',
        ]],
        ['Post free text', {
            startup_mode: 'free_text',
            startup_commands: 'printf free-text',
        }, ['command_id', 'parameters_override', 'command_set_id']],
        ['Post command default', {
            startup_mode: 'command',
            command_id: 'e2e-command',
        }, ['startup_commands', 'parameters_override', 'command_set_id']],
        ['Post command empty', {
            startup_mode: 'command',
            command_id: 'e2e-command',
            parameters_override: '',
        }, ['startup_commands', 'command_set_id']],
        ['Post command custom', {
            startup_mode: 'command',
            command_id: 'e2e-command',
            parameters_override: '--custom value',
        }, ['startup_commands', 'command_set_id']],
        ['Post command set', {
            startup_mode: 'command_set',
            command_set_id: 'e2e-command-set',
        }, ['startup_commands', 'command_id', 'parameters_override']],
    ];

    for (const [name, expected, absent] of cases) {
        await launchProfile(page, name);
        await expect.poll(() => sshAttempts(page)).toHaveLength(1);
        const [{ payload }] = await sshAttempts(page);
        expect(payload).toMatchObject(expected);
        absent.forEach(field => expect(payload).not.toHaveProperty(field));
        await page.locator('#cancelConnectionBtn').click();
        await installSshConnectTrap(page);
    }
});

test('saving after mode changes removes stale post-connect fields', async ({ page }) => {
    await openProfileManagement(page);
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorName').fill('Post stale cleanup');
    await page.locator('#profileEditorHost').fill('cleanup.local');
    await page.locator('#profileEditorUsername').fill('cleanup');
    await page.locator('#profileEditorAuthType').selectOption('key');
    const keyOption = page.locator('#profileEditorKeySelect option').filter({
        hasText: 'E2E usable key',
    });
    await page.locator('#profileEditorKeySelect').selectOption(
        await keyOption.getAttribute('value'),
    );

    await page.locator('#profileEditorPostConnectMode').selectOption('free_text');
    await page.locator('#profileEditorStartupCommands').fill('stale free text');
    await page.locator('#profileEditorPostConnectMode').selectOption('command');
    await page.locator('#profileEditorCommandSelect').selectOption('e2e-command');
    await page.locator('#profileEditorUseDefaultParameters').uncheck();
    await page.locator('#profileEditorCommandParameters').fill('stale parameters');
    await page.locator('#profileEditorPostConnectMode').selectOption('command_set');
    await page.locator('#profileEditorCommandSetSelect').selectOption('e2e-command-set');
    await page.locator('#profileEditorPostConnectMode').selectOption('none');
    await page.locator('#profileEditorForm button[type="submit"]').click();
    await expect(page.locator('.profile-management-item').filter({
        hasText: 'Post stale cleanup',
    })).toHaveCount(1);

    const stored = await page.evaluate(() => (
        window.ProfileManager.profiles.find(profile => profile.name === 'Post stale cleanup')
    ));
    expect(stored).toMatchObject({ startup_mode: 'none' });
    for (const field of [
        'startup_commands', 'command_id', 'parameters_override', 'command_set_id',
    ]) {
        expect(stored).not.toHaveProperty(field);
    }
});

test('missing post-connect references stop before the guarded SSH network layer', async ({ page }) => {
    await restoreSshConnect(page);
    for (const [name, message] of [
        ['Post missing command', 'Command not found'],
        ['Post missing command set', 'Command set not found'],
    ]) {
        await launchProfile(page, name);
        await expect(page.locator('.notification-error').last()).toContainText(message);
        await expect(page.locator('.notification-error').last()).not.toContainText(
            'E2E network guard reached',
        );
        await page.locator('#cancelConnectionBtn').click();
    }
});
