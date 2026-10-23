const { test, expect } = require('playwright/test');
const { login, installSshConnectTrap, sshAttempts, assertNoExternalRequests } = require('./helpers');

test.beforeEach(async ({page}) => { await login(page); });
test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

test('file chooser shares favorites, group order, search and readiness with the host launcher', async ({page}) => {
    const launcherGroups = await page.locator('.profile-launcher-section-title').allTextContents();
    await page.locator('#fileTransferBtn').click();
    await page.locator('#fmLeftList .fm-empty-source-cta').click();
    await expect(page.locator('#fmSourceGroups .fm-source-group')).toHaveCount(launcherGroups.length);
    const sourceGroups = await page.locator('#fmSourceGroups h4 > span:first-child').allTextContents();
    expect(sourceGroups).toEqual(launcherGroups);
    await expect(page.locator('[data-source-key="profile:usable-key"]')).toHaveAttribute('data-readiness', 'saved');
    await expect(page.locator('[data-source-key="profile:password-review"]')).toHaveAttribute('data-readiness', 'password-needed');
    await expect(page.locator('[data-source-key="profile:missing-key"]')).toHaveAttribute('data-readiness', 'key-missing');
    await page.locator('#fmSourceSearch').fill('Operations');
    await expect(page.locator('#fmSourceGroups .fm-source-row')).toHaveCount(2);
});

test('save and connect persists a host then requests its password without bypassing authentication', async ({page}) => {
    await installSshConnectTrap(page);
    await page.locator('#manageProfilesBtn').click();
    await page.locator('#newProfileBtn').click();
    await expect(page.locator('#profileAdvancedSettingsCard')).not.toHaveAttribute('open', '');
    const name = `UX save connect ${Date.now()}`;
    await page.locator('#profileEditorName').fill(name);
    await page.locator('#profileEditorHost').fill('ux-save.invalid');
    await page.locator('#profileEditorUsername').fill('operator');
    await page.locator('#saveConnectProfileBtn').click();
    await expect(page.locator('#connectionModal')).toBeVisible();
    await expect(page.locator('#connectionProfileContextName')).toHaveText(name);
    await expect(page.locator('#hostInput')).toHaveValue('ux-save.invalid');
    await expect(page.locator('#passwordInput')).toBeFocused();
    expect(await sshAttempts(page)).toHaveLength(0);
    await expect.poll(() => page.evaluate(name => ProfileManager.profiles.some(p => p.name === name), name)).toBe(true);
});

test('a rejected save does not launch a connection or discard the editor', async ({page}) => {
    await installSshConnectTrap(page);
    await page.locator('#manageProfilesBtn').click();
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorName').fill('Rejected UX save');
    await page.locator('#profileEditorHost').fill('invalid-save.invalid');
    await page.locator('#profileEditorUsername').fill('operator');
    await page.evaluate(() => {
        const emit = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, ...args) => event === 'save_profile'
            ? args.at(-1)({success: false, error: 'Test save rejected'})
            : emit(event, ...args);
    });
    await page.locator('#saveConnectProfileBtn').click();
    await expect(page.locator('#profileEditorName')).toHaveValue('Rejected UX save');
    await expect(page.locator('#profileEditorView')).toBeVisible();
    await expect(page.locator('#connectionModal')).toBeHidden();
    expect(await sshAttempts(page)).toHaveLength(0);
});

test('command section choice survives navigation and reload for the same account', async ({page}) => {
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandLibraryPanel')).toBeVisible();
    await page.locator('#commandSetsTab').click();
    await page.locator('#workspaceNavBtn').click();
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandSetsPanel')).toBeVisible();
    await page.reload();
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandSetsPanel')).toBeVisible();
});

test('all mobile primary destinations work without an SSH session and tools remain reachable', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    for (const [view, surface] of [['files', '#sftpFileManager'], ['commands', '#commandWorkspaceModal'], ['hosts', '#profileManagementModal']]) {
        const button = page.locator(`#mobileAppDock [data-mobile-view="${view}"]`);
        await expect(button).toBeEnabled();
        await button.click();
        await expect(page.locator(surface)).toBeVisible();
        await expect(button).toHaveAttribute('aria-current', 'page');
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
        expect(overflow).toBe(false);
    }
    await page.locator('[data-mobile-view="workspaces"]').click();
    await page.locator('#contextWorkspaceLauncher').click();
    await expect(page.locator('#contextWorkspace')).toBeVisible();
    await expect(page.locator('#contextNotesPanel')).toBeVisible();
    await expect(page.locator('[data-mobile-view="workspaces"]')).toHaveAttribute('aria-current', 'page');
    await page.locator('#contextWorkspaceClose').click();
});


test('host density persists and advanced hosts expose their existing settings', async ({page}) => {
    await page.locator('#manageProfilesBtn').click();
    const density = page.locator('#profileDensityBtn');
    await density.click();
    await expect(density).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#profileManagementList')).toHaveClass(/is-compact/);
    await page.reload();
    await page.locator('#manageProfilesBtn').click();
    await expect(density).toHaveAttribute('aria-pressed', 'true');
    await page.locator('#profileSearchInput').fill('Post free text');
    const host = page.locator('.profile-management-item').filter({hasText: 'Post free text'});
    await host.locator('.profile-action-menu > summary').click();
    await host.locator('[data-profile-action="edit"]').click();
    await expect(page.locator('#profileAdvancedSettingsCard')).toHaveAttribute('open', '');
});

test('host actions retain their menu and keyboard focus across refreshed profile data', async ({page}) => {
    await page.locator('#manageProfilesBtn').click();
    await page.locator('#profileSearchInput').fill('Post free text');
    const host = page.locator('.profile-management-item').filter({hasText: 'Post free text'});
    const profileId = await host.getAttribute('data-profile-card-id');
    await host.locator('.profile-action-menu > summary').click();
    await host.locator('[data-profile-action="edit"]').focus();
    await page.evaluate(async id => {
        await new Promise(requestAnimationFrame);
        ProfileManager.setProfiles(ProfileManager.profiles.map(profile => profile.id === id
            ? {...profile, host: 'refreshed-target.invalid'} : profile));
    }, profileId);
    await expect(host.locator('.profile-action-menu')).toHaveAttribute('open', '');
    await expect(host.locator('[data-profile-action="edit"]')).toBeFocused();
    await page.locator('#profileSearchInput').focus();
    await page.evaluate(() => ProfileManager.setProfiles([...ProfileManager.profiles]));
    await expect(page.locator('#profileSearchInput')).toBeFocused();
    await expect(host.locator('.profile-action-menu')).toHaveAttribute('open', '');
    await host.locator('[data-profile-action="edit"]').click();
    await expect(page.locator('#profileEditorHost')).toHaveValue('refreshed-target.invalid');
});

test('collapsing a host group dismisses its open action menus across refresh and expansion', async ({page}) => {
    await page.locator('#manageProfilesBtn').click();
    const search = page.locator('#profileSearchInput');
    await search.fill('Post free text');
    const host = page.locator('.profile-management-item').filter({hasText: 'Post free text'});
    const groupKey = await host.locator('xpath=ancestor::section[contains(@class, "profile-management-section")]')
        .locator('[data-profile-group-toggle]').getAttribute('data-profile-group-toggle');
    await search.fill('');
    const section = page.locator('.profile-management-section')
        .filter({has: page.locator('[data-profile-group-toggle="' + groupKey + '"]')});
    const toggle = section.locator('[data-profile-group-toggle]');
    const target = section.locator('.profile-management-item').filter({hasText: 'Post free text'});
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await target.locator('.profile-action-menu > summary').click();
    await expect(target.locator('.profile-action-menu')).toHaveAttribute('open', '');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await page.evaluate(() => ProfileManager.setProfiles([...ProfileManager.profiles]));
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await expect(target.locator('.profile-action-menu')).not.toHaveAttribute('open', '');
});

test('refreshing away an active host action returns focus without retaining stale actions', async ({page}) => {
    await page.locator('#manageProfilesBtn').click();
    const search = page.locator('#profileSearchInput');
    await search.fill('Post free text');
    const host = page.locator('.profile-management-item').filter({hasText: 'Post free text'});
    const profileId = await host.getAttribute('data-profile-card-id');
    await host.locator('.profile-action-menu > summary').click();
    await search.fill('Operations');
    await expect(host).toHaveCount(0);
    await expect(page.locator('.profile-action-menu[open]')).toHaveCount(0);
    await expect(search).toBeFocused();
    await search.fill('Post free text');
    await expect(host.locator('.profile-action-menu')).not.toHaveAttribute('open', '');
    await host.locator('.profile-action-menu > summary').click();
    await host.locator('[data-profile-action="edit"]').focus();
    await page.evaluate(id => ProfileManager.setProfiles(
        ProfileManager.profiles.filter(profile => profile.id !== id),
    ), profileId);
    await expect(host).toHaveCount(0);
    await expect(page.locator('.profile-action-menu[open]')).toHaveCount(0);
    await expect(search).toBeFocused();
    // Clearing the filter must not restore a removed host or its actions.
    await search.fill('');
    await expect(host).toHaveCount(0);
    await expect(page.locator('.profile-action-menu[open]')).toHaveCount(0);
});


test.describe('mobile header touch interaction', () => {
    test.use({hasTouch: true});

    test('mobile header opens Quick Connect from Commands without a session', async ({page}) => {
        await page.setViewportSize({width: 390, height: 844});
        await page.locator('[data-mobile-view="commands"]').click();
        const summary = page.locator('#mobileSessionSummary');
        await expect(summary).toBeEnabled();
        await expect(summary).toHaveText(/Quick Connect/);
        await summary.tap();
        await expect(page.locator('#connectionModal')).toBeVisible();
        await expect(page.locator('#commandWorkspaceModal')).toBeHidden();
    });

});
