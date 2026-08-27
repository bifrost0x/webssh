const { test, expect } = require('playwright/test');
const { assertNoExternalRequests, login } = require('./helpers');

test.use({ viewport: { width: 1440, height: 1024 } });

test.beforeEach(async ({ page }) => {
    await login(page);
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('Hosts, File Manager, and Commands share the main surface while Workspaces stays intact', async ({ page }) => {
    const baseline = await page.evaluate(() => {
        window.__primaryWorkspaceOriginal = document.getElementById('workspace');
        return {
            workspaceChildren: document.getElementById('workspace').childElementCount,
            sessionTabs: document.getElementById('sessionTabs').childElementCount,
        };
    });

    await page.locator('#manageProfilesBtn').click();
    await expect(page.locator('#manageProfilesBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#primaryWorkspaceSurface')).toBeVisible();
    await expect(page.locator('.session-tabs-row')).toBeHidden();
    await expect(page.locator('.main-content')).toBeHidden();
    await expect(page.locator('#workspaceStatusBar')).toBeHidden();
    await expect(page.locator('#profileManagementModal')).toBeVisible();
    await expect(page.locator('#profileManagementModal')).toHaveAttribute('role', 'region');
    await expect(page.locator('#profileManagementModal')).not.toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('#closeProfileManagementModal')).toBeHidden();
    await expect(page.locator('#profileManagementModal .management-resource-title')).toContainText('Hosts');
    await expect(page.locator('#profileManagementModal .connection-asset-nav-label')).toHaveText('Connection resources');
    expect(await page.locator('#profileManagementModal').evaluate(
        element => element.parentElement?.id,
    )).toBe('primaryWorkspaceSurface');

    await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
    await expect(page.locator('#jumpHostManagementModal')).toBeVisible();
    await expect(page.locator('#manageProfilesBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('.main-content')).toBeHidden();

    await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
    await expect(page.locator('#keyManagementModal')).toBeVisible();
    await expect(page.locator('#keyManagementModal')).toHaveAttribute('role', 'region');
    await expect(page.locator('#closeKeyModal')).toBeHidden();

    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandLibraryBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#keyManagementModal')).toBeHidden();
    await expect(page.locator('#commandWorkspaceModal')).toBeVisible();
    await expect(page.locator('#commandWorkspaceModal')).toHaveAttribute('role', 'region');
    await expect(page.locator('#closeCommandWorkspaceModal')).toBeHidden();
    await page.locator('#commandLibraryTab').click();
    await expect(page.locator('#commandLibraryPanel')).toBeVisible();
    await expect(page.locator('#commandSearchInput')).toBeFocused();

    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#fileTransferBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#commandWorkspaceModal')).toBeHidden();
    await expect(page.locator('#sftpFileManager')).toBeVisible();
    await expect(page.locator('#sftpFileManager')).toHaveAttribute('role', 'region');
    await expect(page.locator('#sftpFileManager')).not.toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('#fmClose')).toBeHidden();
    await expect(page.locator('.session-tabs-row')).toBeHidden();
    await expect(page.locator('.main-content')).toBeHidden();
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await expect(page.locator('#fmLeftList .fm-empty-source-cta')).toBeVisible();
    await page.locator('#fmLayoutSplit').click();
    await expect(page.locator('#fmSourceLauncher')).not.toHaveClass(/show/);
    await expect(page.locator('#fmRightList .fm-empty-source-cta')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#sftpFileManager')).toBeVisible();

    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#workspaceNavBtn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#primaryWorkspaceSurface')).toBeHidden();
    await expect(page.locator('.session-tabs-row')).toBeVisible();
    await expect(page.locator('.main-content')).toBeVisible();
    await expect(page.locator('#workspaceStatusBar')).toBeVisible();
    await expect(page.locator('#sftpFileManager')).toBeHidden();

    const restored = await page.evaluate(() => ({
        sameWorkspace: document.getElementById('workspace') === window.__primaryWorkspaceOriginal,
        workspaceChildren: document.getElementById('workspace').childElementCount,
        sessionTabs: document.getElementById('sessionTabs').childElementCount,
        fileManagerMode: window.sftpFileManager?.displayMode,
    }));
    expect(restored).toEqual({
        sameWorkspace: true,
        workspaceChildren: baseline.workspaceChildren,
        sessionTabs: baseline.sessionTabs,
        fileManagerMode: 'closed',
    });
});

test('mobile Settings uses one categorized selector and the user filters report results', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/settings');

    const mobileSection = page.locator('#settingsMobileSection');
    await expect(mobileSection).toBeVisible();
    await expect(page.locator('.settings-center-navigation')).toBeHidden();
    await expect(page.locator('#settingsMobileSection optgroup[label="My account"]')).toHaveCount(1);
    await expect(page.locator('#settingsMobileSection optgroup[label="Administration"]')).toHaveCount(1);

    await mobileSection.selectOption('preferences');
    await expect(page.locator('[data-account-panel="preferences"]')).toBeVisible();
    await expect(page).toHaveURL(/#preferences$/);

    await mobileSection.selectOption('users');
    await expect(page.locator('#tab-users')).toBeVisible();
    await expect(page).toHaveURL(/#users$/);
    await expect(page.locator('#adminUserFilterStatus')).toContainText('users');

    await page.locator('#adminUserSearch').fill('no-such-e2e-user');
    await expect(page.locator('#adminUserFilterStatus')).toHaveText(/0 of \d+ users/);
});

test('return-to-connection command-set editing still behaves as a nested modal', async ({ page }) => {
    await page.locator('#newTabBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.evaluate(() => window.CommandSetManager.openBuilder(null, true));

    await expect(page.locator('#commandWorkspaceModal')).toHaveClass(/show/);
    await expect(page.locator('#commandWorkspaceModal')).toHaveAttribute('role', 'dialog');
    await expect(page.locator('#commandWorkspaceModal')).toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('#primaryWorkspaceSurface')).toBeHidden();
    await expect(page.locator('.main-content')).toBeVisible();
    await expect(page.locator('#commandSetEditorView')).toBeVisible();

    await page.locator('#cancelCommandSetBtn').click();
    await expect(page.locator('#commandWorkspaceModal')).not.toHaveClass(/show/);
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
});
