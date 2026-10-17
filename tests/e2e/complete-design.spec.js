const {test, expect} = require('playwright/test');
const {login: baseLogin, openProfileManagement, assertNoExternalRequests, installExternalRequestGuard} = require('./helpers');

async function login(page) {
    await baseLogin(page);
    // Other regression tests deliberately persist themes on this disposable user.
    // Make visual fixtures deterministic through the real preference workflow.
    if (await page.locator('body').getAttribute('data-theme') !== 'glass') {
        await page.goto('/settings#preferences');
        await page.locator('#settingsThemeSelect').selectOption('glass');
        await expect(page.locator('body')).toHaveAttribute('data-theme', 'glass');
        await page.goto('/');
        await expect.poll(() => page.evaluate(() => window.ProfileManager?.profilesLoaded)).toBe(true);
    }
}

async function navigate(page, selector) {
    if (!await page.locator(selector).isVisible()) await page.locator('#mobileMoreBtn').click();
    await page.locator(selector).click();
}

async function capture(page, name, width) {
    await expect(page.locator('body')).toHaveClass(/webssh-ui/);
    const geometry = await page.evaluate(() => ({
        width: innerWidth,
        scroll: document.documentElement.scrollWidth,
        styleLoaded: [...document.styleSheets].some(sheet => sheet.href?.includes('/css/product-ui.css')),
    }));
    expect(geometry.styleLoaded).toBe(true);
    expect(geometry.scroll).toBeLessThanOrEqual(geometry.width);
    await page.screenshot({path: test.info().outputPath(`${name}-${width}.png`), animations: 'disabled'});
}

for (const width of [1440, 1024, 390]) {
    test(`complete authentication presentation at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        installExternalRequestGuard(page);
        await page.goto('/login');
        await expect(page.locator('#localLoginForm')).toBeVisible();
        await capture(page, 'login', width);
        for (const mode of ['passkey', 'oidc', 'password']) {
            await page.locator(`[data-auth-mode="${mode}"]`).click();
            await capture(page, `login-${mode}`, width);
        }
        await page.goto('/register');
        await expect(page.locator('#registerForm')).toBeVisible();
        await capture(page, 'register', width);
        await login(page);
        await page.goto('/change-password');
        await expect(page.locator('#changePasswordForm')).toBeVisible();
        await expect(page.locator('.auth-form-panel [data-i18n="auth.passwordOverviewHint"]')).toBeVisible();
        await capture(page, 'change-password', width);
        await assertNoExternalRequests(page);
    });

    test(`complete management presentation at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page);
        await page.locator('.profile-launcher-new').click();
        await expect(page.locator('#connectionModal')).toBeVisible();
        await capture(page, 'quick-connect', width);
        await page.locator('#cancelConnectionBtn').click();
        await openProfileManagement(page);
        await capture(page, 'hosts', width);
        const nav = await page.locator('#profileManagementModal .connection-asset-nav').boundingBox();
        const heading = await page.locator('#profileManagementView .management-panel-heading').boundingBox();
        expect(nav.y + nav.height).toBeLessThanOrEqual(heading.y);
        const favorite = page.locator('.profile-management-item.is-derived-favorite').first();
        const card = await favorite.boundingBox();
        const actions = await favorite.locator('.profile-management-actions').boundingBox();
        expect(actions.x).toBeGreaterThanOrEqual(card.x);
        expect(actions.x + actions.width).toBeLessThanOrEqual(card.x + card.width);

        // A click can auto-scroll an offscreen button: verify actual visibility.
        const hostActions = await page.locator('#newProfileBtn').boundingBox();
        expect(hostActions.x).toBeGreaterThanOrEqual(0);
        expect(hostActions.x + hostActions.width).toBeLessThanOrEqual(width);
        const searchIcon = await page.locator('#profileManagementView .management-search-control > .material-icons').boundingBox();
        const searchField = await page.locator('#profileSearchInput').boundingBox();
        expect(searchIcon.y).toBeGreaterThanOrEqual(searchField.y);
        expect(searchIcon.y + searchIcon.height).toBeLessThanOrEqual(searchField.y + searchField.height);
        await page.locator('#newProfileBtn').click();
        await expect(page.locator('#profileEditorForm')).toBeVisible();
        await capture(page, 'host-editor', width);
        await page.locator('#cancelProfileEditorBtn').click();
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        await expect(page.locator('#jumpHostForm')).toBeVisible();
        await capture(page, 'jump-hosts', width);
        await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
        await expect(page.locator('#keyUploadForm')).toBeVisible();
        await capture(page, 'ssh-keys', width);
        if (!await page.locator('#commandLibraryBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
        await page.locator('#commandLibraryBtn').click();
        await page.locator('#commandSetsTab').click();
        await expect(page.locator('#commandSetsPanel')).toBeVisible();
        await capture(page, 'command-sets', width);
        await page.locator('#newCommandSetBtn').click();
        await expect(page.locator('#commandSetForm')).toBeVisible();
        await capture(page, 'command-set-editor', width);
        await page.locator('#commandLibraryTab').click();
        await expect(page.locator('#commandLibraryPanel')).toBeVisible();
        await capture(page, 'command-library', width);
        await page.locator('#addCommandBtn').click();
        await expect(page.locator('#commandForm')).toBeVisible();
        await capture(page, 'command-editor', width);
        await page.locator('#cancelCommandFormBtn').click();
        await assertNoExternalRequests(page);
    });

    test(`complete account and administration presentation at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page);
        for (const section of ['preferences', 'security-overview', 'factors', 'recovery', 'password', 'ssh-host-trust']) {
            await page.goto(`/settings#${section}`);
            await expect(page.locator(`[data-account-panel="${section}"]`)).toBeVisible();
            await capture(page, `settings-${section}`, width);
        }
        await page.goto('/settings#factors');
        await page.locator('#totpAddBtn').click();
        await expect(page.locator('#securityConfirmationModal')).toHaveClass(/show/);
        await capture(page, 'security-confirmation', width);
        // Only open/cancel. No factor, trust or account mutation for visual coverage.
        await page.goto('/admin');
        await expect(page.locator('#adminUsersTable')).toBeVisible();
        await capture(page, 'admin-users', width);
        for (const section of ['authentication', 'registration', 'integrations', 'host-trust', 'retention']) {
            if (width < 768) await page.locator('#settingsMobileSection').selectOption(section);
            else await page.locator(`[data-settings-section="${section}"]`).click();
            await expect(page.locator(`[data-settings-panel="${section}"]`)).toBeVisible();
            await capture(page, `admin-${section}`, width);
        }
        for (const section of ['audit', 'backup', 'operations']) {
            if (width < 768) await page.locator('#settingsMobileSection').selectOption(section);
            else await page.locator(`.admin-navigation [data-tab="${section}"]`).click();
            await capture(page, `admin-${section}`, width);
        }
        await assertNoExternalRequests(page);
    });
}

test('shared presentation respects light theme across account and identity pages', async ({page}) => {
    await page.setViewportSize({width:1440, height:960});
    await page.addInitScript(() => localStorage.setItem('websshTheme', 'paper'));
    await page.goto('/login');
    await expect(page.locator('body')).toHaveAttribute('data-theme','paper');
    await capture(page, 'login-paper', 1440);
    await login(page);
    await page.goto('/settings#preferences');
    await page.locator('#settingsThemeSelect').selectOption('paper');
    await expect(page.locator('body')).toHaveAttribute('data-theme','paper');
    await capture(page, 'settings-paper', 1440);
    await assertNoExternalRequests(page);
});

for (const width of [1440, 390]) {
    test(`Configured MFA methods remain reachable at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        installExternalRequestGuard(page);
        await page.goto('/login');
        await page.locator('#username').fill('e2e_mixed_mfa');
        await page.locator('#password').fill('browser-password');
        await page.locator('form button[type="submit"]').click();
        await expect(page.locator('#authMfaMethodSwitcher')).toBeVisible();
        for (const mode of ['totp', 'passkey']) {
            await page.locator(`#authMfaMethodSwitcher [data-auth-mode="${mode}"]`).click();
            await capture(page, `mfa-${mode}`, width);
        }
        await assertNoExternalRequests(page);
    });

    test(`file source and appearance dialogs fit at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await navigate(page, '#fileTransferBtn');
        await expect(page.locator('#sftpFileManager')).toBeVisible();
        await capture(page, 'files-empty', width);
        await page.locator('[data-source-target="left"]').click();
        await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
        await capture(page, 'file-sources', width);
        // Browser-only enabled-feature fixture, matching the existing SMB suite.
        // Opening the form does not connect to a remote service.
        await page.evaluate(() => {
            const manager = window.sftpFileManager;
            manager.smbEnabled = true;
            manager.smbSourceDialog.enabled = true;
            manager.loadWorkspaceSmbShares = () => manager.smbSourceDialog.setSavedShares([]);
            manager.openSMBSourceDialog();
        });
        await expect(page.locator('#smbSourceModal')).toHaveClass(/show/);
        await capture(page, 'smb-connect', width);
        await page.keyboard.press('Escape');
        await navigate(page, '#workspaceNavBtn');
        if (width < 768) await page.locator('#mobileMoreBtn').click();
        await page.locator('[data-open-terminal-appearance]:visible').click();
        await expect(page.locator('#terminalAppearanceModal')).toHaveClass(/show/);
        await capture(page, 'terminal-appearance', width);
        await assertNoExternalRequests(page);
    });
}
