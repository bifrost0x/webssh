const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests, openProfileManagement} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

async function expectEmptyRegion(page, selector) {
    const region = page.locator(selector);
    await expect(region).toBeVisible();
    await region.scrollIntoViewIfNeeded();
    const geometry = await region.evaluate(element => {
        const rect = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return {left: rect.left, right: rect.right, width: rect.width, height: rect.height,
            viewport: innerWidth, align: style.textAlign, overflow: element.scrollWidth - element.clientWidth};
    });
    expect(geometry.align).toBe('center');
    expect(geometry.height).toBeGreaterThanOrEqual(96);
    expect(geometry.left).toBeGreaterThanOrEqual(-1);
    expect(geometry.right).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(geometry.overflow).toBeLessThanOrEqual(1);
    return region;
}

for (const width of [360, 733, 1440, 3043]) {
    test(`empty management surfaces are consistent and actionable at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width, height: 740});
        await login(page);
        await expect.poll(() => page.evaluate(() => window.ProfileManager.profilesLoaded)).toBe(true);
        await openProfileManagement(page);
        await page.evaluate(() => new Promise(resolve => window.socket.emit('list_profiles', resolve)));
        await page.evaluate(() => {
            window.ProfileManager.setProfiles([]);
            window.ProfileManager.setKeys([]);
            window.JumpHostManager.setJumpHosts([]);
            window.CommandSetManager.setCommandSets([]);
            window.SessionCommandLauncher.ensurePreferences();
            window.SessionCommandLauncher.favorites.clear();
            window.CommandWorkspace.renderFavorites();
        });
        await expectEmptyRegion(page, '#profileManagementList .no-items');
        await expect(page.locator('#profileManagementList')).toContainText('Create');
        await page.screenshot({path: testInfo.outputPath(`empty-hosts-${width}.png`)});
        await page.locator('#newProfileBtn').click();
        await expect(page.locator('#profileEditorView')).toBeVisible();
        await page.locator('#cancelProfileEditorBtn').click();
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        await page.evaluate(() => new Promise(resolve => window.socket.emit('list_jump_hosts', resolve)));
        await page.evaluate(() => window.JumpHostManager.setJumpHosts([]));
        await expectEmptyRegion(page, '#jumpHostsList .no-items');
        await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
        await page.evaluate(() => new Promise(resolve => window.socket.emit('list_keys', resolve)));
        await page.evaluate(() => window.ProfileManager.setKeys([]));
        await expectEmptyRegion(page, '#keysList .no-items');
        await expect(page.locator('#keysList')).toContainText('upload');
        if (await page.locator('#commandLibraryBtn').isVisible()) await page.locator('#commandLibraryBtn').click();
        else await page.locator('[data-mobile-view="commands"]').click();
        await page.locator('#commandFavoritesTab').click();
        const emptyFavorites = await expectEmptyRegion(page, '.command-favorites-empty');
        await expect(emptyFavorites).toContainText('star');
        await page.screenshot({path: testInfo.outputPath(`empty-favorites-${width}.png`)});
        await page.locator('#commandFavoritesSearch').fill('does-not-exist');
        await expect(emptyFavorites).toContainText('No matching entries');
        await page.locator('#commandSetsTab').click();
        await expectEmptyRegion(page, '#commandSetManagementList .no-items');
        await page.locator('#commandLibraryTab').click();
        await page.locator('#commandSearchInput').fill('does-not-exist');
        await expectEmptyRegion(page, '#commandsList .no-items');
        const grid = await page.locator('#commandsList').boundingBox();
        const empty = await page.locator('#commandsList .no-items').boundingBox();
        expect(empty.width).toBeGreaterThanOrEqual(grid.width - 2);
        await page.locator('#commandSearchInput').fill('');
        await expect(page.locator('#commandsList .command-row').first()).toBeVisible();
        if (await page.locator('#fileTransferBtn').isVisible()) await page.locator('#fileTransferBtn').click();
        else await page.locator('[data-mobile-view="files"]').click();
        await expect(page.locator('.fm-source-empty-state p').first()).toBeVisible();
        await page.screenshot({path: testInfo.outputPath(`empty-files-${width}.png`)});
        await page.locator('.fm-empty-source-cta').first().click();
        await expect(page.locator('#fmSourceLauncher')).toHaveClass(/show/);
    });
}

for (const width of [390, 1440]) {
    test(`empty account factors and admin tables keep structure at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width, height: 740});
        await login(page);
        await page.goto('/settings#factors');
        await expectEmptyRegion(page, '#totpList .security-factor-empty');
        await expect(page.locator('#totpAddBtn')).toBeEnabled();
        await page.screenshot({path: testInfo.outputPath(`empty-factors-${width}.png`)});
        await page.goto('/admin');
        await expect(page.locator('#adminUsersBody tr[data-user-id]').first()).toBeVisible();
        const userIds = await page.locator('#adminUsersBody tr[data-user-id]').evaluateAll(rows => rows.map(row => row.dataset.userId));
        await page.locator('#adminUserSearch').fill('no-such-user');
        await expect(page.locator('#adminUserEmptyRow td')).toHaveText('No matching entries.');
        await expect(page.locator('#adminUserFilterStatus')).toContainText(`0 of ${userIds.length}`);
        await page.locator('#adminUserSearch').fill('');
        await expect(page.locator('#adminUserEmptyRow')).toHaveCount(0);
        expect(await page.locator('#adminUsersBody tr[data-user-id]').evaluateAll(rows => rows.filter(row => !row.hidden).map(row => row.dataset.userId))).toEqual(userIds);
        if (width < 768) await page.locator('#settingsMobileSection').selectOption('host-trust');
        else await page.locator('[data-settings-section="host-trust"]').click();
        const empty = page.locator('#globalHostKeyList td.ui-empty-table');
        await expect(empty).toBeVisible();
        await expect(empty).toHaveAttribute('colspan', '5');
        expect(await empty.evaluate(element => element.tagName)).toBe('TD');
        // Existing responsive tables deliberately become stacked blocks on mobile.
        expect(await empty.evaluate(element => getComputedStyle(element).display)).toBe(width < 768 ? 'block' : 'table-cell');
        expect(await empty.evaluate(element => getComputedStyle(element).textAlign)).toBe('center');
        await page.screenshot({path: testInfo.outputPath(`empty-global-keys-${width}.png`)});
    });
}

test('empty hints translate and wrap in the light theme without exposing hidden context', async ({page}) => {
    await page.setViewportSize({width: 360, height: 640});
    await login(page);
    await openProfileManagement(page);
    await page.evaluate(() => new Promise(resolve => window.socket.emit('list_profiles', resolve)));
    await page.evaluate(() => {
        window.ProfileManager.setProfiles([]);
        document.body.dataset.theme = 'paper';
        window.i18n.setLanguage('de');
    });
    const empty = await expectEmptyRegion(page, '#profileManagementList .no-items');
    await expect(empty).toContainText('Erstelle');
    await expect(page.locator('#hostContextEmpty')).toBeHidden();
    const hint = empty.locator('.empty-state-hint');
    expect(await hint.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
});
