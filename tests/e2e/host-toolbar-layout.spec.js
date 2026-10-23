const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

for (const width of [360, 390, 870, 1440, 3043]) {
    test(`Hosts keeps search above reachable actions at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width, height: width >= 1440 ? 662 : 844});
        await login(page);
        await openProfileManagement(page);
        await page.evaluate(() => new Promise(resolve => window.socket.emit('list_profiles', resolve)));
        await page.evaluate(() => {
            const template = window.ProfileManager.profiles[0];
            window.ProfileManager.setProfiles(Array.from({length: 80}, (_, index) => ({
                ...template, id: `toolbar-${index}`, name: `Toolbar host ${index}`, group: 'Toolbar fixtures', favorite: false,
            })));
        });
        const search = page.locator('#profileSearchInput');
        const actions = page.locator('#profileManagementView .management-panel-actions');
        const searchBox = await search.boundingBox();
        const actionsBox = await actions.boundingBox();
        expect(actionsBox.y).toBeGreaterThanOrEqual(searchBox.y + searchBox.height);
        expect(Math.abs(actionsBox.x - searchBox.x)).toBeLessThanOrEqual(1);
        expect(Math.abs(actionsBox.width - searchBox.width)).toBeLessThanOrEqual(1);
        for (const id of ['profileDensityBtn', 'collapseAllProfilesBtn', 'importProfilesBtn', 'exportProfilesBtn', 'newProfileBtn']) {
            await expect(page.locator(`#${id}`)).toBeInViewport();
        }
        await page.screenshot({path: testInfo.outputPath(`hosts-toolbar-${width}-default.png`)});
        const downloaded = page.waitForEvent('download');
        await page.locator('#exportProfilesBtn').click();
        expect((await downloaded).suggestedFilename()).toMatch(/^webssh-hosts\.(json|zip)$/);
        const list = page.locator('#profileManagementList');
        await list.evaluate(element => { element.scrollTop = element.scrollHeight; });
        expect(await list.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
        expect((await actions.boundingBox()).y).toBe(actionsBox.y);
        await expect(page.locator('#newProfileBtn')).toBeInViewport();
        await search.fill('Toolbar host 79');
        await expect(page.locator('#profileManagementList [data-profile-card-id]')).toHaveCount(1);
        await search.fill('');
        await search.focus();
        await page.keyboard.press('Tab');
        await expect(page.locator('#profileDensityBtn')).toBeFocused();
        await page.locator('#profileDensityBtn').click();
        await expect(page.locator('#profileDensityBtn')).toHaveAttribute('aria-pressed', 'true');
        await page.locator('#collapseAllProfilesBtn').click();
        await page.locator('#newProfileBtn').click();
        await expect(page.locator('#profileEditorView')).toBeVisible();
        await page.locator('#cancelProfileEditorBtn').click();
        await expect(search).toBeVisible();
        await page.evaluate(() => {
            document.body.dataset.theme = 'paper';
            document.getElementById('exportProfilesBtn').textContent = 'Verbindungsmetadaten vollständig exportieren';
            document.getElementById('newProfileBtn').textContent = 'Neue gespeicherte Verbindung erstellen';
        });
        expect(await page.locator('#profileManagementView').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
        await expect(page.locator('#newProfileBtn')).toBeInViewport();
        await page.screenshot({path: testInfo.outputPath(`hosts-toolbar-${width}.png`)});
        await assertNoExternalRequests(page);
    });
}

for (const width of [360, 870, 3043]) {
    test(`Hosts resource navigation preserves Jump Hosts and Keys forms at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 662});
        await login(page);
        await openProfileManagement(page);
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        await expect(page.locator('#jumpHostManagementModal')).toBeVisible();
        await page.locator('#jhNameInput').fill('Navigation draft');
        await page.locator('#jumpHostForm button[type="submit"]').scrollIntoViewIfNeeded();
        await expect(page.locator('#jumpHostForm button[type="submit"]')).toBeInViewport();
        expect(await page.locator('#jumpHostManagementModal .connection-asset-layout').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
        await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
        await expect(page.locator('#keyManagementModal')).toBeVisible();
        await page.locator('#keyNameInput').fill('Key navigation draft');
        await page.locator('#keyContentInput').focus();
        await page.keyboard.press('Tab');
        await expect(page.locator('#keyManagementModal button[type="submit"]')).toBeFocused();
        expect(await page.locator('#keyManagementModal .connection-asset-layout').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
        await page.locator('#keyManagementModal [data-connection-asset="hosts"]').click();
        await expect(page.locator('#profileSearchInput')).toBeVisible();
        await expect(page.locator('#newProfileBtn')).toBeInViewport();
        const search = await page.locator('#profileSearchInput').boundingBox();
        const actions = await page.locator('#profileManagementView .management-panel-actions').boundingBox();
        expect(actions.y).toBeGreaterThanOrEqual(search.y + search.height);
        await assertNoExternalRequests(page);
    });
}
