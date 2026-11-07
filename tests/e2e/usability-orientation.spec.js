const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('main navigation follows its visual order by keyboard and search describes its scope', async ({page}) => {
    await page.setViewportSize({width: 1600, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    const ids = await page.locator('#globalNavigation > :is(button, a)').evaluateAll(buttons =>
        buttons.sort((a, b) => a.getBoundingClientRect().left - b.getBoundingClientRect().left).map(button => button.id));
    await page.locator(`#${ids[0]}`).focus();
    for (const id of ids.slice(1)) {
        await page.keyboard.press('Tab');
        await expect(page.locator(`#${id}`)).toBeFocused();
    }
    await expect(page.locator('#shellSearchBtn')).toHaveAccessibleName('Search actions, hosts, and sessions...');
    await page.locator('#shellSearchBtn').click();
    await expect(page.locator('#commandPaletteInput')).toBeVisible();
});

test('compact host inspector protects edits on return and keeps the filtered list', async ({page}) => {
    await page.setViewportSize({width: 1024, height: 720});
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#manageProfilesBtn').click();
    const search = page.locator('#profileSearchInput');
    await search.fill('Ops');
    await page.locator('.profile-management-item .profile-inspect-button').first().click();
    const original = await page.locator('#profileEditorName').inputValue();
    await page.locator('#profileEditorName').fill(`${original} draft`);
    const back = page.locator('.profile-inspector-close');
    await expect(back).toHaveAccessibleName('Back to list');
    await expect(back.locator('.inspector-return-label')).toBeVisible();
    const titleBox = await page.locator('#profileConnectionDetailsTitle').boundingBox();
    const backBox = await back.boundingBox();
    expect(backBox.y).toBeLessThan(titleBox.y + titleBox.height);
    await back.click();
    const dialog = page.locator('.command-set-confirm-dialog');
    await expect(dialog).toBeVisible();
    await dialog.locator('.btn-secondary').click();
    await expect(page.locator('#profileEditorName')).toHaveValue(`${original} draft`);
    await page.locator('#cancelProfileEditorBtn').click();
    await dialog.locator('.btn-danger').click();
    await expect(search).toBeVisible();
    await expect(search).toHaveValue('Ops');
    await expect(page.locator('.profile-management-item .profile-inspect-button').first()).toBeFocused();
    await page.locator('.profile-management-item .profile-inspect-button').first().click();
    await expect(page.locator('#profileEditorName')).toHaveValue(original);
    await back.click();
    await expect(search).toBeVisible();
    await expect(dialog).toHaveCount(0);
});

test('compact command inspector offers a named return and restores selection focus', async ({page}) => {
    await page.setViewportSize({width: 1024, height: 720});
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#commandLibraryBtn').click();
    const inspect = page.locator('.command-inspect-button').first();
    await inspect.click();
    const back = page.locator('#commandLibraryDetails').getByRole('button', {name: 'Back to list', exact: true});
    await expect(back.locator('.inspector-return-label')).toBeVisible();
    await back.click();
    await expect(inspect).toBeFocused();
    await expect(page.locator('#commandLibraryDetails')).toHaveCount(0);
});
