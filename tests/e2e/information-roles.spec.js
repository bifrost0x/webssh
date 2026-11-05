const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.use({viewport: {width: 1600, height: 900}, deviceScaleFactor: 1});
test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('overview assigns inventory, navigation and route information separate roles', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await expect(page.locator('.overview-intro')).toHaveCount(0);
    await expect(page.locator('.overview-entry-actions')).toHaveCount(0);
    await expect(page.locator('#overviewOpenFiles, #overviewOpenCommands')).toHaveCount(0);
    await expect(page.locator('.overview-network-subtitle')).toHaveCount(0);
    await expect(page.locator('.overview-inventory-origin small')).toHaveCount(0);
    await expect(page.locator('#overviewInventoryGroups')).toBeHidden();
    await expect(page.locator('#overviewGroupFilter')).toBeVisible();
    await expect(page.locator('#overviewInventorySummary [data-resource="groups"]')).toHaveCount(0);
    await expect(page.locator('#overviewNews')).toBeHidden();
    await page.locator('#overviewCustomize').click();
    await page.locator('[data-module=news]').getByRole('checkbox', {name:'Show',exact:true}).check();
    await page.locator('#overviewCustomize').click();
    await expect(page.locator('#overviewNews')).not.toHaveAttribute('open');
    await page.locator('#overviewNews > summary').click();
    await expect(page.locator('.overview-product-note').first()).toBeVisible();
    await page.locator('#overviewGroupFilter').selectOption('group:Operations');
    await expect(page.locator('.overview-list-group')).toHaveCount(1);
    await expect(page.locator('.overview-list-group')).toContainText('Operations');
    await expect(page.locator('#overviewGroupFilter')).toBeVisible();
    await expect(page.locator('#overviewNews')).toBeHidden();
    await page.locator('#overviewGroupFilter').selectOption('');
    await expect(page.locator('#overviewInventorySummary')).toBeVisible();
    await page.locator('#overviewInventorySummary [data-resource="keys"] button').click();
    await expect(page.locator('#keyManagementModal')).toBeVisible();
    await page.locator('#overviewNavBtn').click();
    await page.locator('#overviewCreateHost').click();
    await expect(page.locator('#profileEditorView')).toBeVisible();
    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#sftpFileManager')).toBeVisible();
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandWorkspaceModal')).toBeVisible();
});

test('host resource navigation and editor avoid duplicate captions', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#manageProfilesBtn').click();
    await expect(page.locator('#profileManagementModal .management-resource-title')).not.toBeVisible();
    await page.locator('.profile-inspect-button').first().click();
    await expect(page.locator('#profileConnectionDetailsCard [data-i18n="profiles.editProfile"]')).toHaveCount(0);
    await expect(page.locator('#profileEditorName')).toBeVisible();
    await expect(page.locator('#saveConnectProfileBtn')).toBeVisible();
});

test('a command without parameters has one authoritative code display', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('.command-inspect-button').first()).toBeVisible();
    const command = await page.evaluate(() => CommandLibrary.filteredCommands.find(item => !item.parameters && item.command && item.isSystem));
    expect(command).toBeTruthy();
    await page.locator(`.command-inspect-button[data-cmd-id="${command.id}"]`).click();
    await expect(page.locator('#commandLibraryDetails .command-detail-field pre')).toHaveCount(1);
    await expect(page.locator('#commandLibraryDetails .command-detail-field pre')).toHaveText(command.command);
    await expect(page.locator('#commandLibraryDetails').getByRole('button', {name: 'Add to my commands', exact: true})).toBeVisible();
});
