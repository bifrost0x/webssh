const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

async function openCommands(page) {
    const button = page.locator('#commandLibraryBtn');
    if (await button.isVisible()) await button.click();
    else await page.locator('[data-mobile-view="commands"]').click();
}

for (const width of [1536, 390]) {
    test(`command and command-set edits survive a reload at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page);
        const name = `Persistence ${width}`;
        await openCommands(page);
        await page.locator('#commandLibraryTab').click();
        await page.locator('#addCommandBtn').click();
        await page.locator('#commandFormName').fill(name);
        await page.locator('#commandFormCommand').fill('printf');
        await page.locator('#commandFormParams').fill('original');
        await page.locator('#commandFormDescription').fill('Persistence regression check');
        await page.locator('#osAll').check();
        await page.locator('#commandForm button[type="submit"]').click();
        await page.locator('#commandSearchInput').fill(name);
        const command = page.locator('.command-row').filter({hasText: name});
        await expect(command).toHaveCount(1);
        await command.locator('.cmd-edit').click();
        await page.locator('#commandFormParams').fill('edited');
        await page.locator('#commandForm button[type="submit"]').click();
        await expect(command).toContainText('edited');

        await page.locator('#commandSetsTab').click();
        await page.locator('#newCommandSetBtn').click();
        await page.locator('#commandSetNameInput').fill(name);
        await page.locator('#addInlineCommandStepBtn').click();
        await page.locator('#commandSetSteps textarea').fill('printf first');
        await page.locator('#addInlineCommandStepBtn').click();
        await page.locator('#commandSetSteps textarea').nth(1).fill('printf second');
        await page.locator('#saveCommandSetBtn').click();
        await expect(page.locator('#commandSetEditorView')).not.toBeVisible();
        await openCommands(page);
        await page.locator('#commandSetsTab').click();
        const set = page.locator('.command-set-management-item').filter({
            has: page.getByText(name, {exact: true}),
        });
        await expect(set).toContainText(/2 steps/i);
        await set.locator('summary').click();
        await set.locator('[data-command-set-action="edit"]').click();
        await page.locator('#commandSetSteps textarea').nth(1).fill('printf changed');
        await page.locator('#saveCommandSetBtn').click();
        await expect(page.locator('#commandSetEditorView')).not.toBeVisible();
        await page.reload();
        await openCommands(page);
        await page.locator('#commandSetsTab').click();
        await set.locator('summary').click();
        await set.locator('[data-command-set-action="edit"]').click();
        await expect(page.locator('#commandSetSteps textarea').nth(1)).toHaveValue('printf changed');
        await page.locator('#cancelCommandSetBtn').click();
        await set.locator('summary').click();
        await set.locator('[data-command-set-action="duplicate"]').click();
        const copy = page.locator('.command-set-management-item').filter({
            has: page.getByText(`${name} Copy`, {exact: true}),
        });
        await expect(copy).toContainText(/2 steps/i);
        await copy.locator('summary').click();
        await copy.locator('[data-command-set-action="edit"]').click();
        await expect(page.locator('#commandSetSteps textarea').nth(1)).toHaveValue('printf changed');
        await page.locator('#cancelCommandSetBtn').click();
        page.once('dialog', dialog => dialog.accept());
        await copy.locator('summary').click();
        await copy.locator('[data-command-set-action="delete"]').click();
        await expect(copy).toHaveCount(0);
        page.once('dialog', dialog => dialog.accept());
        await set.locator('summary').click();
        await set.locator('[data-command-set-action="delete"]').click();
        await expect(set).toHaveCount(0);
        await page.locator('#commandLibraryTab').click();
        await page.locator('#commandSearchInput').fill(name);
        await command.locator('.cmd-edit').click();
        await expect(page.locator('#commandFormParams')).toHaveValue('edited');
        await page.locator('#cancelCommandFormBtn').click();
        page.once('dialog', dialog => dialog.accept());
        await command.locator('.cmd-delete').click();
        await expect(command).toHaveCount(0);
        await page.reload();
        await openCommands(page);
        await page.locator('#commandSetsTab').click();
        await expect(set).toHaveCount(0);
        await page.locator('#commandLibraryTab').click();
        await page.locator('#commandSearchInput').fill(name);
        await expect(command).toHaveCount(0);
        await assertNoExternalRequests(page);
    });

    test(`jump-host creation and deletion persist at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page);
        await openProfileManagement(page);
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        const name = `Persistence bastion ${width}`;
        await page.locator('#jhNameInput').fill(name);
        await page.locator('#jhHostInput').fill('bastion.example');
        await page.locator('#jhPortInput').fill('2222');
        await page.locator('#jhUsernameInput').fill('tester');
        await page.locator('#jumpHostForm button[type="submit"]').click();
        const item = page.locator('#jumpHostsList .key-item').filter({hasText: name});
        await expect(item).toContainText('tester@bastion.example:2222');
        await page.reload();
        await openProfileManagement(page);
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        await expect(item).toContainText('tester@bastion.example:2222');
        page.once('dialog', dialog => dialog.accept());
        await item.getByRole('button', {name: 'Delete', exact: true}).click();
        await expect(item).toHaveCount(0);
        await page.reload();
        await openProfileManagement(page);
        await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
        await expect(item).toHaveCount(0);
        await assertNoExternalRequests(page);
    });
}

test('command-set editor does not steal focus after the user chooses another field', async ({page}) => {
    await login(page);
    await openCommands(page);
    await page.locator('#commandSetsTab').click();
    // Control the opening delay so fast input cannot make this regression intermittent.
    await page.clock.install();
    await page.clock.pauseAt(new Date());
    await page.locator('#newCommandSetBtn').dispatchEvent('click');
    const description = page.locator('#commandSetDescriptionInput');
    await description.focus();
    await page.clock.runFor(100);
    await expect(description).toBeFocused();
    await description.fill('Keep input in the selected field');
    await expect(page.locator('#commandSetNameInput')).toHaveValue('');
    await assertNoExternalRequests(page);
});
