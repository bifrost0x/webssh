const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

for (const kind of ['command', 'set']) {
    test(`${kind} draft survives a cancelled reload and stops warning after discard`, async ({page}) => {
        await login(page);
        await page.locator('#commandLibraryBtn').click();
        if (kind === 'command') await page.locator('#addCommandBtn').click();
        else {
            await page.locator('#commandSetsTab').click();
            await page.locator('#newCommandSetBtn').click();
        }
        const input = page.locator(kind === 'command' ? '#commandFormName' : '#commandSetNameInput');
        await input.fill('Unsaved command draft');
        const dialogs = [];
        page.on('dialog', async dialog => { dialogs.push(dialog.type()); await dialog.dismiss(); });
        await page.evaluate(() => setTimeout(() => location.reload(), 0));
        await expect.poll(() => dialogs).toEqual(['beforeunload']);
        await expect(input).toHaveValue('Unsaved command draft');
        if (kind === 'command') await page.locator('#cancelCommandFormBtn').click();
        else await page.locator('#commandLibraryTab').click();
        await page.locator('.command-set-confirm-dialog').getByRole('button', {name: 'Discard', exact: true}).click();
        await expect(input).not.toBeVisible();
        await page.reload();
        expect(dialogs).toEqual(['beforeunload']);
    });
}
