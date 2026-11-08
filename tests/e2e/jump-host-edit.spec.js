const {test, expect} = require('playwright/test');
const {login, openProfileManagement} = require('./helpers');
async function openJumps(page) {
    await openProfileManagement(page);
    await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();
}
for (const width of [390, 1536]) {
    test(`jump host edits retain identity, references and drafts at ${width}`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await openJumps(page);
        await page.locator('#jumpResourceNew').click();
        const name = `Edit bastion ${width}`;
        await page.locator('#jhNameInput').fill(name);
        await page.locator('#jhHostInput').fill('old.example');
        await page.locator('#jhUsernameInput').fill('deploy');
        await page.locator('#jhPortInput').fill('0');
        await page.locator('#saveJumpHostBtn').click();
        expect(await page.locator('#jhPortInput').evaluate(el => el.validity.rangeUnderflow)).toBe(true);
        await page.locator('#jhPortInput').fill('22');
        await page.locator('#saveJumpHostBtn').click();
        const row = page.locator('#jumpHostsList .key-item').filter({hasText: name});
        await expect(row).toBeVisible();
        const id = await page.evaluate(name => JumpHostManager.jumpHosts.find(j => j.name === name).id, name);
        await row.getByRole('button', {name:'Edit', exact:true}).click();
        await expect(page.locator('#jhHostInput')).toHaveValue('old.example');
        await page.locator('#jhHostInput').fill('draft.example');
        page.once('dialog', d => d.dismiss());
        await page.locator('#cancelJumpHostEdit').click();
        await expect(page.locator('#jhHostInput')).toHaveValue('draft.example');
        // Navigating away and returning preserves the draft rather than resetting it.
        await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
        await page.locator('#keyManagementModal [data-connection-asset="jump-hosts"]').click();
        await expect(page.locator('#jhHostInput')).toHaveValue('draft.example');
        await page.locator('#jhHostInput').fill('not a hostname');
        await page.locator('#saveJumpHostBtn').click();
        await expect(page.locator('#saveJumpHostBtn')).toBeEnabled();
        await expect(page.locator('#jhHostInput')).toHaveValue('not a hostname');
        await expect(row).toContainText('old.example');
        await page.locator('#jhHostInput').fill('edited.example');
        await page.locator('#jhPortInput').fill('2222');
        await page.locator('#saveJumpHostBtn').click();
        await expect(row).toContainText('deploy@edited.example:2222');
        expect(await page.evaluate(name => JumpHostManager.jumpHosts.filter(j => j.name === name).map(j => j.id), name)).toEqual([id]);
        await page.reload();
        await openJumps(page);
        await expect(row).toContainText('edited.example:2222');
        await row.getByRole('button', {name:'Edit', exact:true}).click();
        await expect(page.locator('#jhPortInput')).toHaveValue('2222');
        await page.locator('#cancelJumpHostEdit').click();
        await expect(page.locator('#jhNameInput')).toHaveValue('');
        await page.screenshot({path:`plans/jump-edit-review/jumps-${width}.png`,fullPage:true});
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
        expect(overflow).toBe(false);
        page.once('dialog', d => d.accept());
        await row.getByRole('button', {name:'Delete', exact:true}).click();
        await expect(row).toHaveCount(0);
    });
}
test('workspace quick connect names the action and preserves normal input focus', async ({page}) => {
    await login(page);
    const shortcut = page.locator('#workspaceRecentBtn');
    await expect(shortcut).toHaveAccessibleName('Quick Connect');
    await expect(shortcut.locator('.material-icons')).toHaveText('terminal');
    await shortcut.click();
    await expect(page.locator('#connectionModal')).toBeVisible();
    await expect(page.locator('#recentConnectionsCard summary')).not.toBeFocused();
});
test('jump host save timeout retains the draft and prevents duplicate submission', async ({page}) => {
    await login(page);
    await openJumps(page);
    await page.locator('#jumpResourceNew').click();
    await page.locator('#jhNameInput').fill('Uncertain bastion');
    await page.locator('#jhHostInput').fill('uncertain.example');
    await page.locator('#jhUsernameInput').fill('deploy');
    await page.evaluate(() => {
        window.socket.timeout = () => ({emit: (event, payload, callback) => {
            window.jumpSubmission = {event, payload};
            window.jumpCallback = callback;
        }});
    });
    await page.locator('#saveJumpHostBtn').click();
    await expect(page.locator('#saveJumpHostBtn')).toBeDisabled();
    await expect(page.locator('#jhNameInput')).toBeDisabled();
    await page.evaluate(() => window.jumpCallback(new Error('timeout')));
    await expect(page.locator('#jhNameInput')).toHaveValue('Uncertain bastion');
    await expect(page.locator('#jhNameInput')).toBeEnabled();
    await expect(page.locator('#jhSaveStatus')).toContainText('Check the saved list');
    await expect(page.locator('#saveJumpHostBtn')).toBeDisabled();
    page.once('dialog', d => d.accept());
    await page.locator('#cancelJumpHostEdit').click();
    await expect(page.locator('#saveJumpHostBtn')).toBeEnabled();
});
test('editing a key-authenticated jump retains its key after refresh', async ({page}) => {
    await login(page);
    await openJumps(page);
    const row = page.locator('#jumpHostsList .key-item').filter({hasText:'E2E key jump host'});
    const before = await page.evaluate(() => JumpHostManager.jumpHosts.find(j => j.name === 'E2E key jump host'));
    await row.getByRole('button', {name:'Edit', exact:true}).click();
    await expect(page.locator('input[name="jhAuthType"][value="key"]')).toBeChecked();
    await expect(page.locator('#jhKeySelect')).toHaveValue(before.key_id);
    await page.evaluate(() => ProfileManager.loadKeys());
    await expect(page.locator('#jhKeySelect')).toHaveValue(before.key_id);
    await page.locator('#jhPortInput').fill('2223');
    await page.locator('#saveJumpHostBtn').click();
    await expect(row).toContainText(':2223');
    const after = await page.evaluate(id => JumpHostManager.getById(id), before.id);
    expect(after.key_id).toBe(before.key_id);
    expect(after.auth_type).toBe('key');
    await row.getByRole('button', {name:'Edit', exact:true}).click();
    await page.locator('#jhPortInput').fill(String(before.port));
    await page.locator('#saveJumpHostBtn').click();
    await expect(row).toContainText(`:${before.port}`);
});
test('changing the jump host clears the password for the previous bastion', async ({page}) => {
    await login(page);
    await page.locator('#workspaceRecentBtn').click();
    await page.locator('#connectionAdvancedSettings').evaluate(el => { el.open = true; });
    const id = await page.evaluate(() => JumpHostManager.jumpHosts[0].id);
    await page.locator('#jumpHostSelect').selectOption(id);
    await page.evaluate(() => { document.getElementById('jumpHostPasswordInput').value = 'previous-bastion-secret'; });
    await page.locator('#jumpHostSelect').selectOption('');
    await expect(page.locator('#jumpHostPasswordInput')).toHaveValue('');
});
