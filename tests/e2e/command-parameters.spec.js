const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => {
    const result = await page.evaluate(async () => {
        const saved = window.CommandSetManager?.commandSets.find(item => item.name === 'Parameterized path inspection');
        if (!saved) return {success: true};
        return new Promise((resolve, reject) => window.socket.timeout(5000).emit(
            'delete_command_set', {command_set_id: saved.id},
            (error, response) => error ? reject(error) : resolve(response)
        ));
    });
    expect(result.success).toBe(true);
    assertNoExternalRequests(page);
});

test('argument sets save explicit declarations and preview values before insertion', async ({page}) => {
    await login(page);
    await page.evaluate(() => window.CommandSetManager.openBuilder());
    await page.locator('#commandSetNameInput').fill('Parameterized path inspection');
    await page.locator('#commandSetParameterNames').fill('path');
    await page.locator('#addArgumentCommandStepBtn').click();
    await page.locator('[data-step-field="argv"]').fill('["ls", "--", "{{path}}"]');
    await page.locator('#saveCommandSetBtn').click();
    await expect.poll(() => page.evaluate(() => window.CommandSetManager.commandSets.find(item => item.name === 'Parameterized path inspection')?.parameters)).toEqual([{name: 'path'}]);
    await page.evaluate(() => {
        window.CommandSetManager.renderSelect();
        window.ProfileManager.renderEditorSelects();
    });
    await expect(page.locator('#commandSetSelect option').filter({hasText: 'Parameterized path inspection'})).toHaveCount(0);
    await expect(page.locator('#profileEditorCommandSetSelect option').filter({hasText: 'Parameterized path inspection'})).toHaveCount(0);
    await page.evaluate(() => {
        SessionManager.createSession({session_id: 'parameter-session', host: 'preview.local', username: 'operator', port: 22});
        window.__parameterInputs = [];
        window.SSHInput = {...window.SSHInput, send: async (id, text) => { window.__parameterInputs.push([id, text]); return true; }};
        window.CommandWorkspace.close();
        SessionManager.switchSession('parameter-session');
        window.workspaceLayoutController.openContext('commands', 'user');
    });
    const row = page.locator('.session-command-item').filter({has: page.getByText('Parameterized path inspection', {exact: true})});
    await expect(row).toBeVisible();
    const insert = row.getByRole('button', {name: 'Insert', exact: true});
    await expect(insert).toBeDisabled();
    await row.getByLabel('path', {exact: true}).fill("a'; $(id)");
    await row.getByRole('button', {name: 'Resolve preview'}).click();
    await expect(insert).toBeEnabled();
    await expect(row.locator('code')).toContainText("'ls' -- 'a'\"'\"'; $(id)'");
    expect(await page.evaluate(() => window.__parameterInputs)).toEqual([]);
    await row.getByLabel('path', {exact: true}).fill('new path');
    await expect(insert).toBeDisabled();
    await row.getByRole('button', {name: 'Resolve preview'}).click();
    await expect(insert).toBeEnabled();
    await insert.click();
    expect(await page.evaluate(() => window.__parameterInputs)).toEqual([['parameter-session', "'ls' -- 'new path'"]]);
});
