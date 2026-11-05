const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('assigning a session to another pane moves it and clears the previous target', async ({page}) => {
    await login(page);
    await page.evaluate(() => new Promise(resolve => socket.emit('e2e_workspace_restore', {count: 1}, resolve)));
    try {
        await page.reload();
        await page.locator('#workspaceNavBtn').click();
        await expect(page.locator('.session-tab')).toHaveCount(1);
        const id = await page.evaluate(() => {
            const id = SessionManager.getAllSessions()[0].id;
            SessionManager.showPaneAssignmentModal(2);
            return id;
        });
        await page.locator('input[name="pane-0"]').nth(1).locator('..').click();
        await page.locator('input[name="pane-1"]').nth(1).locator('..').click();
        await expect(page.locator('input[name="pane-0"][value="__empty__"]')).toBeChecked();
        await page.locator('#applyPaneAssignment').click();
        expect(await page.evaluate(() => SessionManager.paneAssignments)).toEqual([null, id]);
        await expect(page.locator('#terminalGrid .terminal-pane').nth(1).locator('.terminal-wrapper')).toHaveCount(1);
        await page.evaluate(id => SessionManager.applyPaneAssignments(2, [id, id]), id);
        expect(await page.evaluate(() => SessionManager.paneAssignments)).toEqual([id, null]);
        await expect(page.locator('#terminalGrid .terminal-pane').first().locator('.terminal-wrapper')).toHaveCount(1);
    } finally {
        await page.evaluate(() => new Promise(resolve => socket.emit('e2e_workspace_restore', {count: 0}, resolve)));
    }
});
