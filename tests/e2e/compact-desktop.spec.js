const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.use({viewport: {width: 1280, height: 720}});
test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('overview compact row contents do not overlap at laptop widths', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await expect.poll(() => page.locator('.overview-compact-row').count()).toBeGreaterThan(0);
    for (const width of [1920, 1600, 1440, 1280, 1152, 1024]) {
        await page.setViewportSize({width, height: 720});
        const collisions = await page.locator('.overview-compact-row').evaluateAll(buttons => buttons.flatMap(button => {
            const children = [...button.children].filter(el => el.getClientRects().length);
            return children.flatMap((a, i) => children.slice(i + 1).filter(b => {
                const x = a.getBoundingClientRect(), y = b.getBoundingClientRect();
                return Math.min(x.right, y.right) - Math.max(x.left, y.left) > 1
                    && Math.min(x.bottom, y.bottom) - Math.max(x.top, y.top) > 1;
            }).map(b => `${a.className}/${b.className}`));
        }));
        expect(collisions).toEqual([]);
    }
});

test('compact command details reserve the view and return to the same searchable library', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#commandLibraryBtn').click();
    const command = page.locator('.command-inspect-button').first();
    const title = await command.innerText();
    await command.click();
    expect(await page.locator('.commands-table-wrapper').evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
    await page.setViewportSize({width: 1024, height: 720});
    await expect(page.locator('.command-library-details')).toBeVisible();
    await expect(page.locator('#commandLibraryPanel > .command-toolbar')).toBeHidden();
    await page.locator('.command-library-details .management-inspector-heading button').click();
    await expect(page.locator('#commandLibraryPanel > .command-toolbar')).toBeVisible();
    await expect(page.locator('.command-inspect-button').first()).toHaveText(title);
});

test('empty workspace host choices stay reachable beside open notes', async ({page}) => {
    await login(page, 'e2e_admin');
    if (!await page.locator('#contextNotesPanel').isVisible()) await page.locator('#contextNotesTab').click();
    await expect(page.locator('.profile-launcher-card').first()).toBeVisible();
    const geometry = await page.evaluate(() => {
        const notes = document.querySelector('#contextWorkspace').getBoundingClientRect();
        const chooser = document.querySelector('.profile-launcher-sections').getBoundingClientRect();
        return {chooserRight: chooser.right, notesLeft: notes.left};
    });
    expect(geometry.chooserRight).toBeLessThanOrEqual(geometry.notesLeft + 1);
    await page.locator('#sessionNotepad').fill('Compact desktop review');
    await page.locator('#contextWorkspaceClose').click();
    await expect(page.locator('.profile-launcher-card').first()).toBeVisible();
    await page.locator('#contextNotesTab').click();
    await expect(page.locator('#sessionNotepad')).toHaveValue('Compact desktop review');
});
