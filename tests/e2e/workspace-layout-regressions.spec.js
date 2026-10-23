const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

async function seedCommands(page) {
    await expect.poll(() => page.evaluate(() => window.CommandLibrary?.commands.length || 0)).toBeGreaterThan(0);
    // Use the same public rendering fixture contract as commands-experience.spec.js.
    await page.evaluate(() => {
        const commands = Array.from({length: 48}, (_, index) => ({
            id: `layout-command-${index}`, name: `Layout command ${String(index).padStart(2, '0')}`,
            command: `printf 'layout ${index}'`, parameters: '',
            description: index === 0 ? 'x'.repeat(128) : 'A short command description.',
            os: ['all'], category: 'custom', isSystem: true,
        }));
        commands[0].name = `A${'Unbroken'.repeat(16)}`;
        window.CommandLibrary.setCommands(commands);
        window.SessionCommandLauncher.ensurePreferences();
        commands.forEach(command => {
            const entry = {type: 'command', id: command.id};
            if (!window.SessionCommandLauncher.favorites.has(window.SessionCommandLauncher.entryKey(entry))) {
                window.SessionCommandLauncher.toggleFavorite(entry);
            }
        });
        window.CommandWorkspace.open('library');
    });
}

async function assertContained(page, panelSelector) {
    const outside = await page.locator(panelSelector).evaluate(panel => {
        const boundary = panel.getBoundingClientRect();
        return [...panel.querySelectorAll('button,input,textarea,pre,.command-row,.command-card,.command-set-step')]
            .filter(element => element.getClientRects().length)
            .filter(element => {
                const rect = element.getBoundingClientRect();
                return rect.left < Math.max(0, boundary.left) - 1
                    || rect.right > Math.min(innerWidth, boundary.right) + 1;
            }).map(element => element.id || element.className);
    });
    expect(outside, 'Rendered controls and cards must remain inside the panel and viewport').toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
}

async function wheelToEnd(page, last, panelSelector) {
    const body = page.locator('#commandWorkspaceModal .command-workspace-body');
    const box = await body.boundingBox();
    expect(box.height).toBeGreaterThan(80);
    expect(box.y + box.height).toBeLessThanOrEqual((await page.viewportSize()).height + 1);
    const before = await body.evaluate(element => element.scrollTop);
    await page.mouse.move(box.x + box.width - 12, box.y + Math.min(100, box.height / 2));
    await page.mouse.wheel(0, 420);
    await expect.poll(() => body.evaluate(element => element.scrollTop), {
        message: 'Wheel input must scroll the command workspace body',
    }).toBeGreaterThan(before);
    await expect(async () => {
        await page.mouse.wheel(0, 100000);
        expect(await body.evaluate(element => element.scrollHeight - element.clientHeight - element.scrollTop))
            .toBeLessThanOrEqual(1);
    }).toPass({timeout: 10000});
    // Library help follows its final card; bring the complete reachable card into view.
    const target = await last.boundingBox();
    // Wheel upward when trailing help leaves the card's header clipped at the top.
    await page.mouse.wheel(0, target.y + target.height / 2 - box.y - box.height / 2);
    await expect(last).toBeInViewport({ratio: 1});
    await expect(page.locator('#commandLibraryTab')).toBeInViewport({ratio: 1});
    await expect(page.locator('#commandSetsTab')).toBeInViewport({ratio: 1});
    await assertContained(page, panelSelector);
}

for (const width of [360, 733, 1440, 3043]) {
    const height = width < 1000 ? 529 : 900;
    test(`library and favorites scroll to the final card at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height});
        await page.emulateMedia({reducedMotion: 'reduce'});
        await login(page);
        await seedCommands(page);
        await expect(page.locator('#commandWorkspaceModal')).toHaveAttribute('role', 'region');
        await assertContained(page, '#commandLibraryPanel');
        if (width === 3043) {
            const geometry = await page.locator('#commandLibraryPanel').evaluate(panel => ({
                panelWidth: panel.getBoundingClientRect().width,
                gridWidth: panel.querySelector('#commandsList').getBoundingClientRect().width,
                cardHeight: panel.querySelector('.command-row:last-child').getBoundingClientRect().height,
            }));
            expect(geometry.gridWidth).toBeGreaterThanOrEqual(geometry.panelWidth * 0.9);
            expect(geometry.cardHeight, 'Short system cards should not have large empty vertical regions').toBeLessThan(340);
        }
        await wheelToEnd(page, page.locator('#commandsList .command-row').last(), '#commandLibraryPanel');
        const libraryFavorite = page.locator('#commandsList .command-row').last().locator('button.command-favorite');
        await libraryFavorite.focus();
        await page.keyboard.press('Space');
        await expect(libraryFavorite).toBeFocused();
        await expect(libraryFavorite).toHaveAttribute('aria-pressed', 'false');
        await page.keyboard.press('Space');
        await expect(libraryFavorite).toBeFocused();
        await expect(libraryFavorite).toHaveAttribute('aria-pressed', 'true');
        // Arrow navigation also needs to retain a usable, visible resource tab bar.
        await page.locator('#commandLibraryTab').focus();
        await page.keyboard.press('ArrowRight');
        await expect(page.locator('#commandFavoritesTab')).toBeFocused();
        await expect(page.locator('#commandFavoritesPanel')).toBeVisible();
        await expect(page.locator('#commandFavoritesList article')).toHaveCount(48);
        await wheelToEnd(page, page.locator('#commandFavoritesList article').last(), '#commandFavoritesPanel');
        await page.locator('#commandFavoritesList article').last().locator('button.command-favorite').focus();
        await page.keyboard.press('Space');
        await expect(page.locator('#commandFavoritesList article')).toHaveCount(47);
        await expect(page.locator('#commandFavoritesList article').last().locator('button.command-favorite')).toBeFocused();
        await page.locator('#commandFavoritesSearch').fill('Layout command 46');
        await expect(page.locator('#commandFavoritesList article')).toHaveCount(1);
        await page.locator('#commandFavoritesList article button.command-favorite').focus();
        await page.keyboard.press('Space');
        await expect(page.locator('#commandFavoritesList article')).toHaveCount(0);
        await expect(page.locator('#commandFavoritesSearch')).toBeFocused();
    });

    for (const nested of [false, true]) {
        test(`${nested ? 'connection modal' : 'primary'} builder reaches final step and footer at ${width}px`, async ({page}) => {
            await page.setViewportSize({width, height});
            await page.emulateMedia({reducedMotion: 'reduce'});
            await login(page);
            if (nested) await page.locator('#newTabBtn').click();
            await page.evaluate(nested => window.CommandSetManager.openBuilder(null, nested), nested);
            await expect(page.locator('#commandWorkspaceModal')).toHaveAttribute('role', nested ? 'dialog' : 'region');
            await page.locator('#commandSetNameInput').fill('Long layout draft');
            for (let index = 0; index < 12; index++) {
                await page.locator('#addInlineCommandStepBtn').click();
            }
            await expect(page.locator('#commandSetSteps .command-set-step')).toHaveCount(12);
            // UI additions may scroll the focused field; begin wheel verification at the top.
            await page.locator('#commandWorkspaceModal .command-workspace-body').evaluate(element => { element.scrollTop = 0; });
            await wheelToEnd(page, page.locator('#commandSetForm .command-set-editor-actions'), '#commandSetsPanel');
            await expect(page.locator('#saveCommandSetBtn')).toBeInViewport({ratio: 1});
            const lastInput = page.locator('#commandSetSteps .command-set-inline-input').last();
            await lastInput.scrollIntoViewIfNeeded();
            await lastInput.fill('printf final-layout-step');
            await expect(lastInput).toHaveValue('printf final-layout-step');
            await expect(lastInput).toBeInViewport({ratio: 1});
            await page.locator('#saveCommandSetBtn').focus();
            await expect(page.locator('#saveCommandSetBtn')).toBeFocused();
            await expect(page.locator('#saveCommandSetBtn')).toBeInViewport({ratio: 1});
        });
    }
}

for (const width of [360, 819, 1440, 3043]) test(`dirty navigation dialog is centered and Escape preserves the draft at ${width}px`, async ({page}) => {
    await page.setViewportSize({width, height: 529});
    await page.emulateMedia({reducedMotion: 'reduce'});
    await login(page);
    await page.evaluate(() => window.CommandSetManager.openBuilder());
    await page.locator('#commandSetNameInput').fill('Keep this layout draft');
    await page.locator('#commandLibraryTab').click();
    const dialog = page.locator('dialog.command-set-confirm-dialog[open]');
    await expect(dialog).toBeVisible();
    const rect = await dialog.boundingBox();
    expect(Math.abs(rect.x + rect.width / 2 - width / 2)).toBeLessThanOrEqual(2);
    expect(Math.abs(rect.y + rect.height / 2 - 529 / 2)).toBeLessThanOrEqual(2);
    await expect(dialog.getByRole('button', {name: 'Keep editing', exact: true})).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(page.locator('#commandSetNameInput')).toHaveValue('Keep this layout draft');
    await expect(page.locator('#commandSetsPanel')).toBeVisible();
    await expect(page.locator('#commandLibraryTab')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', {name: 'Discard', exact: true}).click();
    await expect(page.locator('#commandLibraryPanel')).toBeVisible();
    expect(await page.evaluate(() => window.CommandSetManager.hasUnsavedChanges())).toBe(false);
});

test('long confirmation content and actions remain reachable in a short viewport', async ({page}) => {
    await page.setViewportSize({width: 819, height: 320});
    await page.emulateMedia({reducedMotion: 'reduce'});
    await login(page);
    await page.evaluate(() => {
        window.CommandSetManager.confirmDialog({
            title: 'Long confirmation', message: 'Long confirmation content. '.repeat(80),
            confirmLabel: 'Confirm long content', cancelLabel: 'Keep editing',
        });
    });
    const dialog = page.locator('dialog.command-set-confirm-dialog[open]');
    await expect(dialog).toBeVisible();
    const rect = await dialog.boundingBox();
    expect(Math.abs(rect.x + rect.width / 2 - 819 / 2)).toBeLessThanOrEqual(2);
    expect(Math.abs(rect.y + rect.height / 2 - 320 / 2)).toBeLessThanOrEqual(2);
    await dialog.getByRole('button', {name: 'Confirm long content', exact: true}).focus();
    await expect(dialog.getByRole('button', {name: 'Confirm long content', exact: true})).toBeInViewport({ratio: 1});
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
});
