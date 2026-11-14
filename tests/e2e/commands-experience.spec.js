const {test, expect} = require('playwright/test');

test('restored command IDs remain literal attributes and open the correct detail', async ({page}) => {
    await login(page);
    await page.evaluate(() => window.CommandLibrary.openLibrary());
    await expect(page.locator('#commandsList .command-row').first()).toBeVisible();
    // Opening the library requests a fresh list; a late reply must not replace the fixture below.
    await page.evaluate(() => { window.socket.off('commands_list'); });
    const id = 'legacy" data-injected="yes';
    await page.evaluate(id => {
        window.CommandLibrary.setCommands([{
            id, name: 'Restored command', command: 'pwd', parameters: '',
            description: 'Legacy identifier', os: ['all'], category: 'custom', isSystem: false,
        }]);
    }, id);
    const row = page.locator('#commandsList .command-row');
    await expect(row).toHaveCount(1);
    await expect(row.locator('[data-injected]')).toHaveCount(0);
    await expect(row.locator('.command-inspect-button')).toHaveAttribute('data-cmd-id', id);
    await row.locator('.command-inspect-button').click();
    await expect(page.locator('#commandLibraryDetails')).toContainText('Restored command');
});
const path = require('node:path');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

test('command sets retain the compact library search position across themes and widths', async ({page}) => {
    test.setTimeout(120000);
    await login(page);
    await page.evaluate(() => window.CommandLibrary.openLibrary());
    for (const width of [360, 768, 1440, 3440]) {
        await page.setViewportSize({width, height: 900});
        for (const theme of ['glass','solar','paper','noir','arctic-ice','rose-gold','obsidian','retro','cyberpunk-neon','emerald-matrix']) {
            await page.evaluate(theme => applyTheme(theme), theme);
            await page.locator('#commandLibraryTab').click();
            const reference = await page.locator('#commandSearchInput').boundingBox();
            await page.locator('#commandSetsTab').click();
            const search = await page.locator('#commandSetManagementSearch').boundingBox();
            expect(Math.abs(search.y - reference.y), `${theme} ${width}: search position`).toBeLessThanOrEqual(1);
            expect(search.height).toBeGreaterThanOrEqual(40);
            await expect(page.locator('#newCommandSetBtn')).toBeInViewport();
            await expect(page.locator('#commandSetUsageFilter')).toBeVisible();
            await expect(page.locator('#commandSetsPanel')).toHaveAccessibleDescription('Build reusable command sequences and assign one to any saved connection.');
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
            if (theme === 'glass' && [360, 1440].includes(width)) {
                await page.screenshot({path: test.info().outputPath(`compact-command-sets-${width}.png`)});
            }
        }
    }
});

test('system command details open a personal copy without running a session command', async ({page}) => {
    await page.setViewportSize({width: 1586, height: 991});
    await login(page);
    await page.evaluate(() => window.CommandLibrary.openLibrary());
    await expect(page.locator('.command-row.system-command').first()).toBeVisible();
    await expect(page.locator('.commands-table-header > span')).toHaveCount(6);
    await page.locator('#commandSourceFilter').selectOption('personal');
    await expect(page.locator('.command-row.system-command')).toHaveCount(0);
    await expect(page.locator('.command-row').first()).toBeVisible();
    await page.locator('#commandSourceFilter').selectOption('system');
    expect(await page.evaluate(() => window.CommandLibrary.filteredCommands.every(item => item.isSystem))).toBe(true);
    await page.locator('#commandSourceFilter').selectOption('all');
    const command = await page.evaluate(() => window.CommandLibrary.filteredCommands.find(item => item.isSystem && item.command === 'df' && item.parameters === '-h'));
    expect(command).toBeTruthy();
    const row = page.locator('.command-row').filter({has: page.locator(`button.command-inspect-button[data-cmd-id="${command.id}"]`)});
    await row.locator('.command-inspect-button').click();
    const details = page.locator('#commandLibraryDetails');
    await expect(details).toBeVisible();
    expect((await details.boundingBox()).width).toBeCloseTo(420, 0);
    await expect(details.locator('.command-source-label')).toHaveText('System · fixed template');
    await expect(details.locator('.command-detail-field pre').first()).toHaveText(command.command);
    await expect(details.locator('.command-detail-field pre').nth(2)).toHaveText('df -h');
    await expect(details.locator('input, textarea, [contenteditable="true"]')).toHaveCount(0);
    await expect(details.locator('.command-execution-hint')).toContainText('Run commands from the command tool in a session.');
    await expect(details.getByRole('button', {name: 'Edit', exact: true})).toHaveCount(0);
    await expect(details.getByRole('button', {name: 'Delete', exact: true})).toHaveCount(0);
    await page.screenshot({path: path.join(process.cwd(), 'plans/commands-reference-render.png')});
    await details.getByRole('button', {name: 'Add to my commands', exact: true}).click();
    await expect(page.locator('#commandFormName')).toHaveValue(command.name);
    await expect(page.locator('#commandFormCommand')).toHaveValue(command.command);
    expect(await page.evaluate(() => window.CommandLibrary.editingCommandId)).toBeNull();
    expect(await page.evaluate(() => Object.keys(SessionManager.sessions).length)).toBe(0);
    await page.locator('#cancelCommandFormBtn').click();
    await details.getByRole('button', {name: 'Back to list', exact: true}).click();
    await expect(details).toHaveCount(0);
    await expect(row.locator('.command-inspect-button')).toBeFocused();
});

test('favorites retain entry type across management and the workspace', async ({page}) => {
    await login(page);
    await page.evaluate(() => window.CommandSetManager.openManagement());
    // Fixture IDs are stable and selection stays literal rather than parsing a label.
    const id = await page.evaluate(() => window.CommandSetManager.commandSets[0].id);
    const target = page.locator('.command-set-management-item').filter({has: page.locator(`[data-command-set-id="${id}"]`)}).first();
    await expect(target).toBeVisible();
    await target.locator('.command-favorite').click();
    await page.locator('#commandFavoritesTab').click();
    await expect(page.locator('#commandFavoritesPanel')).toBeVisible();
    await expect(page.locator('#commandFavoritesList article.command-kind-set')).toHaveCount(1);
    await page.locator('#commandFavoritesSearch').fill('no-such-command');
    await expect(page.locator('#commandFavoritesList article.command-kind-set')).toHaveCount(0);
    await page.locator('#commandFavoritesSearch').fill('');
    await expect(page.locator('#commandFavoritesList article.command-kind-set')).toHaveCount(1);
    await page.locator('#commandFavoritesList button.command-favorite').click();
    await expect(page.locator('#commandFavoritesList article.command-kind-set')).toHaveCount(0);
});

test('builder saves in place and protects an unsaved draft from tab changes', async ({page}) => {
    await login(page, 'e2e_user');
    await page.evaluate(() => window.CommandSetManager.openBuilder());
    await page.locator('#commandSetNameInput').fill('Draft protection experience');
    await page.locator('#addInlineCommandStepBtn').click();
    await page.locator('.command-set-inline-input').fill('printf safe');
    const bounds = await page.locator('#commandSetForm').evaluate(form => ({
        stepsBottom: form.querySelector('.command-set-step').getBoundingClientRect().bottom,
        optionsTop: form.querySelector('#commandSetParameterOptions').getBoundingClientRect().top,
    }));
    expect(bounds.optionsTop).toBeGreaterThanOrEqual(bounds.stepsBottom);
    await page.locator('#commandLibraryTab').click();
    const confirm = page.locator('.command-set-confirm-dialog');
    await expect(confirm).toBeVisible();
    await confirm.getByRole('button', {name: /keep editing|weiter bearbeiten/i}).click();
    await expect(page.locator('#commandSetNameInput')).toHaveValue('Draft protection experience');
    await page.locator('#saveCommandSetBtn').click();
    await expect(page.locator('#commandSetManagementView')).toBeVisible();
    const row = page.locator('.command-set-management-item').filter({hasText: 'Draft protection experience'});
    await expect(row).toBeVisible();
    await expect(row.locator('.command-set-step-count')).toHaveCount(1);
    await expect(row).not.toContainText('1 step1 step');
    await page.evaluate(async () => {
        const item = window.CommandSetManager.commandSets.find(set => set.name === 'Draft protection experience');
        if (item) await new Promise(resolve => window.socket.emit('delete_command_set', {command_set_id:item.id}, resolve));
    });
});

for (const width of [360, 390]) test(`mobile commands and builder remain usable without horizontal overflow at ${width}px`, async ({page}) => {
    await page.setViewportSize({width,height:740});
    await login(page);
    await page.evaluate(() => window.CommandSetManager.openBuilder());
    await page.locator('#commandSetNameInput').fill('Mobile draft');
    await page.locator('#addInlineCommandStepBtn').click();
    await page.locator('.command-set-inline-input').fill('printf mobile');
    await expect(page.locator('#commandSetDraftPreview')).toContainText('printf mobile');
    await expect(page.locator('#saveCommandSetBtn')).toBeVisible();
    const overflow = await page.evaluate(() => {
        const root = document.querySelector('#commandWorkspaceModal');
        return [...root.querySelectorAll('button,input,textarea,pre')].filter(el => el.getClientRects().length)
            .filter(el => { const r=el.getBoundingClientRect(); return r.left < -1 || r.right > innerWidth + 1; }).map(el=>el.id || el.className);
    });
    expect(overflow).toEqual([]);
    await page.emulateMedia({reducedMotion:'reduce'});
    await expect(page.locator('#commandSetSteps')).toBeVisible();
    await page.screenshot({path:test.info().outputPath(`commands-builder-${width}.png`)});
});

test('hostile command names remain literal in library and favorites', async ({page}) => {
    await login(page);
    await expect.poll(()=>page.evaluate(()=>window.CommandLibrary.commands.length)).toBeGreaterThan(0);
    const name = '<img src=x onerror="window.commandInjected=true">';
    await page.evaluate(name=>{
        window.CommandLibrary.setCommands([{id:'literal-command',name,command:'printf',parameters:'<script>',description:'Literal <b>description</b>',os:['all'],category:'custom',isSystem:false}]);
        window.CommandWorkspace.open('library');
    },name);
    const row = page.locator('#commandsList .command-row');
    await expect(row).toHaveCount(1);
    await expect(row).toContainText(name);
    await expect(row.locator('img,script,b')).toHaveCount(0);
    await row.locator('button.command-favorite').click();
    await page.locator('#commandFavoritesTab').click();
    await expect(page.locator('#commandFavoritesList')).toContainText(name);
    await expect(page.locator('#commandFavoritesList img, #commandFavoritesList script')).toHaveCount(0);
    expect(await page.evaluate(()=>window.commandInjected)).toBeUndefined();
});

test('command editor Escape keeps unsaved text unless discard is confirmed', async ({page}) => {
    await login(page);
    await page.evaluate(()=>window.CommandWorkspace.open('library'));
    await page.locator('#addCommandBtn').click();
    await page.locator('#commandFormName').fill('Preserve this draft');
    await page.keyboard.press('Escape');
    const confirmation = page.locator('.command-set-confirm-dialog');
    await expect(confirmation).toBeVisible();
    await confirmation.getByRole('button',{name:'Keep editing',exact:true}).click();
    await expect(page.locator('#commandFormName')).toHaveValue('Preserve this draft');
    await page.locator('#cancelCommandFormBtn').click();
    await expect(confirmation).toBeVisible();
    await confirmation.locator('.btn-danger').click();
    await expect(page.locator('#commandFormModal')).not.toBeVisible();
});


test('mobile catalog separates inspection defaults from advanced effects and returns to its filtered list', async ({page}) => {
    await page.setViewportSize({width: 360, height: 740});
    await login(page);
    await page.evaluate(() => window.CommandLibrary.openLibrary());
    await expect(page.locator('#commandsList .command-row').first()).toBeVisible();
    expect(await page.evaluate(() => window.CommandLibrary.filteredCommands.some(item => item.id === 'file-006'))).toBe(false);
    await page.locator('#commandSearchInput').fill('rm -rf');
    const row = page.locator('#commandsList .command-row').filter({has: page.locator('[data-cmd-id="file-006"]')});
    await expect(row).toBeVisible();
    await row.locator('.command-inspect-button').click();
    const details = page.locator('#commandLibraryDetails');
    await expect(details.locator('.command-impact-label')).toHaveText('Deletes or overwrites data');
    await expect(details.locator('.command-source-label')).toHaveText('System · fixed template');
    await details.evaluate(node => { node.scrollTop = node.scrollHeight; });
    await expect(details.getByRole('button', {name:'Back to list', exact:true})).toBeInViewport();
    await details.getByRole('button', {name:'Back to list', exact:true}).click();
    await expect(page.locator('#commandSearchInput')).toHaveValue('rm -rf');
    await expect(row.locator('.command-inspect-button')).toBeFocused();
    await page.locator('#commandSearchInput').fill('ping');
    await page.locator('#commandLibraryPanel .os-filter-btn[data-os="windows"]').click();
    expect(await page.evaluate(() => window.CommandLibrary.filteredCommands.filter(item => item.command === 'ping').map(item => item.parameters))).toEqual(['-n 4 hostname']);
    expect(await page.evaluate(() => Object.keys(SessionManager.sessions).length)).toBe(0);
});

for (const width of [360, 390]) for (const language of ['en', 'de']) {
    test(`mobile inspector return label fits at ${width}px in ${language}`, async ({page}) => {
        await page.setViewportSize({width, height: 740});
        await login(page);
        await page.evaluate(async language => {
            window.i18n.setLanguage(language);
            window.CommandLibrary.openLibrary();
            await window.CommandLibrary.applyLanguage();
        }, language);
        await page.locator('#commandSearchInput').fill('apt upgrade');
        await page.locator('[data-cmd-id="sys-002"].command-inspect-button').click();
        const back = page.locator('#commandLibraryDetails .inspector-return');
        await expect(back).toBeInViewport();
        const dimensions = await back.evaluate(button => {
            const label = button.querySelector('.inspector-return-label');
            const range = document.createRange();
            range.selectNodeContents(label);
            const style = getComputedStyle(label);
            return {
                buttonWidth: button.getBoundingClientRect().width,
                panelScrollLeft: button.closest('aside').scrollLeft,
                panelClientWidth: button.closest('aside').clientWidth,
                panelScrollWidth: button.closest('aside').scrollWidth,
                headingWidth: button.parentElement.getBoundingClientRect().width,
                titleWidth: button.parentElement.querySelector('h3').clientWidth,
                titleScrollWidth: button.parentElement.querySelector('h3').scrollWidth,
                labelWidth: label.clientWidth,
                labelScrollWidth: label.scrollWidth,
                lines: range.getClientRects().length,
                height: label.getBoundingClientRect().height,
                lineHeight: parseFloat(style.lineHeight),
            };
        });
        expect(dimensions.panelScrollLeft).toBe(0);
        expect(dimensions.panelScrollWidth).toBeLessThanOrEqual(dimensions.panelClientWidth + 1);
        expect(dimensions.headingWidth).toBeLessThanOrEqual(dimensions.panelClientWidth + 1);
        expect(dimensions.titleScrollWidth).toBeLessThanOrEqual(dimensions.titleWidth + 1);
        expect(dimensions.lines).toBe(1);
        expect(dimensions.labelWidth).toBeGreaterThan(50);
        expect(dimensions.labelScrollWidth).toBeLessThanOrEqual(dimensions.labelWidth + 1);
        expect(dimensions.height).toBeLessThanOrEqual(dimensions.lineHeight + 1);
        expect(dimensions.buttonWidth).toBeGreaterThan(dimensions.labelWidth + 28);
        await page.screenshot({path:test.info().outputPath(`return-label-${width}-${language}.png`), animations:'disabled'});
        await back.click();
        await expect(page.locator('#commandSearchInput')).toHaveValue('apt upgrade');
    });
}
