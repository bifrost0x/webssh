const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

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
