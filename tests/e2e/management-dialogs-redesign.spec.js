const { test, expect } = require('playwright/test');
const path = require('node:path');
const {
    assertNoExternalRequests,
    login,
    openKeyManagement,
    openProfileManagement,
} = require('./helpers');

test.beforeEach(async ({ page }) => {
    await login(page);
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('host reference capture retains fixture identity and separate resource columns', async ({page}) => {
    await page.setViewportSize({width: 1586, height: 991});
    await openProfileManagement(page);
    await page.locator('.profile-inspect-button').filter({hasText: /^Usable key$/}).click();
    await expect(page.locator('#profileConnectionDetailsTitle')).toHaveText('Usable key');
    expect((await page.locator('#profileEditorView').boundingBox()).width).toBeCloseTo(420, 0);
    expect((await page.locator('label[for="profileEditorAuthType"]').boundingBox()).height).toBeLessThan(30);
    await expect(page.locator('.profile-management-columns > span')).toHaveCount(6);
    await expect(page.locator('#profileEditorUsername')).toHaveValue('keyuser');
    await page.locator('#profileConnectionDetailsTitle').click();
    await page.screenshot({path: path.join(process.cwd(), 'plans/hosts-reference-render.png')});
    await page.locator('.profile-inspector-close').click();
    await expect(page.locator('#profileEditorView')).not.toBeVisible();
    await expect(page.locator('#profileSearchInput')).toBeVisible();
});

test('keeps saved-connection actions visible while its form scrolls', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 700 });
    await openProfileManagement(page);
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorAuthType').selectOption('key');
    await page.locator('#profileEditorAddKeyBtn').click();
    await page.locator('#profileAdvancedSettingsCard > summary').click();
    await page.locator('#profileEditorPostConnectMode').selectOption('free_text');

    await expect(page.locator('#profileConnectionDetailsCard')).toBeVisible();
    await expect(page.locator('#profileAdvancedSettingsCard')).toBeVisible();
    await expect(page.locator('#cancelProfileEditorBtn')).toBeVisible();
    await expect(page.locator('#saveConnectProfileBtn')).toBeVisible();

    const before = await page.locator('#profileEditorForm').evaluate(form => {
        const scroller = form.querySelector('.profile-editor-scroll-region');
        const actions = form.querySelector('.profile-editor-actions').getBoundingClientRect();
        return {
            actionsTop: actions.top,
            clientHeight: scroller.clientHeight,
            scrollHeight: scroller.scrollHeight,
        };
    });
    expect(before.scrollHeight).toBeGreaterThan(before.clientHeight);

    await page.locator('.profile-editor-scroll-region').evaluate(scroller => {
        scroller.scrollTop = scroller.scrollHeight;
    });
    const after = await page.locator('#profileEditorForm').evaluate(form => ({
        actionsTop: form.querySelector('.profile-editor-actions').getBoundingClientRect().top,
        scrollTop: form.querySelector('.profile-editor-scroll-region').scrollTop,
    }));
    expect(after.scrollTop).toBeGreaterThan(0);
    expect(after.actionsTop).toBeCloseTo(before.actionsTop, 0);
});

test('host inspector protects a dirty selection and persists explicit saves without connecting', async ({page}) => {
    await page.setViewportSize({width: 1280, height: 800});
    await openProfileManagement(page);
    const name = 'Inspector persistence regression';
    let profileId;
    try {
        await page.locator('#newProfileBtn').click();
        await page.locator('#profileEditorName').fill(name);
        await page.locator('#profileEditorHost').fill('inspector.example');
        await page.locator('#profileEditorUsername').fill('original');
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        const selected = page.locator('.profile-inspect-button').filter({hasText: name});
        await expect(selected).toBeVisible();
        profileId = await selected.getAttribute('data-profile-id');
        await selected.click();
        await expect(page.locator('#profileManagementView')).toBeVisible();
        await expect(page.locator('#profileAdvancedSettingsCard')).not.toHaveAttribute('open');
        const bounds = await page.locator('#profileManagementModal').evaluate(modal => ({
            list: modal.querySelector('#profileManagementView').getBoundingClientRect().right,
            editor: modal.querySelector('#profileEditorView').getBoundingClientRect().left,
        }));
        expect(bounds.editor).toBeGreaterThanOrEqual(bounds.list);
        expect(await page.locator('#profileManagementList').evaluate(list => list.scrollWidth <= list.clientWidth + 1)).toBe(true);
        await page.locator('#profileEditorUsername').fill('edited');
        await page.locator('.profile-inspect-button').filter({hasNotText: name}).first().click();
        const confirmation = page.locator('.command-set-confirm-dialog');
        await expect(confirmation).toBeVisible();
        await confirmation.getByRole('button', {name: 'Keep editing', exact: true}).click();
        await expect(page.locator('#profileEditorUsername')).toHaveValue('edited');
        await expect(page.locator('#profileEditorId')).toHaveValue(profileId);
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        await expect(selected.locator('..')).toContainText('edited@inspector.example');
        await page.reload();
        await openProfileManagement(page);
        await selected.click();
        await expect(page.locator('#profileEditorUsername')).toHaveValue('edited');
        expect(await page.evaluate(() => Object.keys(SessionManager.sessions).length)).toBe(0);
    } finally {
        if (profileId) await page.evaluate(id => new Promise(resolve => window.socket.emit('delete_profile', {profile_id: id}, resolve)), profileId);
    }
});

for (const width of [390, 1180]) {
    test(`resource libraries open focused editors and return to their list at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 844});
        await openProfileManagement(page);
        for (const [kind, id, button, input] of [
            ['jump-hosts', 'jumpHostManagementModal', 'jumpResourceNew', 'jhNameInput'],
            ['keys', 'keyManagementModal', 'keyResourceNew', 'keyNameInput'],
        ]) {
            await page.evaluate(kind => window.openConnectionAssetManager(kind), kind);
            const view = page.locator('#' + id);
            await expect(view.locator('.host-resource-library')).toBeVisible();
            await expect(page.locator('#' + input)).toBeHidden();
            await page.locator('#' + button).click();
            await expect(page.locator('#' + input)).toBeVisible();
            await expect(page.locator('#' + input)).toBeFocused();
            expect(await view.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
            await view.locator('.resource-editor-back').click();
            await expect(view.locator('.host-resource-library')).toBeVisible();
            await expect(page.locator('#' + button)).toBeFocused();
        }
        await page.evaluate(() => window.openConnectionAssetManager('hosts'));
        if (!await page.locator('#accountBtnHeader').isVisible()) await page.locator('#mobileMoreBtn').click();
        await page.locator('#accountBtnHeader').click();
        await page.locator('#accountSettingsBtn').click();
        await expect(page).toHaveURL(/\/settings#preferences$/);
        await expect(page.locator('.settings-preferences-surface')).toHaveCount(3);
        await expect(page.locator('.admin-navigation')).toBeVisible();
    });
}

test('exposes modal close controls as focusable locally hosted icon buttons', async ({ page }) => {
    const readSemantics = () => page.locator('.modal-header .close')
        .evaluateAll(elements => elements.map(element => ({
            tag: element.tagName,
            type: element.getAttribute('type'),
            tabIndex: element.tabIndex,
            fontFamily: getComputedStyle(element).fontFamily,
        })));
    const workspaceSemantics = await readSemantics();

    await page.goto('/admin');
    const adminSemantics = await readSemantics();
    const semantics = [...workspaceSemantics, ...adminSemantics];
    expect(semantics.length).toBeGreaterThan(0);

    for (const control of semantics) {
        expect(control.tag).toBe('BUTTON');
        expect(control.type).toBe('button');
        expect(control.tabIndex).toBeGreaterThanOrEqual(0);
        expect(control.fontFamily).toMatch(/Material Icons|WebSSH Outline/);
    }
});
