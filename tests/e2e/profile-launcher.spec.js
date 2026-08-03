const { test, expect } = require('playwright/test');
const {
    assertNoExternalRequests,
    installKeyUploadTrap,
    installSshConnectTrap,
    keyUploadAttempts,
    launchProfile,
    login,
    openKeyManagement,
    openProfileManagement,
    observeConnectionModal,
    sshAttempts,
} = require('./helpers');

async function expectReviewDialogState(page, expected) {
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#hostInput')).toHaveValue(expected.host);
    await expect(page.locator('#portInput')).toHaveValue(expected.port);
    await expect(page.locator('#usernameInput')).toHaveValue(expected.username);
    await expect(page.locator('#authTypeSelect')).toHaveValue(expected.authType);
}

test.beforeEach(async ({ page }) => {
    await login(page);
    await installSshConnectTrap(page);
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('creates, edits, and deletes a profile through the management UI', async ({ page }) => {
    await openProfileManagement(page);
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorName').fill('Browser CRUD');
    await page.locator('#profileEditorHost').fill('crud.local');
    await page.locator('#profileEditorPort').fill('2222');
    await page.locator('#profileEditorUsername').fill('tester');
    await page.locator('#profileEditorForm button[type="submit"]').click();

    const created = page.locator('.profile-management-item').filter({ hasText: 'Browser CRUD' });
    await expect(created).toContainText('tester@crud.local:2222');
    await created.locator('[data-profile-action="edit"]').click();
    await page.locator('#profileEditorName').fill('Browser CRUD edited');
    await page.locator('#profileEditorHost').fill('edited.local');
    await page.locator('#profileEditorForm button[type="submit"]').click();

    const edited = page.locator('.profile-management-item').filter({
        hasText: 'Browser CRUD edited',
    });
    await expect(edited).toContainText('tester@edited.local:2222');
    page.once('dialog', dialog => dialog.accept());
    await edited.locator('[data-profile-action="delete"]').click();
    await expect(edited).toHaveCount(0);
});

test('only auto-connects profiles whose credentials and references are currently safe', async ({ page }) => {
    for (const name of [
        'Password review',
        'Usable key',
        'Missing key',
        'Missing jump host',
        'Authorized Tailscale',
    ]) {
        await expect(page.locator('.profile-launcher-name', { hasText: name })).toHaveCount(1);
    }

    await launchProfile(page, 'Password review');
    await expectReviewDialogState(page, {
        host: 'password.local',
        port: '22',
        username: 'passworduser',
        authType: 'password',
    });
    await expect(page.locator('#passwordInput')).toBeFocused();
    await expect.poll(() => sshAttempts(page)).toHaveLength(0);
    await page.locator('#cancelConnectionBtn').click();

    await observeConnectionModal(page);
    await launchProfile(page, 'Usable key');
    await expect.poll(() => sshAttempts(page)).toHaveLength(1);
    await expect.poll(() => page.evaluate(
        () => window.__connectionModalShows,
    )).toBe(0);
    expect((await sshAttempts(page))[0].payload).toMatchObject({
        host: 'key.local',
        username: 'keyuser',
        auth_type: 'key',
    });

    await expect(page.locator(
        '.profile-launcher-card[data-profile-id="missing-key"] .profile-launcher-action',
    )).toHaveClass(/mode-review/);
    await launchProfile(page, 'Missing key');
    await expectReviewDialogState(page, {
        host: 'missing-key.local',
        port: '22',
        username: 'keyuser',
        authType: 'key',
    });
    await expect(page.locator('#keyGroup')).not.toHaveClass(/hidden/);
    await expect(page.locator('#keySelect')).toHaveValue('');
    await expect(page.locator('#keySelect option[value="missing-key"]')).toHaveCount(0);
    await expect(page.locator('#connectBtn')).toBeFocused();
    await expect.poll(() => sshAttempts(page)).toHaveLength(1);
    await page.locator('#cancelConnectionBtn').click();

    await expect(page.locator(
        '.profile-launcher-card[data-profile-id="missing-jump-host"] .profile-launcher-action',
    )).toHaveClass(/mode-review/);
    await launchProfile(page, 'Missing jump host');
    await expectReviewDialogState(page, {
        host: 'missing-jump.local',
        port: '22',
        username: 'keyuser',
        authType: 'key',
    });
    await expect(page.locator('#keySelect option:checked')).toContainText('E2E usable key');
    await expect(page.locator('#jumpHostSelect')).toHaveValue('');
    await expect(page.locator(
        '#jumpHostSelect option[value="missing-jump-host"]',
    )).toHaveCount(0);
    await expect(page.locator('#connectBtn')).toBeFocused();
    await expect.poll(() => sshAttempts(page)).toHaveLength(1);
    await page.locator('#cancelConnectionBtn').click();

    await page.evaluate(() => {
        window.__connectionModalShows = 0;
    });
    await launchProfile(page, 'Authorized Tailscale');
    await expect.poll(() => sshAttempts(page)).toHaveLength(2);
    await expect.poll(() => page.evaluate(
        () => window.__connectionModalShows,
    )).toBe(0);
    expect((await sshAttempts(page))[1].payload).toMatchObject({
        host: 'tail-node',
        username: 'root',
        auth_type: 'tailscale',
    });
});

test('an unauthorized Tailscale profile opens for review without an SSH attempt', async ({ page }) => {
    await page.context().clearCookies();
    await login(page, 'e2e_user');
    await installSshConnectTrap(page);

    await expect(page.locator(
        '.profile-launcher-card[data-profile-id="unauthorized-tailscale"] '
        + '.profile-launcher-action',
    )).toHaveClass(/mode-review/);
    await launchProfile(page, 'Unauthorized Tailscale');
    await expectReviewDialogState(page, {
        host: 'tail-node',
        port: '22',
        username: 'root',
        authType: '',
    });
    await expect.poll(() => sshAttempts(page)).toHaveLength(0);
    await expect(page.locator('#authTypeSelect option[value="tailscale"]')).toHaveCount(0);
    await expect(page.locator('#passwordGroup')).toHaveClass(/hidden/);
    await expect(page.locator('#keyGroup')).toHaveClass(/hidden/);
    await expect(page.locator('#connectBtn')).toBeFocused();
});

test('key jump hosts and management actions launch directly without Quick Connect', async ({ page }) => {
    await observeConnectionModal(page);
    await launchProfile(page, 'Key jump host');
    await expect.poll(() => sshAttempts(page)).toHaveLength(1);
    await expect.poll(() => page.evaluate(() => window.__connectionModalShows)).toBe(0);
    expect((await sshAttempts(page))[0].payload).toMatchObject({
        host: 'jump-target.local',
        auth_type: 'key',
        proxy_jump: {
            host: 'jump.local',
            username: 'jumpuser',
            auth_type: 'key',
        },
    });

    await expect(page.locator('.profile-launcher-name', { hasText: 'Usable key' })).toBeVisible();
    await openProfileManagement(page);
    const usable = page.locator('.profile-management-item').filter({ hasText: 'Usable key' });
    await usable.locator('[data-profile-action="connect"]').click();
    await expect.poll(() => sshAttempts(page)).toHaveLength(2);
    await expect(page.locator('#profileManagementModal')).not.toHaveClass(/show/);
    await expect.poll(() => page.evaluate(() => window.__connectionModalShows)).toBe(0);
    await expect(page.locator('.notification-error').last()).toContainText(
        'E2E intercepted local SSH connect',
    );
    await expect(page.locator('.profile-launcher-name', { hasText: 'Usable key' })).toBeVisible();
});

test('inline key upload preserves the saved connection draft and focuses the new key', async ({ page }) => {
    await installKeyUploadTrap(page);
    await openProfileManagement(page);
    const usable = page.locator('.profile-management-item').filter({ hasText: 'Usable key' });
    await usable.locator('[data-profile-action="edit"]').click();
    await page.locator('#profileEditorName').fill('Unsaved browser draft');
    await page.locator('#profileEditorHost').fill('draft.local');
    await page.locator('#profileEditorPort').fill('2202');
    await page.locator('#profileEditorUsername').fill('draftuser');
    await page.locator('#profileEditorAddKeyBtn').click();
    await page.locator('#profileEditorNewKeyName').fill('Inline browser key');
    await page.locator('#profileEditorNewKeyContent').fill('E2E private key text never sent');
    await page.locator('#profileEditorUploadKeyBtn').click();

    await expect.poll(() => keyUploadAttempts(page)).toHaveLength(1);
    expect((await keyUploadAttempts(page))[0]).toEqual({
        name: 'Inline browser key',
        key_content: 'E2E private key text never sent',
    });
    await expect(page.locator('#profileEditorName')).toHaveValue('Unsaved browser draft');
    await expect(page.locator('#profileEditorHost')).toHaveValue('draft.local');
    await expect(page.locator('#profileEditorPort')).toHaveValue('2202');
    await expect(page.locator('#profileEditorUsername')).toHaveValue('draftuser');
    await expect(page.locator('#profileEditorKeySelect')).toHaveValue('e2e-inline-key');
    await expect(page.locator('#profileEditorKeySelect')).toBeFocused();
    await expect(page.locator('#profileEditorNewKeyName')).toHaveValue('');
    await expect(page.locator('#profileEditorNewKeyContent')).toHaveValue('');
    await expect(page.locator('#profileEditorAddKeyPanel')).toHaveClass(/hidden/);
});

test('SSH key rename supports click, Enter, cancel, and Escape', async ({ page }) => {
    await openKeyManagement(page);
    const keyList = page.locator('#keysList');
    let keyItem = keyList.locator('.key-item').filter({ hasText: 'E2E usable key' });
    await expect(keyItem).toHaveCount(1);
    const keyId = await keyItem.locator('[data-key-id]').first().getAttribute('data-key-id');
    const stableKeyItem = () => keyList.locator('.key-item').filter({
        has: page.locator(`[data-key-id="${keyId}"]`),
    });

    await keyItem.locator('[data-key-action="rename"]').click();
    keyItem = stableKeyItem();
    await keyItem.locator('.key-rename-input').fill('Cancelled rename');
    await keyItem.locator('[data-key-action="cancel-rename"]').click();
    await expect(keyList).toContainText('E2E usable key');
    await expect(keyList).not.toContainText('Cancelled rename');

    keyItem = stableKeyItem();
    await keyItem.locator('[data-key-action="rename"]').click();
    await keyItem.locator('.key-rename-input').fill('Escaped rename');
    await page.keyboard.press('Escape');
    await expect(keyList).toContainText('E2E usable key');
    await expect(keyList).not.toContainText('Escaped rename');

    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__keyRenameOriginalEmit = originalEmit;
        window.socket.emit = function wrappedEmit(event, ...args) {
            if (event !== 'rename_key') return originalEmit(event, ...args);
            const acknowledgement = typeof args.at(-1) === 'function'
                ? args.at(-1)
                : null;
            queueMicrotask(() => acknowledgement?.({
                success: false,
                error: 'E2E intercepted key rename',
            }));
            return window.socket;
        };
    });
    keyItem = stableKeyItem();
    await keyItem.locator('[data-key-action="rename"]').click();
    await keyItem.locator('.key-rename-input').fill('Preserved failed rename');
    await keyItem.locator('[data-key-action="save-rename"]').click();
    await expect(keyItem.locator('.key-rename-input')).toHaveValue(
        'Preserved failed rename',
    );
    await expect(keyItem.locator('.key-rename-input')).toBeFocused();
    await expect(keyItem.locator('[data-key-action="save-rename"]')).toBeEnabled();
    await page.evaluate(() => {
        window.socket.emit = window.__keyRenameOriginalEmit;
        delete window.__keyRenameOriginalEmit;
    });
    await keyItem.locator('[data-key-action="cancel-rename"]').click();

    keyItem = stableKeyItem();
    await keyItem.locator('[data-key-action="rename"]').click();
    await keyItem.locator('.key-rename-input').fill('Renamed E2E key');
    await page.keyboard.press('Enter');
    await expect(keyList).toContainText('Renamed E2E key');

    keyItem = stableKeyItem();
    await keyItem.locator('[data-key-action="rename"]').click();
    await keyItem.locator('.key-rename-input').fill('E2E usable key');
    await keyItem.locator('[data-key-action="save-rename"]').click();
    await expect(keyList).toContainText('E2E usable key');
});

test('referenced commands and command sets cannot be deleted', async ({ page }) => {
    await page.locator('#commandLibraryBtn').click();
    await expect(page.locator('#commandWorkspaceModal')).toHaveClass(/show/);

    const guardedSet = page.locator('.command-set-management-item').filter({
        hasText: 'Guarded profile set',
    });
    await expect(guardedSet).toHaveCount(1);
    page.once('dialog', dialog => dialog.accept());
    await guardedSet.locator('[data-command-set-action="delete"]').click();
    await expect(page.locator('.notification-error').last()).toContainText(
        'Command set is used by 1 profile',
    );
    await expect(guardedSet).toHaveCount(1);

    await page.locator('#commandLibraryTab').click();
    await page.locator('#commandSearchInput').fill('Guarded direct command');
    const guardedCommand = page.locator('.command-row').filter({
        hasText: 'Guarded direct command',
    });
    await expect(guardedCommand).toHaveCount(1);
    page.once('dialog', dialog => dialog.accept());
    await guardedCommand.locator('.cmd-delete').click();
    await expect(page.locator('.notification-error').last()).toContainText(
        'Command is used by 1 profile',
    );
    await expect(guardedCommand).toHaveCount(1);
});

test('modals restore focus and close by Escape or overlay while containing scroll', async ({ page }) => {
    const trigger = page.locator('#manageProfilesBtn');
    await trigger.focus();
    await trigger.click();
    const modal = page.locator('#profileManagementModal');
    await expect(modal).toHaveClass(/show/);
    await expect(page.locator('#newProfileBtn')).toBeFocused();

    const scrollState = await modal.evaluate(element => {
        const content = element.querySelector('.modal-content');
        const body = element.querySelector('.modal-body');
        body.scrollTop = body.scrollHeight;
        const header = element.querySelector('.modal-header');
        return {
            contentOverflow: getComputedStyle(content).overflow,
            bodyOverflowY: getComputedStyle(body).overflowY,
            scrolls: body.scrollHeight > body.clientHeight,
            headerTop: header.getBoundingClientRect().top,
            contentTop: content.getBoundingClientRect().top,
        };
    });
    expect(scrollState).toMatchObject({
        contentOverflow: 'hidden',
        bodyOverflowY: 'auto',
        scrolls: true,
    });
    expect(scrollState.headerTop).toBeGreaterThanOrEqual(scrollState.contentTop);

    await page.keyboard.press('Escape');
    await expect(modal).not.toHaveClass(/show/);
    await expect(trigger).toBeFocused();

    await trigger.click();
    await modal.click({ position: { x: 4, y: 4 } });
    await expect(modal).not.toHaveClass(/show/);
    await expect(trigger).toBeFocused();
});

test('the profile launcher remains contained and readable at 375px', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    const card = page.locator('.profile-launcher-card').filter({
        has: page.locator('.profile-launcher-name', { hasText: 'Post command custom' }),
    });
    await expect(card).toBeVisible();

    const layout = await card.evaluate(element => {
        const name = element.querySelector('.profile-launcher-name').getBoundingClientRect();
        const endpoint = element.querySelector('.profile-launcher-endpoint').getBoundingClientRect();
        const action = element.querySelector('.profile-launcher-action').getBoundingClientRect();
        const bounds = element.getBoundingClientRect();
        return {
            documentWidth: document.documentElement.scrollWidth,
            viewportWidth: window.innerWidth,
            gridTemplateColumns: getComputedStyle(element).gridTemplateColumns,
            nameContained: name.left >= bounds.left && name.right <= bounds.right,
            endpointContained: endpoint.left >= bounds.left && endpoint.right <= bounds.right,
            actionBelowEndpoint: action.top >= endpoint.bottom,
        };
    });
    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.gridTemplateColumns.split(' ')).toHaveLength(1);
    expect(layout.nameContained).toBe(true);
    expect(layout.endpointContained).toBe(true);
    expect(layout.actionBelowEndpoint).toBe(true);
});

test('inline key upload and rename actions stay touchable at 375px', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await openProfileManagement(page);
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorAuthType').selectOption('key');
    await page.locator('#profileEditorAddKeyBtn').click();

    const inlineLayout = await page.locator('#profileEditorAddKeyPanel').evaluate(panel => {
        const panelBounds = panel.getBoundingClientRect();
        const modalBounds = panel.closest('.modal-content').getBoundingClientRect();
        const actions = [...panel.querySelectorAll('.profile-inline-key-actions .btn')];
        return {
            contained: panelBounds.left >= modalBounds.left
                && panelBounds.right <= modalBounds.right,
            actionHeights: actions.map(action => action.getBoundingClientRect().height),
            documentWidth: document.documentElement.scrollWidth,
            viewportWidth: window.innerWidth,
        };
    });
    expect(inlineLayout.contained).toBe(true);
    expect(inlineLayout.actionHeights.every(height => height >= 44)).toBe(true);
    expect(inlineLayout.documentWidth).toBeLessThanOrEqual(inlineLayout.viewportWidth);

    await page.locator('#closeProfileManagementModal').click();
    await openKeyManagement(page);
    let keyItem = page.locator('#keysList .key-item').filter({ hasText: 'E2E usable key' });
    const keyId = await keyItem.locator('[data-key-id]').first().getAttribute('data-key-id');
    await keyItem.locator('[data-key-action="rename"]').click();
    keyItem = page.locator('#keysList .key-item').filter({
        has: page.locator(`[data-key-id="${keyId}"]`),
    });
    const renameLayout = await keyItem.evaluate(item => {
        const bounds = item.getBoundingClientRect();
        const actions = [...item.querySelectorAll('.key-item-actions .btn')];
        return {
            contained: actions.every(action => {
                const actionBounds = action.getBoundingClientRect();
                return actionBounds.left >= bounds.left && actionBounds.right <= bounds.right;
            }),
            actionHeights: actions.map(action => action.getBoundingClientRect().height),
        };
    });
    expect(renameLayout.contained).toBe(true);
    expect(renameLayout.actionHeights.every(height => height >= 44)).toBe(true);
});
