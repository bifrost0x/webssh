const { test, expect } = require('playwright/test');
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

test('keeps saved-connection actions visible while its form scrolls', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 700 });
    await openProfileManagement(page);
    await page.locator('#newProfileBtn').click();
    await page.locator('#profileEditorAuthType').selectOption('key');
    await page.locator('#profileEditorAddKeyBtn').click();
    await page.locator('#profileEditorPostConnectMode').selectOption('free_text');

    await expect(page.locator('#profileConnectionDetailsCard')).toBeVisible();
    await expect(page.locator('#profileAdvancedSettingsCard')).toBeVisible();
    await expect(page.locator('#cancelProfileEditorBtn')).toBeVisible();
    await expect(page.locator('#profileEditorForm button[type="submit"]')).toBeVisible();

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

test('uses paired cards for jump hosts and SSH keys plus full-page settings', async ({ page }) => {
    await page.setViewportSize({ width: 1180, height: 760 });
    await openProfileManagement(page);
    await page.locator('#profileManagementModal [data-connection-asset="jump-hosts"]').click();

    const jumpHostCards = page.locator('#jumpHostManagementModal .manager-card');
    await expect(jumpHostCards).toHaveCount(2);
    const jumpGeometry = await jumpHostCards.evaluateAll(cards => cards.map(card => (
        card.getBoundingClientRect()
    )));
    expect(jumpGeometry[0].right).toBeLessThanOrEqual(jumpGeometry[1].left);

    await page.locator('#jumpHostManagementModal [data-connection-asset="keys"]').click();
    const keyCards = page.locator('#keyManagementModal .manager-card');
    await expect(keyCards).toHaveCount(2);
    const keyGeometry = await keyCards.evaluateAll(cards => cards.map(card => (
        card.getBoundingClientRect()
    )));
    expect(keyGeometry[0].right).toBeLessThanOrEqual(keyGeometry[1].left);

    await page.locator('#workspaceNavBtn').click();
    await page.locator('#accountBtnHeader').click();
    await page.locator('#accountSettingsBtn').click();
    await expect(page).toHaveURL(/\/settings#preferences$/);
    await expect(page.locator('.settings-preferences-surface')).toHaveCount(2);
    await expect(page.locator('.admin-navigation')).toBeVisible();
});

test('stacks asset manager cards without horizontal overflow on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openKeyManagement(page);

    const geometry = await page.locator('#keyManagementModal').evaluate(modal => {
        const cards = [...modal.querySelectorAll('.manager-card')]
            .map(card => card.getBoundingClientRect());
        return {
            firstBottom: cards[0].bottom,
            secondTop: cards[1].top,
            scrollWidth: modal.querySelector('.modal-body').scrollWidth,
            clientWidth: modal.querySelector('.modal-body').clientWidth,
        };
    });
    expect(geometry.firstBottom).toBeLessThanOrEqual(geometry.secondTop);
    expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.clientWidth);
});

test('exposes every modal close control as a keyboard-focusable button', async ({ page }) => {
    const readSemantics = () => page.locator('.modal-header .close')
        .evaluateAll(elements => elements.map(element => ({
            tag: element.tagName,
            type: element.getAttribute('type'),
            tabIndex: element.tabIndex,
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
    }
});

test('renders modal close controls with the Material Icons font', async ({ page }) => {
    const fontFamilies = await page.locator('.modal-header .close.material-icons')
        .evaluateAll(elements => elements.map(
            element => getComputedStyle(element).fontFamily,
        ));

    expect(fontFamilies.length).toBeGreaterThan(0);
    for (const fontFamily of fontFamilies) {
        expect(fontFamily).toContain('Material Icons');
    }
});
