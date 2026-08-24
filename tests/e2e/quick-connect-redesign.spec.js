const { test, expect } = require('playwright/test');
const {
    assertNoExternalRequests,
    installSshConnectTrap,
    login,
    sshAttempts,
} = require('./helpers');

test.beforeEach(async ({ page }) => {
    await login(page);
    await installSshConnectTrap(page);
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('keeps Quick Connect in the workspace without a duplicate header action', async ({ page }) => {
    await expect(page.locator('#newConnectionBtn')).toHaveCount(0);

    const newTab = page.locator('#newTabBtn');
    const centralLauncher = page.locator('.profile-launcher-new');
    await expect(newTab).toBeVisible();
    await expect(centralLauncher).toBeVisible();

    await newTab.click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.locator('#cancelConnectionBtn').click();

    await centralLauncher.click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.locator('#cancelConnectionBtn').click();

    await page.keyboard.press('Control+Shift+N');
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await page.locator('#cancelConnectionBtn').click();

    await page.keyboard.press('Control+k');
    await page.locator('#commandPaletteInput').fill('Quick Connect');
    await page.locator(
        '.palette-item[data-palette-kind="action"][data-palette-id="quick-connect"]',
    ).click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
});

test('presents a focused two-column quick connect without a saved-profile picker', async ({ page }) => {
    await page.evaluate(() => {
        for (let index = 0; index < 7; index += 1) {
            window.ConnectionHistory.addConnection(
                `recent-${index}.internal`, 2202 + index, 'operator'
            );
        }
    });
    await page.locator('#newTabBtn').click();

    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#connectionDetailsCard')).toBeVisible();
    await expect(page.locator('#recentConnectionsCard')).toBeVisible();
    await expect(page.locator('#connectionAdvancedSettings')).toBeVisible();
    await expect(page.locator('#profileSelect')).toHaveCount(0);
    await expect(page.locator('#deleteProfileBtn')).toHaveCount(0);
    await expect(page.locator('#connectionProfileContext')).toHaveClass(/hidden/);
    await expect(page.locator('.recent-connection-item').first()).toHaveRole('button');
    await expect(page.locator('.recent-connection-item')).toHaveCount(7);
    await expect(page.locator('#recentConnectionsCard')).toHaveAttribute('open', '');

    const historyViewport = await page.locator('#recentConnectionsList').evaluate(list => {
        const listRect = list.getBoundingClientRect();
        const visibleItems = [...list.querySelectorAll('.recent-connection-item')]
            .filter(item => {
                const itemRect = item.getBoundingClientRect();
                return itemRect.top >= listRect.top && itemRect.bottom <= listRect.bottom;
            });
        return {
            clientHeight: list.clientHeight,
            scrollHeight: list.scrollHeight,
            visibleItems: visibleItems.length,
        };
    });
    expect(historyViewport.visibleItems).toBe(5);
    expect(historyViewport.scrollHeight).toBeGreaterThan(historyViewport.clientHeight);

    await page.locator('#recentConnectionsCard > summary').click();
    await expect(page.locator('#recentConnectionsCard')).not.toHaveAttribute('open', '');
    await expect(page.locator('#recentConnectionsList')).not.toBeVisible();
    await page.locator('#recentConnectionsCard > summary').click();
    await expect(page.locator('#recentConnectionsList')).toBeVisible();

    const historyStorage = await page.evaluate(() => {
        const scope = document.body.dataset.connectionHistoryScope;
        return {
            key: window.ConnectionHistory.storageKey,
            legacy: localStorage.getItem('recentConnections'),
            scoped: localStorage.getItem(`recentConnections:${scope}`),
        };
    });
    expect(historyStorage.key).toMatch(/^recentConnections:[a-f0-9]{64}$/);
    expect(historyStorage.legacy).toBeNull();
    expect(historyStorage.scoped).toContain('recent-6.internal');

    const geometry = await page.locator('#connectionModal').evaluate(modal => {
        const details = modal.querySelector('#connectionDetailsCard')
            .getBoundingClientRect();
        const recent = modal.querySelector('#recentConnectionsCard')
            .getBoundingClientRect();
        return {
            detailsLeft: details.left,
            detailsRight: details.right,
            recentLeft: recent.left,
        };
    });
    expect(geometry.detailsLeft).toBeLessThan(geometry.recentLeft);
    expect(geometry.detailsRight).toBeLessThanOrEqual(geometry.recentLeft);
});

test('uses the requested connection details and advanced settings hierarchy', async ({ page }) => {
    await page.locator('#newTabBtn').click();

    const hierarchy = await page.locator('#connectionModal').evaluate(modal => {
        const detailsContent = modal.querySelector('.quick-connect-details-content');
        const authRow = modal.querySelector('.quick-connect-auth-method');
        const authLabel = authRow?.querySelector('label');
        const authSelect = authRow?.querySelector('select');
        const host = modal.querySelector('#hostInput');
        const jumpHostLabel = modal.querySelector('label[for="jumpHostSelect"]');
        const runAfterLabel = modal.querySelector('.post-connect-label');
        const previewLabel = modal.querySelector('.post-connect-preview-header');
        const style = element => element ? getComputedStyle(element) : null;
        const rect = element => element ? element.getBoundingClientRect() : null;

        return {
            detailsTitle: modal.querySelector('#connectionDetailsTitle')?.textContent.trim(),
            advancedTitle: modal.querySelector('#connectionAdvancedSettings summary strong')?.textContent.trim(),
            detailsBorder: style(detailsContent)?.borderTopWidth,
            authLabelCenter: rect(authLabel) && (rect(authLabel).top + rect(authLabel).bottom) / 2,
            authSelectCenter: rect(authSelect) && (rect(authSelect).top + rect(authSelect).bottom) / 2,
            authBottom: rect(authRow)?.bottom,
            hostTop: rect(host)?.top,
            jumpHostFontSize: style(jumpHostLabel)?.fontSize,
            runAfterFontSize: style(runAfterLabel)?.fontSize,
            runAfterWeight: Number(style(runAfterLabel)?.fontWeight),
            previewFontSize: style(previewLabel)?.fontSize,
            previewWeight: Number(style(previewLabel)?.fontWeight),
        };
    });

    expect(hierarchy.detailsTitle).toBe('Connection Details');
    expect(hierarchy.advancedTitle).toBe('Advanced Settings');
    expect(hierarchy.detailsBorder).toBe('1px');
    expect(Math.abs(hierarchy.authLabelCenter - hierarchy.authSelectCenter)).toBeLessThan(2);
    expect(hierarchy.authBottom).toBeLessThan(hierarchy.hostTop);
    expect(hierarchy.runAfterFontSize).toBe(hierarchy.jumpHostFontSize);
    expect(parseFloat(hierarchy.previewFontSize)).toBeLessThan(parseFloat(hierarchy.runAfterFontSize));
    expect(hierarchy.previewWeight).toBeLessThan(hierarchy.runAfterWeight);
});

test('keeps modal actions fixed while expanded content scrolls inside', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 700 });
    await page.evaluate(() => {
        for (let index = 0; index < 7; index += 1) {
            window.ConnectionHistory.addConnection(
                `scroll-${index}.internal`, 22, 'operator'
            );
        }
    });
    await page.locator('#newTabBtn').click();
    await page.locator('#connectionAdvancedSettings > summary').click();
    await expect(page.locator('#connectionModal .modal-content')).toHaveCSS('transform', 'none');

    const before = await page.locator('#connectionModal').evaluate(modal => {
        const content = modal.querySelector('.modal-content').getBoundingClientRect();
        const scroller = modal.querySelector('.quick-connect-scroll-region');
        const actions = modal.querySelector('.quick-connect-actions').getBoundingClientRect();
        return {
            actionsBottom: actions.bottom,
            actionsTop: actions.top,
            contentBottom: content.bottom,
            scrollerClientHeight: scroller.clientHeight,
            scrollerScrollHeight: scroller.scrollHeight,
        };
    });
    expect(before.actionsBottom).toBeLessThanOrEqual(before.contentBottom);
    expect(before.scrollerScrollHeight).toBeGreaterThan(before.scrollerClientHeight);
    await expect(page.locator('#cancelConnectionBtn')).toBeVisible();
    await expect(page.locator('#connectBtn')).toBeVisible();

    await page.locator('.quick-connect-scroll-region').evaluate(scroller => {
        scroller.scrollTop = scroller.scrollHeight;
    });
    const after = await page.locator('#connectionModal').evaluate(modal => {
        const scroller = modal.querySelector('.quick-connect-scroll-region');
        const actions = modal.querySelector('.quick-connect-actions').getBoundingClientRect();
        return {
            actionsTop: actions.top,
            scrollTop: scroller.scrollTop,
        };
    });
    expect(after.scrollTop).toBeGreaterThan(0);
    expect(after.actionsTop).toBeCloseTo(before.actionsTop, 0);
});

test('shows saved-profile context and opens advanced settings for review-only profiles', async ({ page }) => {
    await page.evaluate(() => window.launchProfileForPane('missing-jump-host', 0));

    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(page.locator('#connectionProfileContext')).not.toHaveClass(/hidden/);
    await expect(page.locator('#connectionProfileContextName')).toHaveText(
        'Missing jump host'
    );
    await expect(page.locator('#profileSelect')).toHaveCount(0);
    await expect(page.locator('#connectionAdvancedSettings')).toHaveAttribute('open', '');
    await expect(page.locator('#connectionProfileJumpResolution')).toBeVisible();

    await page.locator('#connectBtn').click();
    await expect.poll(() => sshAttempts(page)).toHaveLength(0);
    await expect(page.locator('.notification')).toContainText('Choose a jump host');

    await page.locator('#connectionProfileDirectConfirm').check();
    await page.locator('#connectBtn').click();
    await expect.poll(() => sshAttempts(page)).toHaveLength(1);
    expect((await sshAttempts(page))[0].payload).not.toHaveProperty('proxy_jump');
});

test.describe('mobile quick connect', () => {
    test.use({ viewport: { width: 375, height: 844 } });

    test('stacks cards in logical order without horizontal overflow', async ({ page }) => {
        await page.evaluate(() => {
            window.ConnectionHistory.addConnection(
                'mobile.internal', 22, 'mobile'
            );
        });
        await page.locator('#newTabBtn').click();

        const geometry = await page.locator('#connectionModal').evaluate(modal => {
            const details = modal.querySelector('#connectionDetailsCard')
                .getBoundingClientRect();
            const recent = modal.querySelector('#recentConnectionsCard')
                .getBoundingClientRect();
            const advanced = modal.querySelector('#connectionAdvancedSettings')
                .getBoundingClientRect();
            return {
                detailsBottom: details.bottom,
                recentTop: recent.top,
                recentBottom: recent.bottom,
                advancedTop: advanced.top,
                scrollWidth: document.documentElement.scrollWidth,
                viewportWidth: window.innerWidth,
            };
        });

        expect(geometry.detailsBottom).toBeLessThanOrEqual(geometry.recentTop);
        expect(geometry.recentBottom).toBeLessThanOrEqual(geometry.advancedTop);
        expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.viewportWidth);
        await expect(page.locator('#connectBtn')).toBeVisible();
    });
});
