const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('group work hides welcome distractions and reports the filtered inventory', async ({page}) => {
    await page.setViewportSize({width: 1600, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#overviewCustomize').click();
    await page.locator('[data-module=news] input[type=checkbox]').check();
    await page.locator('#overviewCustomize').click();
    await expect(page.locator('.overview-news-card')).toBeVisible();
    await page.locator('#overviewGroupFilter').selectOption('group:Operations');
    await expect(page.locator('.overview-news-card')).toBeHidden();
    await expect(page.locator('.overview-heading')).toBeHidden();
    await expect(page.locator('.overview-session-strip')).toBeHidden();
    await expect(page.locator('.overview-compact-row')).toHaveCount(2);
    await expect(page.locator('.overview-list-group h3')).toHaveText('Operations2');
    await expect(page.locator('#overviewCreateHost')).toBeVisible();
    await page.locator('#overviewHostSearch').fill('Ops');
    await page.locator('#fileTransferBtn').click();
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#overviewHostsTitle')).toBeFocused();
    await expect(page.locator('.overview-news-card')).toBeHidden();
    await page.locator('#overviewHostSearch').fill('');
    await expect(page.locator('.overview-news-card')).toBeHidden();
    await expect(page.locator('#overviewGroupFilter')).toHaveValue('group:Operations');
    await page.locator('#overviewGroupFilter').selectOption('');
    await expect(page.locator('.overview-news-card')).toBeVisible();
    await expect(page.locator('.overview-heading')).toBeVisible();
    await page.locator('#overviewHostSearch').fill('Ops');
    await expect(page.locator('.overview-news-card')).toBeHidden();
    await page.locator('#overviewHostSearch').fill('');
    await expect(page.locator('.overview-news-card')).toBeVisible();
});

test('explicit overview reset clears search while returning from another view preserves it', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.locator('#overviewGroupFilter').selectOption('group:Operations');
    await page.locator('#overviewHostSearch').fill('Ops');
    await page.locator('#fileTransferBtn').click();
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#overviewHostSearch')).toHaveValue('Ops');
    await expect(page.locator('#overviewGroupFilter')).toHaveValue('group:Operations');
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#overviewHostSearch')).toHaveValue('');
    await expect(page.locator('#overviewGroupFilter')).toHaveValue('');
    await expect(page.locator('.overview-heading')).toBeVisible();
    await page.setViewportSize({width:360,height:529});
    await page.screenshot({path:testInfo.outputPath('overview-short.png'),animations:'disabled'});
});

test('ultrawide header keeps navigation and connection within a readable working span', async ({page}) => {
    await page.setViewportSize({width: 3440, height: 1440});
    await login(page, 'e2e_admin', {workspace: false});
    const nav = await page.locator('#globalNavigation').boundingBox();
    const connect = await page.locator('#shellConnectBtn').boundingBox();
    expect(nav.x).toBeGreaterThan(400);
    expect(connect.x + connect.width - nav.x).toBeLessThan(1800);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('empty files offer one source entry per pane and help is clearly informational', async ({page}) => {
    await login(page);
    await page.locator('#fileTransferBtn').click();
    await expect(page.locator('#fmLeftList .fm-empty-source-cta')).toBeVisible();
    await expect(page.locator('#fmLeftPane [data-source-target]')).toBeHidden();
    await expect(page.locator('.fm-permissions-help summary')).toContainText('Permissions help');
    await page.locator('#fmLayoutSplit').click();
    await expect(page.locator('#fmRightList .fm-empty-source-cta')).toBeVisible();
    await expect(page.locator('#fmRightPane [data-source-target]')).toBeHidden();
});

test('transfer states remain visible in a collapsed queue and expose progress accessibly', async ({page}) => {
    await login(page);
    await page.locator('#fileTransferBtn').click();
    await page.evaluate(() => {
        sftpFileManager.transferQueue = [
            {id: 'review-active', type: 'upload', filename: 'archive.tar', status: 'active', progress: 42},
            {id: 'review-error', type: 'upload', filename: 'notes.txt', status: 'error', error: 'Permission denied.', progress: 0},
        ];
        sftpFileManager.renderTransferQueue();
    });
    await expect(page.locator('#fmQueueHeader')).toContainText('1 active');
    await expect(page.locator('#fmQueueHeader')).toContainText('1 failed');
    await expect(page.locator('#fmQueueBadge')).toHaveText('2');
    await expect(page.locator('#fmQueue')).toHaveClass(/collapsed/);
    await page.locator('#fmQueueHeader').click();
    await expect(page.getByRole('progressbar', {name: 'archive.tar'})).toHaveAttribute('aria-valuenow', '42');
    await expect(page.locator('#fmQueueList')).toContainText('Permission denied.');
    await page.locator('#workspaceNavBtn').click();
    await expect(page.locator('#workspaceStatusTransfers')).toContainText('1 failed');
});
