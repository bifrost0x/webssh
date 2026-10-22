const { test, expect } = require('playwright/test');
const fs = require('node:fs/promises');
const { login, assertNoExternalRequests } = require('./helpers');

test.beforeEach(async ({ page }) => {
    await login(page);
    await page.evaluate(() => {
        const source = { sourceId: 'sftp-session:review-fixture', endpoint: 'review@example.test:22' };
        window.getSFTPFileManager().buildSourceCatalog = () => [{ items: [source] }];
        window.__reviewSaves = [];
        const emit = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ...args) => {
            if (event === 'preview_file') {
                queueMicrotask(() => window.FilePreview.handlePreviewData({
                    ...data, filename: 'review.txt', content: 'café\nold\n', size: 10,
                }));
                return window.socket;
            }
            if (event === 'open_file_for_edit') {
                queueMicrotask(() => window.FilePreview.handleEditData({
                    ...data, content: 'café\nold\n', revision: 'original-revision',
                    encoding: 'latin-1', newline: 'crlf', original_bytes: 'Y2Fm6Q0Kb2xkCg==',
                }));
                return window.socket;
            }
            if (event === 'save_file') {
                window.__reviewSaves.push(structuredClone(data));
                return window.socket;
            }
            return emit(event, data, ...args);
        };
        window.FilePreview.open(source.sourceId, '/etc/review.txt', 'review.txt');
    });
    await page.locator('#previewEditBtn').click();
    await expect(page.locator('#editorContent')).toHaveValue('café\nold\n');
});

test.afterEach(async ({ page }) => {
    await assertNoExternalRequests(page);
});

test('reviews target and both versions, downloads exact original and saves deliberately', async ({ page }) => {
    await page.locator('#editorContent').fill('café\nnew\n');
    await page.locator('#editorSaveBtn').click();
    await expect(page.locator('#editorReviewTarget')).toHaveText('review@example.test:22\n/etc/review.txt');
    await expect(page.locator('#editorReviewDiff')).toContainText('-old');
    await expect(page.locator('#editorReviewDiff')).toContainText('+new');
    await page.locator('.editor-review-versions summary').click();
    await expect(page.locator('#editorReviewOriginal')).toHaveValue('café\nold\n');
    await expect(page.locator('#editorReviewEdited')).toHaveValue('café\nnew\n');
    expect(await page.evaluate(() => window.__reviewSaves.length)).toBe(0);

    const downloadEvent = page.waitForEvent('download');
    await page.locator('#editorBackupBtn').click();
    const download = await downloadEvent;
    expect(download.suggestedFilename()).toBe('review.txt.original');
    expect(await fs.readFile(await download.path())).toEqual(Buffer.from([99, 97, 102, 233, 13, 10, 111, 108, 100, 10]));

    await page.locator('#editorCommitBtn').click();
    const saved = await page.evaluate(() => window.__reviewSaves);
    expect(saved).toHaveLength(1);
    expect(saved[0]).toMatchObject({ source_id: 'sftp-session:review-fixture', path: '/etc/review.txt', content: 'café\nnew\n', expected_revision: 'original-revision', encoding: 'latin-1', newline: 'crlf' });
    await expect(page.locator('#fileEditor')).toBeVisible();
    await expect(page.locator('#editorStatus')).toHaveText('Saving...');
    await page.evaluate(() => window.FilePreview.handleFileSaved({ ...window.__reviewSaves[0], revision: 'saved-revision' }));
    await expect(page.locator('#fileEditor')).toBeHidden();
});

test('failed save keeps draft and review, then SMB consent retries only the reviewed text', async ({ page }) => {
    await page.locator('#editorContent').fill('changed');
    await page.locator('#editorSaveBtn').click();
    await page.locator('#editorCommitBtn').click();
    await page.evaluate(() => window.FilePreview.handleSocketError({ ...window.__reviewSaves[0], operation: 'save_file', code: 'EDIT_CONFLICT' }));
    await expect(page.locator('#editorReview')).toBeVisible();
    await expect(page.locator('#editorReviewEdited')).toHaveValue('changed');
    await expect(page.locator('#editorStatus')).toContainText('changed on the server');
    await page.locator('#editorBackBtn').click();
    await expect(page.locator('#editorContent')).toHaveValue('changed');
    await page.locator('#editorContent').fill('reviewed again');
    await page.locator('#editorSaveBtn').click();
    await page.locator('#editorCommitBtn').click();
    page.once('dialog', dialog => dialog.accept());
    await page.evaluate(() => window.FilePreview.handleSocketError({ ...window.__reviewSaves[1], operation: 'save_file', code: 'SMB_RECOVERABLE_REPLACE_REQUIRED', save_challenge: 'review-challenge' }));
    expect(await page.evaluate(() => window.__reviewSaves.at(-1))).toMatchObject({ content: 'reviewed again', replace_strategy: 'recoverable_swap', save_challenge: 'review-challenge', expected_revision: 'original-revision' });
    expect(await page.evaluate(() => window.__reviewSaves.length)).toBe(3);
});

test('switching file source requires draft confirmation and invalidates a prior review', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#editorContent').fill('keep this draft');
    await page.locator('#editorSaveBtn').click();
    page.once('dialog', dialog => dialog.dismiss());
    await page.evaluate(() => window.FilePreview.open('smb-quick:other', '/other', 'other.txt'));
    await expect(page.locator('#editorReviewEdited')).toHaveValue('keep this draft');
    await expect(page.locator('#editorReviewTarget')).toContainText('review@example.test:22');
    page.once('dialog', dialog => dialog.accept());
    await page.evaluate(() => window.FilePreview.open('smb-quick:other', '/other', 'other.txt'));
    await expect(page.locator('#editorReview')).toBeHidden();
    await page.evaluate(() => window.FilePreview.commitReviewedEdit());
    expect(await page.evaluate(() => window.__reviewSaves.length)).toBe(0);
});

for (const width of [390, 1536]) {
    test(`review confirmation separates literal colored changes and final actions at ${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 960 });
        await page.locator('#editorContent').fill('café\n<img src=x onerror="window.__reviewInjected=true">\n');
        await page.locator('#editorSaveBtn').click();
        await expect(page.locator('#editorSaveBtn')).toBeHidden();
        await expect(page.locator('#editorReview .editor-review-heading')).toBeVisible();
        await expect(page.locator('#editorReviewDiff .editor-diff-removed')).toContainText('-old');
        await expect(page.locator('#editorReviewDiff .editor-diff-added')).toContainText('+<img');
        await expect(page.locator('#editorReviewDiff .editor-diff-removed')).toHaveAttribute('data-old-line', '2');
        await expect(page.locator('#editorReviewDiff .editor-diff-added')).toHaveAttribute('data-new-line', '2');
        expect(await page.locator('#editorReviewDiff img').count()).toBe(0);
        expect(await page.evaluate(() => window.__reviewInjected)).toBeUndefined();
        expect(await page.locator('#editorReview').evaluate(el => el.getBoundingClientRect().right <= innerWidth)).toBe(true);
        await expect(page.locator('#editorCommitBtn')).toBeVisible();
        await page.screenshot({ path: test.info().outputPath('review-confirmation.png') });
        await page.locator('#editorBackBtn').click();
        await expect(page.locator('#editorSaveBtn')).toBeVisible();
        expect(await page.evaluate(() => window.__reviewSaves.length)).toBe(0);
    });
}

test('unknown save retains the draft and exposes recovery actions immediately', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 960 });
    await page.locator('#editorContent').fill('keep this recovery draft');
    await page.locator('#editorSaveBtn').click();
    await page.locator('#editorCommitBtn').click();
    await page.evaluate(() => window.FilePreview.interruptSave());
    await expect(page.locator('#editorReview')).toBeHidden();
    await expect(page.locator('#editorContent')).toHaveValue('keep this recovery draft');
    await expect(page.locator('#editorDraftBtn')).toBeVisible();
    await expect(page.locator('#editorReloadBtn')).toBeVisible();
    await expect(page.locator('#editorCommitBtn')).toBeDisabled();
    const downloading = page.waitForEvent('download');
    await page.locator('#editorDraftBtn').click();
    expect(await fs.readFile(await (await downloading).path(), 'utf8')).toBe('keep this recovery draft');
    expect(await page.evaluate(() => window.__reviewSaves.length)).toBe(1);
});
