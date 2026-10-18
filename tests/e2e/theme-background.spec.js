const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
async function image(page, width = 1920, height = 1080) {
    const data = await page.evaluate(([w,h]) => {
        const c = document.createElement('canvas'); c.width = w; c.height = h;
        const ctx = c.getContext('2d'); ctx.fillStyle = '#135a7b'; ctx.fillRect(0,0,w,h);
        return c.toDataURL('image/png').split(',')[1];
    }, [width, height]);
    return {name: 'private-test.png', mimeType: 'image/png', buffer: Buffer.from(data, 'base64')};
}
async function settings(page) {
    await page.goto('/security');
    await page.locator('[data-account-section="preferences"]').click();
}
test('custom backgrounds persist per theme and account in this browser, never on login', async ({page}) => {
    await login(page);
    await settings(page);
    await page.locator('#themeBackgroundFile').setInputFiles(await image(page));
    await expect(page.locator('#themeBackgroundStatus')).toHaveText('Background saved in this browser.');
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    await expect(page.locator('#themeBackgroundPreview')).toBeVisible();
    const original = await page.locator('#settingsThemeSelect').inputValue();
    const other = original === 'paper' ? 'glass' : 'paper';
    await page.locator('#settingsThemeSelect').selectOption(other);
    await expect(page.locator('body')).not.toHaveAttribute('data-custom-background');
    await expect(page.locator('#settingsThemeSelect')).toBeEnabled();
    await page.locator('#settingsThemeSelect').selectOption(original);
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    await page.reload();
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    await page.goto('/');
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    await expect(page.locator('#overviewHosts')).toContainText('Usable key');
    await page.screenshot({path: test.info().outputPath('custom-background.png')});
    // A different authenticated namespace must not inherit this image.
    await page.evaluate(() => document.querySelector('meta[name="background-scope"]').content = 'a'.repeat(64));
    await page.addScriptTag({url: '/static/js/theme-background.js'});
    await expect(page.locator('body')).not.toHaveAttribute('data-custom-background');
    await settings(page);
    await page.locator('#themeBackgroundRemove').click();
    await expect(page.locator('#themeBackgroundStatus')).toHaveText('Default theme background restored.');
    await expect(page.locator('body')).not.toHaveAttribute('data-custom-background');
    const logout = await page.request.post('/logout', {headers: {'X-CSRFToken': await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    expect(logout.ok()).toBe(true);
    await page.goto('/login');
    await expect(page.locator('meta[name="background-scope"]')).toHaveCount(0);
    await expect(page.locator('body')).not.toHaveAttribute('data-custom-background');
    await assertNoExternalRequests(page);
});
test('invalid, executable, animated and oversize images do not replace a saved background', async ({page}) => {
    await login(page); await settings(page);
    await page.locator('#themeBackgroundFile').setInputFiles(await image(page));
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    const saved = await page.locator('#themeBackgroundPreview').getAttribute('src');
    const invalid = [
        await image(page, 640, 480),
        {name:'fake.png', mimeType:'image/png', buffer:Buffer.from('<svg onload="alert(1)"/>')},
        {name:'large.jpg', mimeType:'image/jpeg', buffer:Buffer.alloc(5*1024*1024+1)},
    ];
    for (const file of invalid) {
        await page.locator('#themeBackgroundFile').setInputFiles(file);
        await expect(page.locator('#themeBackgroundStatus')).toHaveClass(/text-danger/);
        await expect(page.locator('#themeBackgroundPreview')).toHaveAttribute('src', saved);
    }
    await assertNoExternalRequests(page);
});

test('a storage failure keeps the previous wallpaper and reports the failed save', async ({page}) => {
    await login(page); await settings(page);
    await page.locator('#themeBackgroundFile').setInputFiles(await image(page));
    await expect(page.locator('body')).toHaveAttribute('data-custom-background', '');
    const saved = await page.locator('#themeBackgroundPreview').getAttribute('src');
    await page.evaluate(() => {
        IDBObjectStore.prototype.put = () => { throw new DOMException('Quota exceeded', 'QuotaExceededError'); };
    });
    await page.locator('#themeBackgroundFile').setInputFiles(await image(page));
    await expect(page.locator('#themeBackgroundStatus')).toHaveText('Browser storage is unavailable or full. The image could not be saved.');
    await expect(page.locator('#themeBackgroundPreview')).toHaveAttribute('src', saved);
});
