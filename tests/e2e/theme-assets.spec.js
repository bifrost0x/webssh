const {test, expect} = require('playwright/test');
const {assertNoExternalRequests} = require('./helpers');

const themes = ['glass', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];

test('every theme background decodes at the original resolution', async ({page}) => {
    assertNoExternalRequests(page);
    await page.goto('/login');
    for (const theme of themes) {
        const dimensions = await page.evaluate(async value => {
            document.body.dataset.theme = value;
            const source = getComputedStyle(document.body, '::before').backgroundImage;
            const url = source.match(/url\(["']?([^"')]+)["']?\)/)[1];
            const image = new Image();
            image.src = url;
            await image.decode();
            return [image.naturalWidth, image.naturalHeight];
        }, theme);
        expect(dimensions, theme).toEqual([1672, 941]);
    }
});

test('login remains usable when storage and the background are unavailable', async ({page}) => {
    assertNoExternalRequests(page);
    await page.addInitScript(() => {
        Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Blocked', 'SecurityError'); }});
    });
    await page.route('**/theme-backgrounds/**', route => route.abort());
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('/login');
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'glass');
    await page.locator('input[name="username"]').fill('fallback-works');
    await expect(page.locator('input[name="username"]')).toHaveValue('fallback-works');
    expect(errors).toEqual([]);
});
