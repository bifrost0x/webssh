const {test, expect} = require('playwright/test');
const {login, installExternalRequestGuard, assertNoExternalRequests} = require('./helpers');

const themes = ['glass', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'obsidian', 'retro', 'cyberpunk-neon', 'emerald-matrix'];

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('the shared SVG actually inherits colors, without reloading its artwork', async ({page}) => {
    installExternalRequestGuard(page);
    await page.goto('/register');
    const logo = page.locator('.auth-product-logo');
    await expect(logo).toHaveAttribute('viewBox', '0 0 128 128');
    await expect(logo.locator('use')).toHaveAttribute('href', /webssh-logo\.svg\?v=[a-f0-9]+#webssh-terminal$/);
    const before = await logo.screenshot();
    // Changing only the inherited prompt token must repaint the external symbol.
    // The surrounding page and all frame colors stay identical.
    await logo.evaluate(el => el.style.setProperty('--brand-accent', '#ff0000'));
    const after = await logo.screenshot();
    expect(after.equals(before)).toBe(false);
    await logo.evaluate(el => el.style.removeProperty('--brand-accent'));

    const identity = await logo.getAttribute('viewBox');
    for (const theme of themes) {
        await page.evaluate(theme => { document.body.dataset.theme = theme; }, theme);
        const state = await logo.evaluate(el => {
            const style = getComputedStyle(el);
            return {width: el.getBoundingClientRect().width, height: el.getBoundingClientRect().height,
                prompt: style.getPropertyValue('--brand-accent').trim(),
                themeAccent: getComputedStyle(document.body).getPropertyValue('--ws2-accent').trim()};
        });
        expect(state.prompt, theme).toBe(state.themeAccent);
        expect(state.width, theme).toBe(64);
        expect(state.height, theme).toBe(64);
        await expect(logo).toHaveAttribute('viewBox', identity);
    }
});

test('branding fits authentication, settings and workspace at mobile and desktop sizes', async ({page}) => {
    await login(page);
    for (const width of [390, 1440]) {
        await page.setViewportSize({width, height: width === 390 ? 844 : 960});
        for (const route of ['/', '/settings', '/security', '/change-password']) {
            await page.goto(route);
            const logo = page.locator('.app-brand-logo, .auth-product-logo').first();
            await expect(logo).toBeVisible();
            const size = await logo.boundingBox();
            expect(size.width).toBe(size.height);
            expect(size.width).toBe(route === '/change-password' ? (width === 390 ? 56 : 64) : (width === 390 && route === '/' ? 30 : 32));
            await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', /^data:image\/svg\+xml,/);
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        }
    }
});

test('the tab icon follows theme changes and keeps a local fallback on load failure', async ({page}) => {
    installExternalRequestGuard(page);
    await page.goto('/register');
    const icon = page.locator('link[rel="icon"][data-theme-logo]');
    await expect(icon).toHaveAttribute('href', /^data:image\/svg\+xml,/);
    const blue = await icon.getAttribute('href');
    await page.evaluate(() => { document.body.dataset.theme = 'emerald-matrix'; });
    await expect.poll(() => icon.getAttribute('href')).not.toBe(blue);
    const green = decodeURIComponent((await icon.getAttribute('href')).split(',', 2)[1]);
    expect(green).toContain('#45d86f');
    expect(green).not.toContain('var(--brand-');
    await page.route('**/webssh-logo.svg*', route => route.abort());
    await page.reload();
    await expect(icon).toHaveAttribute('href', /\/static\/images\/webssh-logo\.svg\?v=/);
    await page.locator('#username').fill('still-usable');
    await expect(page.locator('#username')).toHaveValue('still-usable');
});
