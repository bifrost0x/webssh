const {test, expect} = require('playwright/test');
const {assertNoExternalRequests, installExternalRequestGuard, login} = require('./helpers');

const themes = ['glass', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];
const scenes = {
    solar: 'solar-observatory.webp', paper: 'paper-pavilion.webp', noir: 'noir-retreat.webp',
    'arctic-ice': 'arctic-fjord.webp', 'rose-gold': 'rose-desert.webp', obsidian: 'obsidian-coast.webp',
    retro: 'retro-lounge.webp', 'cyberpunk-neon': 'cyberpunk-city.webp', 'emerald-matrix': 'emerald-forest.webp',
};

test.afterEach(async ({page}) => {
    await assertNoExternalRequests(page);
});

test('every theme background decodes at its expected resolution', async ({page}) => {
    installExternalRequestGuard(page);
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
        expect(dimensions, theme).toEqual(theme === 'glass' ? [1536, 512] : [1672, theme === 'obsidian' ? 940 : 941]);
    }
});

test('login downloads only the selected scene and keeps it behind the form', async ({page}) => {
    installExternalRequestGuard(page);
    await page.addInitScript(() => localStorage.setItem('websshTheme', 'solar'));
    const requested = [];
    page.on('request', request => {
        if (request.url().includes('/theme-scenes/')) requested.push(new URL(request.url()).pathname);
    });
    await page.goto('/login');
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'solar');
    await expect.poll(() => requested).toEqual(['/static/images/theme-scenes/solar-observatory.webp']);
    await expect(page.locator('.auth-card')).toHaveCSS('background-image', 'none');
    await page.locator('#username').fill('scene-input-check');
    await expect(page.locator('#username')).toHaveValue('scene-input-check');
});

test('theme scenes follow the selected theme on overview and the window desktop', async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await page.locator("#workspaceLayoutPicker > summary").click();
    await page.locator('.split-btn[data-layout="windows"]').click();
    await expect(page.locator('#terminalGrid')).toHaveClass(/window-mode/);
    await page.locator('#overviewNavBtn').click();
    await page.locator('#overviewListBtn').click();
    for (const [theme, name] of Object.entries(scenes)) {
        await page.evaluate(value => { document.body.dataset.theme = value; }, theme);
        await expect(page.locator('.overview-heading')).toHaveCSS('background-image', new RegExp(name));
        await expect(page.locator('#terminalGrid')).toHaveCSS('background-image', new RegExp(name));
        await expect(page.locator('.overview-heading')).toHaveCSS('background-size', 'cover');
        await page.locator('#overviewGraphBtn').click();
        await expect(page.locator('.overview-heading')).toHaveCSS('background-image', 'none');
        await page.locator('#overviewListBtn').click();
    }
    await page.evaluate(() => { document.body.dataset.theme = 'glass'; });
    await expect(page.locator('.overview-heading')).toHaveCSS('background-image', /midnight-lodge.webp/);
    await expect(page.locator('#terminalGrid')).toHaveCSS('background-image', /radial-gradient/);
});

test('login remains usable when storage and the background are unavailable', async ({page}) => {
    installExternalRequestGuard(page);
    await page.addInitScript(() => {
        Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Blocked', 'SecurityError'); }});
    });
    await page.route('**/theme-backgrounds/**', route => route.abort());
    await page.route('**/theme-scenes/**', route => route.abort());
    await page.route('**/redesign/midnight-lodge.webp*', route => route.abort());
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('/login');
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'glass');
    await page.locator('input[name="username"]').fill('fallback-works');
    await expect(page.locator('input[name="username"]')).toHaveValue('fallback-works');
    expect(errors).toEqual([]);
});
