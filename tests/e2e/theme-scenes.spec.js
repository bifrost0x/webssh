const {test, expect} = require('playwright/test');
const {login, installExternalRequestGuard, assertNoExternalRequests} = require('./helpers');

const themes = ['glass','werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];

async function sceneDetails(page, selector, pseudo) {
    return page.locator(selector).evaluate(async (element, layer) => {
        const style = getComputedStyle(element, layer);
        const match = style.backgroundImage.match(/url\(["']?([^"')]+)["']?\)/);
        const image = new Image();
        if (match) {
            image.src = match[1];
            await image.decode();
        }
        return {
            source: match?.[1], width: image.naturalWidth, height: image.naturalHeight,
            display: style.display, layerHeight: parseFloat(style.height), layerWidth: parseFloat(style.width),
            background: style.backgroundImage, position: style.backgroundPosition,
        };
    }, pseudo);
}

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('each mobile login theme keeps a visible scene band and the primary action in reach', async ({page}) => {
    installExternalRequestGuard(page);
    await page.setViewportSize({width: 390, height: 844});
    await page.goto('/login');
    for (const theme of themes) {
        await page.evaluate(value => { document.body.dataset.theme = value; }, theme);
        const scene = await sceneDetails(page, 'body', '::before');
        expect(scene.display, theme).toBe('block');
        expect(scene.width, theme).toBeGreaterThanOrEqual(1500);
        expect(scene.layerHeight, theme).toBeLessThanOrEqual(844);
        const headerScene = await sceneDetails(page, '.auth-context-panel');
        expect(headerScene.source, theme).toBeUndefined();
        expect(headerScene.layerHeight, theme).toBeLessThanOrEqual(110);
        const utility = await page.locator('.auth-utility-bar').boundingBox();
        const dock = await page.locator('.auth-access-dock').boundingBox();
        expect(dock.y - utility.y - utility.height, theme).toBeGreaterThanOrEqual(4);
        expect(dock.y + dock.height, theme).toBeLessThanOrEqual(844);
        const action = await page.locator('form button[type="submit"]').boundingBox();
        expect(action.y + action.height, theme).toBeLessThanOrEqual(844);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), theme).toBe(true);
    }
    await page.locator('#username').fill('visible-scene-input');
    await expect(page.locator('#username')).toHaveValue('visible-scene-input');
});

test('mobile overview integrates the scene inside the welcome without covering inventory controls', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await login(page, 'e2e_admin', {workspace: false});
    for (const theme of themes) {
        await page.evaluate(value => {document.body.dataset.theme = value;}, theme);
        const scene = await sceneDetails(page, '.od-scene');
        expect(scene.width, theme).toBeGreaterThanOrEqual(1500);
        const photo = await page.locator('.od-hero').boundingBox();
        const title = await page.locator('#overviewTitle').boundingBox();
        const inventory = await page.locator('.od-kpis').boundingBox();
        expect(photo.height, theme).toBeGreaterThanOrEqual(60);
        expect(title.y, theme).toBeGreaterThanOrEqual(photo.y);
        expect(title.y + title.height, theme).toBeLessThanOrEqual(photo.y + photo.height);
        expect(photo.x + photo.width, theme).toBeLessThanOrEqual(390);
        expect(inventory.y, theme).toBeGreaterThanOrEqual(photo.y + photo.height);
    }
    await expect(page.locator('.od-scene')).toBeVisible();
    await page.locator('#overviewSearch').fill('Usable');
    await expect(page.locator('#overviewSearch')).toHaveValue('Usable');
    expect(await page.locator('#overviewSearch').evaluate(input => {
        const box = input.getBoundingClientRect();
        return document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2) === input;
    })).toBe(true);
    await page.locator('#overviewSearch').fill('');
});

test('scene readiness and custom wallpaper override preserve the mobile overview', async ({page}) => {
    await page.setViewportSize({width: 390, height: 844});
    await login(page, 'e2e_admin', {workspace: false});
    await page.evaluate(() => {
        document.body.dataset.theme = 'paper';
        document.body.dataset.deferThemeBackground = '';
        document.body.removeAttribute('data-theme-background-ready');
    });
    await expect(page.locator('.od-scene')).not.toHaveCSS('background-image', /url\(/);
    await page.evaluate(() => {
        document.body.dataset.themeBackgroundReady = '';
        const canvas = document.createElement('canvas');
        canvas.width = 1920;
        canvas.height = 1080;
        canvas.getContext('2d').fillRect(0, 0, canvas.width, canvas.height);
        document.body.style.setProperty('--theme-background-image', `url("${canvas.toDataURL()}")`);
        document.body.dataset.customBackground = '';
    });
    await expect(page.locator('.od-scene')).toHaveCSS('background-image', /data:image\/png/);
    await page.evaluate(() => {
        document.body.style.removeProperty('--theme-background-image');
        delete document.body.dataset.customBackground;
    });
    await expect(page.locator('.od-scene')).toHaveCSS('background-image', /paper-pavilion/);
});

test('large screens decode local scene sources and keep the login form concentrated', async ({page}) => {
    installExternalRequestGuard(page);
    await page.setViewportSize({width: 3840, height: 2160});
    await page.goto('/login');
    for (const theme of themes) {
        await page.evaluate(value => { document.body.dataset.theme = value; }, theme);
        const scene = await sceneDetails(page, 'body', '::before');
        expect(new URL(scene.source).origin, theme).toBe(new URL(page.url()).origin);
        expect(scene.width, theme).toBeGreaterThanOrEqual(1500);
        expect(scene.layerWidth, theme).toBeLessThanOrEqual(scene.width);
        expect(scene.layerHeight, theme).toBeLessThanOrEqual(scene.height + 1);
        const dock = await page.locator('.auth-access-dock').boundingBox();
        expect(dock.width, theme).toBeLessThanOrEqual(540);
        expect(dock.x, theme).toBeGreaterThan(1400);
    }
});


test('high density desktops keep the bundled login scene within its physical pixel budget', async ({browser, baseURL}) => {
    const context = await browser.newContext({baseURL, viewport: {width: 2560, height: 1440}, deviceScaleFactor: 2});
    const page = await context.newPage();
    installExternalRequestGuard(page);
    try {
        await page.goto('/login');
        for (const theme of themes) {
            await page.evaluate(value => { document.body.dataset.theme = value; }, theme);
            const scene = await sceneDetails(page, 'body', '::before');
            expect(scene.layerWidth * 2, theme).toBeLessThanOrEqual(scene.width);
            expect(scene.layerHeight * 2, theme).toBeLessThanOrEqual(scene.height + 1);
        }
        await assertNoExternalRequests(page);
    } finally {
        await context.close();
    }
});

for (const locale of ['en', 'de']) {
    test(`compact login stays complete with one continuous scene in ${locale}`, async ({page}) => {
        installExternalRequestGuard(page);
        await page.addInitScript(value => localStorage.setItem('language', value), locale);
        for (const [width, height] of [[320, 568], [360, 560], [320, 640], [360, 640], [390, 700], [600, 740], [768, 740], [820, 1180], [1024, 600], [1024, 768]]) {
            await page.setViewportSize({width, height});
            await page.goto('/login');
            await page.evaluate(() => document.fonts.ready);
            await expect(page.locator('html')).toHaveAttribute('lang', locale);
            const geometry = await page.locator('.auth-access-dock').evaluate(element => ({
                bottom: element.getBoundingClientRect().bottom,
                height: document.documentElement.scrollHeight,
                width: document.documentElement.scrollWidth,
                headerImage: getComputedStyle(element.querySelector('.auth-context-panel')).backgroundImage,
                sceneMask: getComputedStyle(document.body, '::before').maskImage,
            }));
            expect(geometry.bottom, `${width}x${height}`).toBeLessThanOrEqual(height);
            expect(geometry.height, `${width}x${height}`).toBeLessThanOrEqual(height);
            expect(geometry.width).toBeLessThanOrEqual(width);
            expect(geometry.headerImage).not.toContain('url(');
            expect(geometry.sceneMask).toContain('linear-gradient');
            for (const tab of await page.locator('.auth-method-option').all()) {
                await expect(tab).toBeVisible();
                expect((await tab.boundingBox()).height).toBeGreaterThanOrEqual(44);
            }
            await expect(page.locator('#localLoginForm .btn-primary')).toBeInViewport({ratio: 1});
            await expect(page.locator('.auth-footer')).toBeInViewport({ratio: 1});
        }
    });
}

test('compact sign-in tabs use the available width for one to four enabled methods', async ({page}) => {
    installExternalRequestGuard(page);
    await page.setViewportSize({width: 390, height: 844});
    for (const count of [1, 2, 3, 4]) {
        await page.goto('/login');
        await page.locator('.auth-method-switcher').evaluate((element, amount) => {
            while (element.children.length > amount) element.lastElementChild.remove();
            while (element.children.length < amount) {
                const tab = element.firstElementChild.cloneNode(true);
                tab.removeAttribute('id');
                tab.setAttribute('aria-selected', 'false');
                tab.querySelector('strong').textContent = 'GitHub';
                element.append(tab);
            }
        }, count);
        const boxes = await page.locator('.auth-method-option').evaluateAll(elements => elements.map(element => {
            const box = element.getBoundingClientRect();
            return {left: box.left, right: box.right, top: box.top, width: box.width};
        }));
        const rows = [...new Set(boxes.map(box => box.top))];
        expect(rows.length).toBe(count === 4 ? 2 : 1);
        const bounds = await page.locator('.auth-method-switcher').boundingBox();
        for (const top of rows) {
            const row = boxes.filter(box => box.top === top);
            expect(row[0].left - bounds.x).toBeLessThanOrEqual(6);
            expect(bounds.x + bounds.width - row.at(-1).right).toBeLessThanOrEqual(6);
        }
    }
});
