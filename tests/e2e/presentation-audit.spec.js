const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
const themes = ['glass', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'obsidian', 'retro', 'cyberpunk-neon', 'emerald-matrix'];
const languages = ['en', 'vi', 'de', 'fr', 'es', 'zh'];

async function navigate(page, selector) {
    if (!await page.locator(selector).isVisible()) await page.locator('#mobileMoreBtn').click();
    await page.locator(selector).click();
}
async function records(page) {
    // Test-only records; never saved to the account or bundled in the app.
    await page.evaluate(() => {
        ProfileManager.setProfiles(Array.from({length: 5}, (_, index) => ({
            id: `audit-${index}`, name: `Server ${index + 1}`, group: `Group ${index + 1}`,
            host: `audit-${index}.example.invalid`, username: 'audit', auth_type: 'password',
            jump_host_id: index < 2 ? 'audit-jump' : null, favorite: index === 0,
        })));
        JumpHostManager.setJumpHosts([{id: 'audit-jump', name: 'Bastion'}]);
    });
}
async function capture(page, name) {
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({path: test.info().outputPath( `${name}.png`), animations: 'disabled'});
}
async function contrast(page, selector, backgroundSelector) {
    return page.evaluate(({selector, backgroundSelector}) => {
        const element = document.querySelector(selector);
        const canvas = document.createElement('canvas');
        canvas.width = canvas.height = 1;
        const context = canvas.getContext('2d', {willReadFrequently: true});
        const rgba = color => {
            context.clearRect(0, 0, 1, 1);
            context.fillStyle = color;
            context.fillRect(0, 0, 1, 1);
            return [...context.getImageData(0, 0, 1, 1).data];
        };
        const background = target => {
            const color = rgba(getComputedStyle(target).backgroundColor);
            if (color[3] === 255) return color;
            const below = target.parentElement ? background(target.parentElement) : [255, 255, 255];
            return color.slice(0, 3).map((c, i) => c * color[3] / 255 + below[i] * (1 - color[3] / 255));
        };
        const luminance = color => color.slice(0, 3).map(c => c / 255).map(c => c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4)
            .reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
        const foreground = luminance(rgba(getComputedStyle(element).color));
        const bg = luminance(background(backgroundSelector ? document.querySelector(backgroundSelector) : element));
        return (Math.max(foreground, bg) + .05) / (Math.min(foreground, bg) + .05);
    }, {selector, backgroundSelector});
}

test.afterEach(async ({page}) => assertNoExternalRequests(page));

for (const theme of themes) {
    test(`presentation contrast and route accents in ${theme}`, async ({page}) => {
        await page.setViewportSize({width: 1440, height: 1024});
        await login(page);
        await records(page);
        await page.evaluate(theme => { document.body.dataset.theme = theme; }, theme);
        await navigate(page, '#overviewNavBtn');
        for (const selector of ['#overviewQuickConnect', '#overviewListBtn', '.overview-empty', '.overview-row-title', '.overview-group-heading']) {
            expect(await contrast(page, selector), `${theme}: ${selector}`).toBeGreaterThanOrEqual(4.5);
        }
        for (let tone = 0; tone < 5; tone++) {
            expect(await contrast(page, `#overviewHosts [data-tone="${tone}"] .overview-group-heading`), `${theme}: group ${tone}`).toBeGreaterThanOrEqual(4.5);
        }
        await page.locator('#overviewQuickConnect').hover();
        expect(await contrast(page, '#overviewQuickConnect'), `${theme}: primary hover`).toBeGreaterThanOrEqual(4.5);
        await page.mouse.move(0, 0);
        await capture(page, `theme-${theme}-overview`);
        await page.locator('#overviewGraphBtn').click();
        await expect(page.locator('#overviewHosts .overview-edges path')).toHaveCount(2);
        const accents = await page.locator('.overview-jump').evaluate(element => {
            const style = getComputedStyle(element);
            return {border: style.borderTopColor, icon: getComputedStyle(element.querySelector('.material-icons')).color};
        });
        expect(accents.border).toBe(accents.icon);
        expect(await contrast(page, '#overviewGraphBtn')).toBeGreaterThanOrEqual(4.5);
        await capture(page, `theme-${theme}-routes`);
        await navigate(page, '#manageProfilesBtn');
        await capture(page, `theme-${theme}-hosts`);
        await page.goto('/settings#preferences');
        await page.evaluate(theme => { document.body.dataset.theme = theme; }, theme);
        await capture(page, `theme-${theme}-settings`);
    });
}

for (const language of languages) {
    for (const width of [1440, 390]) {
        test(`translated navigation and content in ${language} at ${width}px`, async ({page}) => {
            await page.setViewportSize({width, height: 1024});
            await login(page);
            await records(page);
            await page.evaluate(language => i18n.setLanguage(language), language);
            const unchangedNames = ['Server 1', 'Server 2', 'Server 3', 'Server 4', 'Server 5'];
            await navigate(page, '#overviewNavBtn');
            await expect(page.locator('html')).toHaveAttribute('lang', language);
            await expect(page.locator('#overviewHosts .overview-row-title')).toHaveText(unchangedNames);
            await expect(page.locator('#overviewTitle')).toHaveText(await page.evaluate(() => i18n.t('overview.heading')));
            await expect(page.locator('#connectionOverview')).not.toContainText(/homelab|demo|placeholder/i);
            await capture(page, `language-${language}-${width}-overview`);
            await page.locator('#overviewGraphBtn').click();
            await expect(page.locator('#overviewTitle')).toHaveText(await page.evaluate(() => i18n.t('overview.routesHeading')));
            await expect(page.locator('#overviewHosts .overview-edges path')).toHaveCount(2);
            await capture(page, `language-${language}-${width}-routes`);
            for (const [selector, name] of [['#manageProfilesBtn', 'hosts'], ['#commandLibraryBtn', 'commands'], ['#fileTransferBtn', 'files']]) {
                await navigate(page, selector);
                await capture(page, `language-${language}-${width}-${name}`);
            }
            await page.goto('/settings#preferences');
            await page.evaluate(language => i18n.setLanguage(language), language);
            await capture(page, `language-${language}-${width}-settings`);
            // All directly translated DOM labels use this locale, never raw keys.
            const invalid = await page.evaluate(() => [...document.querySelectorAll('[data-i18n]')]
                .filter(el => el.getClientRects().length && el.textContent.trim() !== i18n.t(el.dataset.i18n).trim())
                .map(el => el.dataset.i18n));
            expect(invalid).toEqual([]);
            // Exercise the public auth bundle separately from the full app bundle.
            await page.context().clearCookies();
            await page.goto('/');
            await expect(page.locator('.alert[data-i18n="auth.loginRequired"]')).toBeVisible();
            await page.evaluate(language => i18n.setLanguage(language), language);
            await expect(page.locator('.alert')).toHaveText(await page.evaluate(() => i18n.t('auth.loginRequired')));
            await page.locator('#username').fill('missing_audit_account');
            await page.locator('#password').fill('incorrect');
            await page.locator('#localLoginForm button[type="submit"]').click();
            await expect(page.locator('.alert[data-i18n="auth.invalidCredentials"]')).toHaveText(await page.evaluate(() => i18n.t('auth.invalidCredentials')));
            await capture(page, `language-${language}-${width}-login`);
        });
    }
}
