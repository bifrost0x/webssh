const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

const localeRequests = page => {
    const requested = [];
    page.on('request', request => {
        const match = /\/static\/js\/i18n\/([a-z]{2})\.js\?v=/.exec(request.url());
        if (match) requested.push(match[1]);
    });
    return requested;
};

for (const [language, overview, signIn] of [['de', 'Übersicht', 'Anmelden'], ['fr', 'Vue d’ensemble', 'Se connecter'], ['zh', '概览', '登录']]) {
    test(`the application starts translated in ${language} and loads only English and ${language}`, async ({page}) => {
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        // Resource errors (for example optional API probes answered with 403) are not script errors.
        page.on('console', message => { if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) errors.push(message.text()); });
        await page.addInitScript(value => localStorage.setItem('language', value), language);

        await page.goto('/login');
        await expect(page.locator('html')).toHaveAttribute('lang', language);
        await expect(page.locator('[data-i18n="auth.login"]').first()).toHaveText(signIn);

        const requested = localeRequests(page);
        await login(page, 'e2e_admin', {workspace: false});
        await expect(page.locator('html')).toHaveAttribute('lang', language);
        expect(await page.evaluate(() => window.i18n.getLanguage())).toBe(language);
        await expect(page.locator('#overviewNavBtn [data-i18n="overview.title"]')).toHaveText(overview);
        // Startup strings set by scripts, not only data-i18n attributes, are translated.
        expect(await page.evaluate(() => [...document.querySelectorAll('[data-i18n]')]
            .filter(element => /^[a-z][\w-]*\.[\w.-]+$/.test(element.textContent.trim())).map(element => element.textContent.trim()))).toEqual([]);
        expect([...new Set(requested)].sort()).toEqual(['en', language].sort());
        expect(errors).toEqual([]);
    });
}

test('switching language loads the dictionary on demand and dispatches languageChanged once', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    const requested = localeRequests(page);
    await page.evaluate(() => {
        window.__languageEvents = [];
        window.addEventListener('languageChanged', event => window.__languageEvents.push(event.detail.lang));
    });
    expect(await page.evaluate(() => window.i18n.isLocaleLoaded('es'))).toBe(false);
    expect(await page.evaluate(() => window.i18n.setLanguage('es'))).toBe(true);
    await expect(page.locator('html')).toHaveAttribute('lang', 'es');
    await expect(page.locator('#overviewNavBtn [data-i18n="overview.title"]')).toHaveText(await page.evaluate(() => window.i18n.t('overview.title')));
    expect(await page.evaluate(() => window.i18n.t('overview.title'))).not.toBe('Overview');
    expect(await page.evaluate(() => window.__languageEvents)).toEqual(['es']);
    expect(requested).toEqual(['es']);

    // A loaded language switches back without another request.
    expect(await page.evaluate(() => window.i18n.setLanguage('en'))).toBe(true);
    expect(await page.evaluate(() => window.__languageEvents)).toEqual(['es', 'en']);
    expect(requested).toEqual(['es']);

    // The choice survives a reload and is loaded synchronously again.
    await page.evaluate(() => window.i18n.setLanguage('vi'));
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('lang', 'vi');
    await expect(page.locator('#overviewNavBtn [data-i18n="overview.title"]')).toHaveText(await page.evaluate(() => window.i18n.t('overview.title')));
    expect(await page.evaluate(() => window.i18n.isLocaleLoaded('vi'))).toBe(true);
    await page.evaluate(() => window.i18n.setLanguage('en'));
});

test('the settings language selector switches languages that are not loaded yet', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await page.goto('/settings');
    await page.locator('[data-account-section="preferences"]').click();
    const select = page.locator('#settingsLanguageSelect');
    await select.selectOption('fr');
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(select).toHaveValue('fr');
    await expect(page.getByText(await page.evaluate(() => window.i18n.t('settings.languageUpdated'))).first()).toBeVisible();
    await select.selectOption('en');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
});

for (const language of ['es', 'vi']) {
    test(`sign-in and registration pages are translated in ${language}`, async ({page}) => {
        await page.addInitScript(value => localStorage.setItem('language', value), language);
        for (const path of ['/login', '/register']) {
            const response = await page.goto(path);
            if (response.status() !== 200) continue;
            await expect(page.locator('html')).toHaveAttribute('lang', language);
            const english = await page.evaluate(() => {
                const leftovers = [];
                document.querySelectorAll('[data-i18n]').forEach(element => {
                    if (/^[a-z][\w-]*\.[\w.-]+$/.test(element.textContent.trim())) leftovers.push(element.textContent.trim());
                });
                return leftovers;
            });
            expect(english).toEqual([]);
        }
    });
}
