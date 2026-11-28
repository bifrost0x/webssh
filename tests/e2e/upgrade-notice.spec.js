// The one-time notice after the update to 3.4. The Go server shows it to
// accounts its first-start migration took over from 3.3; the seed marks two
// such accounts as migrated, each used by one test only, because the
// acknowledgement is stored for good. The Python release, the default
// backend of this suite, has neither the notice nor its route: there no
// account sees one.
const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

const wiki = 'https://github.com/bifrost0x/webssh/wiki/Upgrading-to-3.4';
const issues = 'https://github.com/bifrost0x/webssh/issues';
// The support links of the settings page, .github/FUNDING.yml and the README.
const support = [
    ['GitHub Sponsors', 'https://github.com/sponsors/bifrost0x', 'favorite'],
    ['Patreon', 'https://www.patreon.com/bifrost0x', 'volunteer_activism'],
    ['Buy Me a Coffee', 'https://buymeacoffee.com/bifrost0x', 'local_cafe'],
];
const themes = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];
const notice = page => page.locator('dialog.upgrade-notice');
const noticesRead = page => page.waitForResponse(response => response.url().endsWith('/api/account/notices')
    && response.request().method() === 'GET');

// GET /api/realtime/status exists only on the Go server.
async function goBackend(page) {
    const response = await page.request.get('/api/realtime/status');
    return response.ok() && Array.isArray((await response.json()).subprotocols);
}

// Signs in and returns the page's own request for its notices.
async function signIn(page, username) {
    const read = noticesRead(page);
    await login(page, username, {workspace: false});
    return read;
}

async function expectNoNotice(page) {
    const read = noticesRead(page);
    await page.reload();
    const response = await read;
    if (response.ok()) expect(await response.json()).toEqual({notices: []});
    await expect(notice(page)).toHaveCount(0);
}

test('a taken-over account sees the notice once, before the tour, and on no other device again', async ({page, browser}) => {
    await signIn(page, 'e2e_upgraded');
    if (!await goBackend(page)) {
        await expectNoNotice(page);
        return;
    }
    const dialog = notice(page);
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleName('With 3.4, WebSSH runs on a new foundation built in Go');
    await expect(dialog).toContainText('All your data was carried over automatically');

    // With the tour not yet seen, the notice comes first and the tour waits.
    const csrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
    expect((await page.request.post('/api/account/tour', {data: {state: 'new'}, headers: {'X-CSRFToken': csrf}})).ok()).toBe(true);
    await page.reload();
    await expect(dialog).toBeVisible();
    await expect(page.locator('.intro-tour')).toHaveCount(0);

    for (const [name, href] of [['What has changed', wiki], ['Report an issue', issues], ...support]) {
        const link = dialog.getByRole('link', {name, exact: true});
        await expect(link).toHaveAttribute('href', href);
        await expect(link).toHaveAttribute('target', '_blank');
        await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    }
    // The support offer is its own section below the notice, with the icons of the settings page.
    const offer = dialog.getByRole('region', {name: 'WebSSH stays free and independent'});
    await expect(offer).toContainText('I build WebSSH as a solo developer, with no company and no ads behind it.');
    await expect(dialog).toContainText("Please report it as an issue on GitHub. I'll take care of it right away.");
    await expect(dialog).not.toContainText(/\b(we|us)\b/i);
    expect(await offer.locator('a .material-icons').allTextContents()).toEqual(support.map(([, , glyph]) => glyph));
    for (const width of [390, 1440]) {
        await page.setViewportSize({width, height: 800});
        const box = await dialog.boundingBox();
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(width);
        await expect(dialog.getByRole('button', {name: 'Got it', exact: true})).toBeInViewport();
    }

    const saved = page.waitForResponse(response => response.url().endsWith('/api/account/notices/acknowledge'));
    await dialog.getByRole('button', {name: 'Got it', exact: true}).click();
    expect((await saved).status()).toBe(200);
    await expect(dialog).toHaveCount(0);
    const tour = page.locator('.intro-tour');
    await expect(tour).toBeVisible();
    await tour.getByRole('button', {name: 'Skip tour', exact: true}).click();
    await expect(tour).toHaveCount(0);

    await expectNoNotice(page);
    await expect(tour).toHaveCount(0);
    const context = await browser.newContext();
    const other = await context.newPage();
    await signIn(other, 'e2e_upgraded');
    await expectNoNotice(other);
    await context.close();
    // No tracking and no external resources: the links were not followed.
    expect(page.__externalRequests).toEqual([]);
});

test('the notice is a modal dialog that works with the keyboard alone', async ({page}) => {
    await signIn(page, 'e2e_upgraded_keyboard');
    if (!await goBackend(page)) {
        await expectNoNotice(page);
        return;
    }
    const dialog = notice(page);
    await expect(dialog).toBeVisible();
    expect(await dialog.evaluate(element => element.matches(':modal'))).toBe(true);
    expect(await dialog.evaluate(element => document.getElementById(element.getAttribute('aria-labelledby'))?.tagName)).toBe('H2');
    const done = dialog.getByRole('button', {name: 'Got it', exact: true});
    await expect(done).toBeFocused();

    // Focus stays inside, forwards and backwards, through both links.
    const focused = () => page.evaluate(() => {
        const active = document.activeElement;
        if (!document.querySelector('dialog.upgrade-notice')?.contains(active)) return null;
        return active.tagName === 'A' ? active.href : active.textContent.trim();
    });
    const walk = async (key, presses) => {
        const seen = [];
        for (let i = 0; i < presses; i++) {
            await page.keyboard.press(key);
            seen.push(await focused());
        }
        return seen;
    };
    // Notice, then the support links, then closing.
    const order = [wiki, issues, ...support.map(([, href]) => href), 'Got it'];
    expect(await walk('Tab', order.length + 1)).toEqual([...order, wiki]);
    expect(await walk('Shift+Tab', order.length + 1)).toEqual(['Got it', ...order.slice(0, -1).reverse(), 'Got it']);

    const saved = page.waitForResponse(response => response.url().endsWith('/api/account/notices/acknowledge'));
    await page.keyboard.press('Escape');
    expect((await saved).status()).toBe(200);
    await expect(dialog).toHaveCount(0);
    // Focus returns to the page instead of getting lost.
    await expect(page.locator('#overviewNavBtn')).toBeFocused();
    await expectNoNotice(page);
});

test('an account created on this installation never sees the notice', async ({page}) => {
    const read = await signIn(page, 'e2e_user');
    if (await goBackend(page)) expect(await read.json()).toEqual({notices: []});
    await expect(notice(page)).toHaveCount(0);
    await expectNoNotice(page);
});

// Rendered from a stubbed notices answer, so no seeded account is used up;
// the same code shows it on both servers.
test('the support offer is quieter than the notice, readable in every theme and follows the administrator', async ({page}) => {
    await login(page, 'e2e_user', {workspace: false});
    await page.route('**/api/account/notices', route => route.fulfill({json: {notices: ['upgrade-3.4']}}));
    await page.route('**/api/account/notices/acknowledge', route => route.fulfill({json: {notices: []}}));
    await page.reload();
    const dialog = notice(page);
    const offer = dialog.locator('.upgrade-notice-support');
    await expect(offer).toBeVisible();
    const size = selector => dialog.locator(selector).first().evaluate(element => parseFloat(getComputedStyle(element).fontSize));
    expect(await size('.upgrade-notice-support p')).toBeLessThan(await size('#upgradeNoticeBody'));

    // WCAG contrast of every text in the dialog against what lies behind it.
    const lowest = () => dialog.evaluate(root => {
        const context = document.createElement('canvas').getContext('2d', {willReadFrequently: true});
        const rgba = color => {
            context.clearRect(0, 0, 1, 1); context.fillStyle = '#000'; context.fillStyle = color; context.fillRect(0, 0, 1, 1);
            const [r, g, b, a] = context.getImageData(0, 0, 1, 1).data;
            return [r, g, b, a / 255];
        };
        const over = ([r, g, b, a], [br, bg, bb]) => [r * a + br * (1 - a), g * a + bg * (1 - a), b * a + bb * (1 - a)];
        const behind = element => {
            const layers = [];
            for (let node = element; node; node = node.parentElement) {
                const layer = rgba(getComputedStyle(node).backgroundColor);
                if (layer[3] > 0) layers.push(layer);
                if (layer[3] >= 1) break;
            }
            return layers.reverse().reduce((base, layer) => over(layer, base), [255, 255, 255]);
        };
        const luminance = rgb => {
            const [r, g, b] = rgb.map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; });
            return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };
        const ratio = element => {
            const background = behind(element);
            const [a, b] = [luminance(over(rgba(getComputedStyle(element).color), background)), luminance(background)].sort((x, y) => y - x);
            return (a + 0.05) / (b + 0.05);
        };
        const texts = [...root.querySelectorAll('h2, h3 > span:not(.material-icons), p, li, a > span:not(.material-icons), .btn')];
        return texts.map(element => [ratio(element), element.textContent.trim().slice(0, 24)]).sort((x, y) => x[0] - y[0])[0];
    });
    // Final colors only: transitions would report a value between two themes.
    await page.addStyleTag({content: '*, *::before, *::after { transition: none !important; animation: none !important; }'});
    for (const theme of themes) {
        await page.evaluate(name => { document.body.dataset.theme = name; }, theme);
        const [ratio, text] = await lowest();
        expect(ratio, `${theme}: "${text}"`).toBeGreaterThanOrEqual(4.5);
    }

    // Without support links on the page (an administrator hid them), the
    // notice offers none either, and Tab goes from the notice to closing.
    await page.route(url => new URL(url).pathname === '/', async route => {
        const response = await route.fetch();
        await route.fulfill({response, body: (await response.text()).replace(/<a id="accountSupportLink"[\s\S]*?<\/a>/, '')});
    });
    await page.reload();
    await expect(dialog).toBeVisible();
    await expect(page.locator('#accountSupportLink')).toHaveCount(0);
    await expect(offer).toHaveCount(0);
    await page.keyboard.press('Shift+Tab');
    await expect(dialog.getByRole('link', {name: 'Report an issue'})).toBeFocused();
    await dialog.getByRole('button', {name: 'Got it', exact: true}).click();
    await expect(dialog).toHaveCount(0);
});
