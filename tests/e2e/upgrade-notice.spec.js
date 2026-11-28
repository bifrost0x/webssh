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

    for (const [name, href] of [['What has changed', wiki], ['Report an issue', issues]]) {
        const link = dialog.getByRole('link', {name});
        await expect(link).toHaveAttribute('href', href);
        await expect(link).toHaveAttribute('target', '_blank');
        await expect(link).toHaveAttribute('rel', /(^|\s)noopener(\s|$)/);
    }
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
    const walk = async key => {
        const seen = [];
        for (let i = 0; i < 4; i++) {
            await page.keyboard.press(key);
            seen.push(await focused());
        }
        return seen;
    };
    expect(await walk('Tab')).toEqual([wiki, issues, 'Got it', wiki]);
    expect(await walk('Shift+Tab')).toEqual(['Got it', issues, wiki, 'Got it']);

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
