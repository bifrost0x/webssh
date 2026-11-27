// M1 acceptance: a walk through every navigation area and dialog. Nothing
// may break: no page error, no unhandled rejection, no server error other
// than the preview's 501 and no loading indicator that stays longer than
// 5 s. Against the Go preview every area it does not provide yet must say
// so through the preview notice; the Python release shows no such notice.
const {test, expect} = require('playwright/test');
const {freshBackend, attachLogOnFailure, kind} = require('./backend');
const {openProfileManagement} = require('../helpers');
const ui = require('./ui');

const admin = {username: 'm1preview', password: 'M1-preview-admin-password-4'};
const busy = '.spinner, .btn-spinner, .loading, .fm-loading, .fm-loading-spinner, .preview-loading, '
    + '.od-skeleton, .od-agents-skeleton, [aria-busy="true"]';

let backend;

test.beforeAll(async () => {
    backend = freshBackend('preview');
    const result = await backend.createAdmin(admin.username, admin.password);
    expect(result.code, result.output).toBe(0);
    await backend.start();
});

test.afterAll(async () => {
    await backend?.dispose();
});

test.afterEach(async ({}, testInfo) => attachLogOnFailure(testInfo, backend));

function watch(page) {
    const problems = [];
    const previewAnswers = [];
    page.on('pageerror', error => problems.push(`pageerror: ${error.message}`));
    page.on('response', async response => {
        const status = response.status();
        if (status === 501) {
            previewAnswers.push(new URL(response.url()).pathname);
            // A page route (a navigation such as /automation) answers in
            // plain text, an API route with the JSON error code.
            const page = response.request().resourceType() === 'document';
            const answer = page
                ? (await response.text().catch(() => '')).includes('Not available in this preview yet.')
                : (await response.json().catch(() => null))?.code === 'not_available_in_preview';
            if (!answer) problems.push(`501 without preview answer: ${response.url()}`);
        } else if (status >= 500) {
            problems.push(`${status} ${response.request().method()} ${response.url()}`);
        }
    });
    return {problems, previewAnswers};
}

async function installRecorders(context) {
    await context.addInitScript(() => {
        window.__m1Rejections = [];
        window.__m1Unavailable = [];
        window.addEventListener('unhandledrejection', event => {
            window.__m1Rejections.push(String(event.reason?.message || event.reason));
        });
        window.addEventListener('webssh:preview-unavailable', event => {
            window.__m1Unavailable.push(event.detail?.feature || 'other');
        });
    });
}

// Waits until no loading indicator is visible; fails after 5 s with the
// indicators that are still there.
const visited = [];

async function settled(page, where) {
    visited.push(where);
    await expect.poll(() => page.locator(busy).evaluateAll(nodes => nodes
        .filter(node => node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden')
        .map(node => node.id || node.className || node.tagName)), {
        timeout: 5000, message: `loading indicator still visible in ${where}`,
    }).toEqual([]);
}

async function visibleIds(page, selector) {
    return page.locator(selector).evaluateAll(nodes => nodes
        .filter(node => node.getClientRects().length && !node.disabled)
        .map(node => node.id).filter(Boolean));
}

async function closeOpenDialogs(page) {
    for (let attempt = 0; attempt < 3; attempt++) {
        if (!await page.locator('.modal.show').count()) return;
        await page.keyboard.press('Escape');
    }
}

test('every area and dialog opens without errors or endless loading', async ({browser}) => {
    const context = await browser.newContext({baseURL: backend.baseURL});
    await installRecorders(context);
    const page = await context.newPage();
    const {problems, previewAnswers} = watch(page);

    await test.step('sign-in page', async () => {
        await page.goto('/login');
        await settled(page, '/login');
        // Every sign-in provider is built, so neither release shows the
        // preview notice before sign-in.
        await expect(page.locator('#previewNotice')).toHaveCount(0);
    });

    await ui.signIn(page, admin.username, admin.password);
    await settled(page, 'workspace after sign-in');

    await test.step('primary navigation', async () => {
        const entries = await visibleIds(page, '#globalNavigation .global-nav-item');
        expect(entries).toEqual(expect.arrayContaining(['overviewNavBtn', 'workspaceNavBtn', 'manageProfilesBtn']));
        for (const id of entries) {
            if (await page.locator(`#${id}`).evaluate(node => node.tagName === 'A')) {
                const href = await page.locator(`#${id}`).getAttribute('href');
                await page.goto(href);
                await settled(page, href);
                await page.goto('/');
                await ui.dismissTour(page);
            } else {
                await page.locator(`#${id}`).click();
                await settled(page, id);
                await closeOpenDialogs(page);
            }
        }
    });

    await test.step('connection assets', async () => {
        await openProfileManagement(page);
        await settled(page, 'hosts');
        const assets = await page.locator('#profileManagementModal .connection-asset-nav [data-connection-asset]')
            .evaluateAll(nodes => nodes.filter(node => node.getClientRects().length).map(node => node.dataset.connectionAsset));
        for (const asset of assets) {
            await page.evaluate(name => window.openConnectionAssetManager(name), asset);
            await settled(page, `asset ${asset}`);
        }
        await closeOpenDialogs(page);
    });

    await test.step('workspace tools', async () => {
        await page.locator('#workspaceNavBtn').click();
        for (const id of await visibleIds(page, '.context-workspace-tab')) {
            await page.locator(`#${id}`).click();
            await settled(page, id);
        }
        await page.locator('#accountBtnHeader').click();
        await settled(page, 'account menu');
        await page.keyboard.press('Escape');
    });

    await test.step('settings center', async () => {
        await page.goto('/settings');
        await settled(page, '/settings');
        const tabs = page.locator('.settings-center-navigation .admin-tab');
        const labels = await tabs.evaluateAll(nodes => nodes.map(node => (node.getClientRects().length
            ? node.textContent.replace(/\s+/g, ' ').trim() : null)));
        expect(labels.filter(Boolean).length).toBeGreaterThan(5);
        for (const [index, label] of labels.entries()) {
            if (!label) continue;
            await tabs.nth(index).click();
            await settled(page, `settings: ${label}`);
        }
        if (kind === 'go') await expect(page.locator('#previewNotice')).toBeAttached();
    });

    await test.step('preview notice', async () => {
        await page.goto('/');
        await ui.dismissTour(page);
        const unavailable = await page.evaluate(() => window.__m1Unavailable);
        if (kind === 'go') {
            const notice = page.locator('#previewNotice');
            await expect(notice).toBeVisible();
            await expect(notice.locator('.preview-notice-text')).not.toBeEmpty();
            // Areas reached in this walk that the preview lacks are named
            // after a reload as well (the notice lives per page).
            if (previewAnswers.length || unavailable.length) {
                await page.locator('#commandLibraryBtn').click().catch(() => {});
                await expect.poll(() => notice.locator('.preview-notice-details').textContent()).not.toBe('');
            }
        } else {
            await expect(page.locator('#previewNotice')).toHaveCount(0);
            expect(previewAnswers).toEqual([]);
            expect(unavailable).toEqual([]);
        }
    });

    test.info().annotations.push({type: 'visited', description: visited.join(', ')});
    expect(await page.evaluate(() => window.__m1Rejections)).toEqual([]);
    expect(problems).toEqual([]);
    await context.close();
});
