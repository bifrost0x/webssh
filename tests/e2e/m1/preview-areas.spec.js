// Walk through every navigation area and the main dialogs of the preview
// (Go server). Areas the preview does not offer must say so, and nothing
// may hang: no page error, no unhandled rejection, no spinner that stays.
const {test, expect} = require('playwright/test');
const {login, waitForInventory} = require('../helpers');

const NAVIGATION = ['#overviewNavBtn', '#workspaceNavBtn', '#fileTransferBtn', '#automationNavBtn', '#commandLibraryBtn', '#manageProfilesBtn'];
const HOST_TABS = ['Hosts', 'Jump Hosts', 'SOCKS5 Proxies', 'SSH Keys', 'Passwords'];

async function trackFailures(page) {
    const failures = [];
    page.on('pageerror', error => failures.push(`pageerror: ${error.message}`));
    await page.addInitScript(() => {
        window.__unhandled = [];
        window.addEventListener('unhandledrejection', event => {
            window.__unhandled.push(String(event.reason?.message || event.reason));
        });
    });
    return failures;
}

// A spinner may show while a request runs, never for longer than 5 s.
async function expectNoStuckSpinner(page, where) {
    const visibleSpinners = () => page.evaluate(() => [...document.querySelectorAll('.spinner, [aria-busy="true"]')]
        .filter(el => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden').length);
    await expect.poll(visibleSpinners, {message: `spinner stays visible in ${where}`, timeout: 5000}).toBe(0);
}

test('every navigation area and dialog of the preview opens without hanging', async ({page}) => {
    test.skip(!process.env.WEBSSH_E2E_SERVER_COMMAND?.includes('webssh'), 'preview areas exist only on the Go server');
    const failures = await trackFailures(page);
    await page.setViewportSize({width: 1440, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    await waitForInventory(page);

    const notice = page.locator('#previewNotice');
    await expect(notice).toBeVisible();
    for (const area of ['Files', 'Automation', 'Server operations']) {
        await expect(notice).toContainText(area);
    }

    for (const selector of NAVIGATION) {
        const button = page.locator(selector);
        if (!(await button.isVisible())) continue;
        await button.click();
        await expectNoStuckSpinner(page, selector);
    }

    await page.locator('#manageProfilesBtn').click();
    for (const name of HOST_TABS) {
        const tab = page.getByRole('tab', {name, exact: true});
        if (!(await tab.count())) continue;
        await tab.first().click();
        await expectNoStuckSpinner(page, `hosts tab ${name}`);
    }

    await page.locator('#shellConnectBtn').click();
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expectNoStuckSpinner(page, 'connection dialog');
    await page.locator('#cancelConnectionBtn').click();

    await page.goto('/settings');
    await expectNoStuckSpinner(page, 'settings');

    // An area without a server side reached through the frontend is named
    // in the notice (the shim reports it).
    await page.goto('/');
    await waitForInventory(page);
    await page.evaluate(() => new Promise(resolve => window.socket.emit('list_directory', {path: '/'}, resolve)));
    await expect(page.locator('#previewNotice')).toContainText('Files');

    expect(failures).toEqual([]);
    expect(await page.evaluate(() => window.__unhandled)).toEqual([]);
});
