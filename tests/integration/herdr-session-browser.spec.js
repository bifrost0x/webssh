const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { test, expect } = require('playwright/test');
const { login } = require('../e2e/helpers');

// Requires the disposable OpenSSH lab with Herdr 0.9.5 and run_herdr_browser_app.py.
const PASSWORD = 'Paramiko5-Test-Only!';
const PYTHON = process.env.PYTHON || 'python';
const MOBILE = {
    viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
};
// Terminal replies that would show up as pane text if they were echoed back.
const LEAKED_REPLY = /(\[\?[0-9;]*c|\d+;\d+R|rgb:[0-9a-f]{2,4}\/|\]1[01];|\[\?\d+;\d\$y|\[\?\d*u)/i;

/** The lab's Herdr state, read over its own SSH connection. */
function lab(action, ...args) {
    const output = execFileSync(PYTHON, [path.join(__dirname, 'herdr_lab_probe.py'), action, ...args], {
        encoding: 'utf8', env: process.env, timeout: 30_000,
    });
    return JSON.parse(output);
}

function profileId(page, name) {
    return page.evaluate(label => window.ProfileManager.profiles.find(profile => profile.name === label).id, name);
}

function sessionIds(page) {
    return page.evaluate(() => Object.keys(window.TerminalManager?.terminals || {}));
}

function screen(page, id) {
    return page.evaluate(key => {
        const term = window.TerminalManager.terminals[key];
        const buffer = term.buffer.active;
        const lines = [];
        for (let row = 0; row < term.rows; row += 1) {
            lines.push(buffer.getLine(buffer.viewportY + row)?.translateToString(true) || '');
        }
        return { cols: term.cols, rows: term.rows, alt: buffer.type === 'alternate', lines };
    }, id);
}

async function waitScreen(page, id, predicate, message, timeout = 20_000, intervals = undefined) {
    let state;
    try {
        await expect.poll(async () => predicate(state = await screen(page, id)), { message, timeout, intervals }).toBe(true);
    } catch (error) {
        error.message += `\nLast screen ${state?.cols}x${state?.rows} alt=${state?.alt}:\n${state?.lines.join('\n')}`;
        throw error;
    }
    return state;
}

/** Wait until the terminal keeps one size across reads and the predicate holds. */
async function waitSettled(page, id, predicate, message, timeout = 20_000) {
    let previous = '';
    return waitScreen(page, id, current => {
        const size = `${current.cols}x${current.rows}`;
        const settled = size === previous;
        previous = size;
        return settled && predicate(current);
    }, message, timeout, [500]);
}

const shows = text => state => state.lines.some(line => line.includes(text));
// Herdr draws up to the last row and column it was given.
const fills = state => state.lines.slice(-3).some(line => line.trim())
    && state.lines.some(line => line.length >= state.cols - 2);
const leaked = state => state.lines.filter(line => LEAKED_REPLY.test(line));

/** Viewport position of a terminal cell centre. */
function cell(page, id, column, row) {
    return page.evaluate(([key, x, y]) => {
        const term = window.TerminalManager.terminals[key];
        const box = term.element.querySelector('.xterm-screen').getBoundingClientRect();
        return { x: box.left + (x + 0.5) * box.width / term.cols, y: box.top + (y + 0.5) * box.height / term.rows };
    }, [id, column, row]);
}

/** Start a saved host through the profile launcher and return the new terminal. */
async function launch(page, name) {
    const before = await sessionIds(page);
    const id = await profileId(page, name);
    await page.evaluate(profile => window.launchProfileForPane(profile), id);
    return finishConnection(page, before);
}

async function finishConnection(page, before) {
    await page.locator('#passwordInput').fill(PASSWORD);
    await page.locator('#connectBtn').click();
    // The lab's host key is confirmed once per application data directory.
    const accept = page.locator('#sshHostKeyAccept');
    let created;
    await expect.poll(async () => {
        if (await accept.isVisible()) await accept.click();
        created = (await sessionIds(page)).find(key => !before.includes(key));
        return Boolean(created);
    }, { message: 'a new terminal session', timeout: 20_000 }).toBe(true);
    return created;
}

/** Leave Herdr's first-run onboarding until its main view is shown. */
async function attached(page, id, mainView) {
    await page.evaluate(key => window.TerminalManager.terminals[key].focus(), id);
    await expect.poll(async () => {
        const state = await screen(page, id);
        const text = state.lines.join(' ');
        if (/esc close/.test(text)) await page.keyboard.press('Escape');
        else if (/↵ continue/.test(text)) await page.keyboard.press('Enter');
        else return state.alt && mainView(state);
        return false;
    }, { message: 'Herdr main view', timeout: 30_000, intervals: [300] }).toBe(true);
    return screen(page, id);
}

async function prefix(page, id, key) {
    await page.keyboard.press('Control+b');
    await waitScreen(page, id, shows('PREFIX'), 'Herdr prefix mode');
    await page.keyboard.press(key);
}

async function reconnectTab(page, id) {
    const before = await sessionIds(page);
    page.once('dialog', dialog => dialog.accept());
    const button = page.locator(`#tab-${id} .tab-reconnect`);
    if (await button.isVisible()) await button.click();
    else await page.evaluate(key => SessionManager.requestReconnect(key), id);
    await expect(page.locator('#passwordInput')).toBeVisible();
    return finishConnection(page, before.filter(key => key !== id));
}

async function closeTab(page, id) {
    page.once('dialog', dialog => dialog.accept());
    await page.evaluate(key => SessionManager.requestCloseSession(key), id);
    await expect.poll(() => page.evaluate(key => key in SessionManager.sessions, id)).toBe(false);
}

test.beforeEach(() => {
    expect(lab('reset').running).toBe(false);
});

test.afterEach(() => {
    lab('reset');
});

test('desktop: Herdr session mode is usable in the WebSSH terminal', async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await login(page);
    const id = await launch(page, 'Herdr agents');
    expect(await page.evaluate(key => SessionManager.sessions[key].useHerdr, id)).toBe(true);
    await expect(page.locator(`#tab-${id} .tab-herdr-badge`)).toBeVisible();

    // Rendering: alternate screen with Herdr's sidebar.
    let state = await attached(page, id, state => shows('agents')(state) && shows('spaces')(state));
    expect(state.alt).toBe(true);
    expect(leaked(state)).toEqual([]);
    await page.screenshot({ path: test.info().outputPath('desktop-attached.png') });

    // Keyboard input reaches the pane.
    await page.evaluate(key => window.TerminalManager.terminals[key].focus(), id);
    await page.keyboard.type('echo MARK-$((6*7))');
    await page.keyboard.press('Enter');
    state = await waitScreen(page, id, shows('MARK-42'), 'pane output');
    const first = lab('snapshot');
    expect(first).toMatchObject({ running: true, panes: 1, tabs: 1 });

    // Prefix: ctrl+b v splits the pane. The terminal consumes ctrl+b, so the
    // browser does not act on it (Firefox would open its bookmarks sidebar).
    await page.evaluate(() => {
        window.prefixKeys = [];
        // xterm also stops propagation, so read the outcome after dispatch.
        window.addEventListener('keydown', event => {
            if (event.ctrlKey && event.key.toLowerCase() === 'b') {
                setTimeout(() => window.prefixKeys.push(event.defaultPrevented));
            }
        }, true);
    });
    await prefix(page, id, 'v');
    await expect.poll(() => page.evaluate(() => window.prefixKeys)).toEqual([true]);
    await expect.poll(() => lab('snapshot').panes, { message: 'split through the prefix' }).toBe(2);
    await page.screenshot({ path: test.info().outputPath('desktop-split.png') });

    // Mouse: a click focuses the pane under the pointer.
    state = await screen(page, id);
    const row = state.lines.findIndex(line => line.includes('MARK-42'));
    let point = await cell(page, id, state.lines[row].indexOf('MARK-42') + 3, row + 2);
    await page.mouse.click(point.x, point.y);
    await expect.poll(() => lab('snapshot').focused, { message: 'left pane focused' }).toBe(first.focused);
    point = await cell(page, id, state.cols - 8, row + 2);
    await page.mouse.click(point.x, point.y);
    await expect.poll(() => lab('snapshot').focused, { message: 'right pane focused' }).not.toBe(first.focused);

    // Right click: Herdr gets it instead of the browser menu; Shift keeps the browser menu.
    await page.evaluate(() => {
        window.contextMenus = [];
        window.addEventListener('contextmenu', event => window.contextMenus.push(event.defaultPrevented));
    });
    point = await cell(page, id, state.cols - 12, row + 4);
    await page.keyboard.down('Shift');
    await page.mouse.click(point.x, point.y, { button: 'right' });
    await page.keyboard.up('Shift');
    await page.keyboard.press('Escape');
    // Firefox does not even deliver Shift+right click to the page.
    expect(await page.evaluate(() => window.contextMenus.includes(true))).toBe(false);
    await page.evaluate(() => { window.contextMenus = []; });
    const panesBeforeMenu = lab('snapshot').panes;
    await page.mouse.click(point.x, point.y, { button: 'right' });
    state = await waitScreen(page, id, shows('Split down'), 'Herdr pane menu');
    expect(await page.evaluate(() => window.contextMenus)).toEqual([true]);
    const menuRow = state.lines.findIndex(line => line.includes('Split down'));
    point = await cell(page, id, state.lines[menuRow].indexOf('Split down') + 3, menuRow);
    await page.mouse.click(point.x, point.y);
    await expect.poll(() => lab('snapshot').panes, { message: 'split from the pane menu' })
        .toBe(panesBeforeMenu + 1);
    await page.screenshot({ path: test.info().outputPath('desktop-menu-split.png') });

    // Resizing the window redraws Herdr at the new size and back.
    const before = { cols: state.cols, rows: state.rows };
    await page.setViewportSize({ width: 1100, height: 700 });
    state = await waitSettled(page, id, current => (current.cols < before.cols || current.rows < before.rows)
        && current.alt && fills(current), 'Herdr redrawn after shrinking');
    expect(leaked(state)).toEqual([]);
    const shrunk = { cols: state.cols, rows: state.rows };
    await page.setViewportSize({ width: 1440, height: 900 });
    state = await waitSettled(page, id, current => (current.cols > shrunk.cols || current.rows > shrunk.rows)
        && current.alt && fills(current), 'Herdr redrawn after growing');
    test.info().annotations.push({ type: 'resize', description:
        `${before.cols}x${before.rows} -> ${shrunk.cols}x${shrunk.rows} -> ${state.cols}x${state.rows}` });

    // A manual reconnect of the tab attaches to the same Herdr session.
    const marked = lab('workspace', 'reattach-mark');
    expect(marked).toMatchObject({ created: true, workspaces: [expect.anything(), 'reattach-mark'] });
    await waitScreen(page, id, shows('reattach-mark'), 'workspace marker in the sidebar');
    const reconnected = await reconnectTab(page, id);
    expect(await page.evaluate(key => SessionManager.sessions[key].useHerdr, reconnected)).toBe(true);
    state = await waitScreen(page, reconnected, current => current.alt && shows('reattach-mark')(current),
        'reattached Herdr session');
    expect(leaked(state)).toEqual([]);
    expect(lab('snapshot')).toMatchObject({ panes: marked.panes, tabs: marked.tabs, workspaces: marked.workspaces });
    await page.screenshot({ path: test.info().outputPath('desktop-reconnected.png') });

    // Closing the WebSSH session leaves the Herdr server running on the host.
    await closeTab(page, reconnected);
    expect(lab('snapshot')).toMatchObject({ running: true, panes: marked.panes, workspaces: marked.workspaces });
});

test.describe('mobile', () => {
    test.use(MOBILE);

    test('Herdr session mode renders, follows touch and rotation, and reconnects', async ({ page }) => {
        test.setTimeout(180_000);
        await login(page);
        const id = await launch(page, 'Herdr agents');

        // Rendering: the narrow terminal gets Herdr's compact layout.
        let state = await attached(page, id, shows('switch'));
        expect(state.alt).toBe(true);
        expect(leaked(state)).toEqual([]);
        await page.screenshot({ path: test.info().outputPath('mobile-attached.png') });

        // Touch: a tap focuses the tapped pane. The prefix needs a keyboard
        // with Ctrl on mobile, so the second pane comes from the Herdr CLI.
        const first = lab('snapshot');
        expect(lab('split')).toMatchObject({ split: true, panes: 2 });
        state = await waitScreen(page, id, current => current.lines.filter(line => /[│▏▕]/.test(line)).length
            >= current.rows / 3, 'split drawn');
        const middle = Math.floor(state.rows / 2);
        let point = await cell(page, id, 4, middle);
        await page.touchscreen.tap(point.x, point.y);
        await expect.poll(() => lab('snapshot').focused, { message: 'tapped left pane' }).toBe(first.focused);
        point = await cell(page, id, state.cols - 4, middle);
        await page.touchscreen.tap(point.x, point.y);
        await expect.poll(() => lab('snapshot').focused, { message: 'tapped right pane' }).not.toBe(first.focused);
        await page.screenshot({ path: test.info().outputPath('mobile-touch.png') });

        // Rotation to landscape and back redraws Herdr at each size.
        expect(lab('snapshot').panes).toBe(2);
        const portrait = { cols: state.cols, rows: state.rows };
        await page.setViewportSize({ width: 844, height: 390 });
        state = await waitSettled(page, id, current => current.cols > portrait.cols && current.alt && fills(current),
            'Herdr redrawn in landscape');
        const landscape = { cols: state.cols, rows: state.rows };
        await page.screenshot({ path: test.info().outputPath('mobile-landscape.png') });
        await page.setViewportSize({ width: 390, height: 844 });
        state = await waitSettled(page, id, current => current.rows > current.cols / 2
            && current.cols < landscape.cols && current.alt && fills(current), 'Herdr redrawn in portrait');
        expect(leaked(state)).toEqual([]);
        test.info().annotations.push({ type: 'rotation', description:
            `${portrait.cols}x${portrait.rows} -> ${landscape.cols}x${landscape.rows} -> ${state.cols}x${state.rows}` });

        // A manual reconnect of the tab attaches to the same Herdr session.
        const marked = lab('workspace', 'reattach-mark');
        expect(marked).toMatchObject({ created: true, panes: 3, workspaces: [expect.anything(), 'reattach-mark'] });
        const reconnected = await reconnectTab(page, id);
        expect(await page.evaluate(key => SessionManager.sessions[key].useHerdr, reconnected)).toBe(true);
        await waitScreen(page, reconnected, current => current.alt && shows('switch')(current), 'reattached Herdr');
        expect(lab('snapshot')).toMatchObject({ panes: marked.panes, tabs: marked.tabs, workspaces: marked.workspaces });
        await page.screenshot({ path: test.info().outputPath('mobile-reconnected.png') });

        await closeTab(page, reconnected);
        expect(lab('snapshot')).toMatchObject({ running: true, panes: marked.panes, workspaces: marked.workspaces });
    });
});

test('a host without Herdr gets a normal shell and one notice', async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await login(page);
    await page.evaluate(() => {
        window.herdrNotices = 0;
        new MutationObserver(records => {
            for (const record of records) {
                for (const node of record.addedNodes) {
                    if (node.textContent?.includes('Herdr was not found')) window.herdrNotices += 1;
                }
            }
        }).observe(document.getElementById('notificationContainer'), { childList: true });
    });
    const id = await launch(page, 'Herdr missing');
    expect(await page.evaluate(key => SessionManager.sessions[key].useHerdr, id)).toBe(false);
    await page.evaluate(key => window.TerminalManager.terminals[key].focus(), id);
    await page.keyboard.type("printf 'shell%s\\n' ready");
    await page.keyboard.press('Enter');
    const state = await waitScreen(page, id, shows('shellready'), 'normal shell output');
    expect(state.alt).toBe(false);
    await expect(page.locator('.notification', { hasText: 'Herdr was not found on 127.0.0.1' })).toHaveCount(1);
    await expect(page.locator(`#tab-${id} .tab-herdr-badge`)).toHaveCount(0);

    // Reconnecting the same host does not repeat the notice.
    const reconnected = await reconnectTab(page, id);
    await waitScreen(page, reconnected, current => current.lines.some(line => line.includes('$')), 'shell prompt');
    expect(await page.evaluate(() => window.herdrNotices)).toBe(1);
    await closeTab(page, reconnected);
});
