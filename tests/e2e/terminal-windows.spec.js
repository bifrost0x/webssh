const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

test.use({ viewport: { width: 1600, height: 960 } });

// Sessions are simulated: requests that name a "win-" session never reach the
// server, and resize and disconnect requests are recorded for assertions.
async function simulateSessions(page) {
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__windowEvents = [];
        window.socket.emit = function windowTestEmit(event, payload, ...rest) {
            const sessionId = payload?.session_id;
            if (typeof sessionId === 'string' && sessionId.startsWith('win-')) {
                window.__windowEvents.push({ event, payload });
                const acknowledge = rest.find(item => typeof item === 'function');
                acknowledge?.({ success: false, error: 'simulated session' });
                return window.socket;
            }
            return originalEmit(event, payload, ...rest);
        };
    });
}

async function connect(page, sessionId, host) {
    await page.evaluate(([id, hostName]) => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: id,
            host: hostName,
            port: 22,
            username: 'ops',
            client_request_id: `reconnect_${id}`,
        }));
    }, [sessionId, host]);
    await expect(page.locator(`#tab-${sessionId}`)).toBeVisible();
}

function windowFor(page, sessionId) {
    return page.locator('#terminalGrid > .ws-window').filter({
        has: page.locator(`#terminal-${sessionId}`),
    });
}

async function box(locator) {
    const rect = await locator.boundingBox();
    return {
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
    };
}

async function dragBy(page, handle, dx, dy) {
    const rect = await handle.boundingBox();
    const startX = rect.x + Math.min(30, rect.width / 2);
    const startY = rect.y + rect.height / 2;
    await page.mouse.move(startX, startY);
    await page.mouse.down();
    await page.mouse.move(startX + dx, startY + dy, { steps: 8 });
    await page.mouse.up();
}

async function enterWindowMode(page) {
    await login(page);
    await simulateSessions(page);
    await page.locator('.split-btn[data-layout="windows"]').click();
    await expect(page.locator('#terminalGrid')).toHaveClass(/window-mode/);
}

test('window mode opens one window per session from the tab rail', async ({ page }) => {
    await enterWindowMode(page);
    await expect(page.locator('.split-btn[data-layout="windows"]')).toHaveClass(/active/);
    await expect(page.locator('#windowArrangeControls')).toBeVisible();
    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(1);
    await expect(page.locator('.ws-window .ws-window-title')).toHaveText('New connection');
    await expect(page.locator('.ws-window .profile-launcher')).toBeVisible();

    await connect(page, 'win-alpha', 'alpha.example');
    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(1);
    await expect(windowFor(page, 'win-alpha').locator('.ws-window-title'))
        .toHaveText('ops@alpha.example');

    await page.locator('#newTabBtn').click();
    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(2);
    await expect(page.locator('.ws-window.is-focused .profile-launcher')).toBeVisible();
    await connect(page, 'win-beta', 'beta.example');
    await connect(page, 'win-gamma', 'gamma.example');

    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(3);
    await expect(windowFor(page, 'win-gamma')).toHaveClass(/is-focused/);
    await expect(page.locator('.terminal-pane.active .xterm-helper-textarea')).toBeAttached();
    expect(await page.evaluate(() => SessionManager.getActiveSession())).toBe('win-gamma');

    await page.locator('#tab-win-alpha .tab-label').click();
    await expect(windowFor(page, 'win-alpha')).toHaveClass(/is-focused/);
    expect(await page.evaluate(() => SessionManager.getActiveSession())).toBe('win-alpha');
    await assertNoExternalRequests(page);
});

test('windows drag, resize, maximize and snap on the desktop', async ({ page }) => {
    await enterWindowMode(page);
    await connect(page, 'win-alpha', 'alpha.example');
    const frame = windowFor(page, 'win-alpha');
    const desktop = await box(page.locator('#terminalGrid'));

    const start = await box(frame);
    await dragBy(page, frame.locator('.ws-window-heading'), -120, 60);
    await expect.poll(async () => (await box(frame)).x).toBe(start.x - 120);
    const moved = await box(frame);
    expect(moved.y).toBe(start.y + 60);

    const sizeBefore = await page.evaluate(() => {
        const terminal = TerminalManager.terminals['win-alpha'];
        return { cols: terminal.cols, rows: terminal.rows };
    });
    await dragBy(page, frame.locator('.ws-resize-se'), 140, 90);
    await expect.poll(async () => (await box(frame)).width).toBeGreaterThan(moved.width + 100);
    await expect.poll(() => page.evaluate(() => window.__windowEvents
        .filter(entry => entry.event === 'ssh_resize').length)).toBeGreaterThan(0);
    const resize = await page.evaluate(() => window.__windowEvents
        .filter(entry => entry.event === 'ssh_resize').at(-1).payload);
    expect(resize.cols).toBeGreaterThan(sizeBefore.cols);
    expect(resize.rows).toBeGreaterThan(sizeBefore.rows);
    const resized = await box(frame);

    await frame.locator('.ws-window-maximize').click();
    await expect(frame).toHaveClass(/is-maximized/);
    await expect.poll(async () => (await box(frame)).width).toBe(desktop.width - 2);
    await frame.locator('.ws-window-maximize').click();
    await expect(frame).not.toHaveClass(/is-maximized/);
    await expect.poll(async () => (await box(frame)).width).toBe(resized.width);

    await frame.locator('.ws-window-heading').dblclick();
    await expect(frame).toHaveClass(/is-maximized/);
    await frame.locator('.ws-window-heading').dblclick();
    await expect(frame).not.toHaveClass(/is-maximized/);

    await expect(frame).not.toHaveClass(/is-gliding/);
    const heading = await frame.locator('.ws-window-heading').boundingBox();
    await page.mouse.move(heading.x + 20, heading.y + heading.height / 2);
    await page.mouse.down();
    await page.mouse.move(desktop.x + desktop.width - 3, desktop.y + desktop.height / 2, { steps: 12 });
    await expect(page.locator('.ws-snap-preview')).toHaveClass(/is-visible/);
    await page.mouse.up();
    await expect(page.locator('.ws-snap-preview')).toBeHidden();
    await expect.poll(async () => {
        const snapped = await box(frame);
        return Math.abs(snapped.x + snapped.width - (desktop.x + desktop.width - 9)) <= 3
            && Math.abs(snapped.width - (desktop.width - 26) / 2) <= 4;
    }).toBe(true);
});

test('minimized windows wait on the tab rail and come back on click', async ({ page }) => {
    await enterWindowMode(page);
    await connect(page, 'win-alpha', 'alpha.example');
    await page.locator('#newTabBtn').click();
    await connect(page, 'win-beta', 'beta.example');

    const beta = windowFor(page, 'win-beta');
    await beta.locator('.ws-window-minimize').click();
    await expect(beta).toBeHidden();
    await expect(page.locator('#tab-win-beta')).toHaveClass(/is-minimized/);
    await expect(page.locator('#terminal-win-beta')).toHaveClass(/unassigned/);
    await expect.poll(() => page.evaluate(() => SessionManager.getActiveSession()))
        .toBe('win-alpha');

    await page.locator('#tab-win-beta .tab-label').click();
    await expect(beta).toBeVisible();
    await expect(beta).toHaveClass(/is-focused/);
    await expect(page.locator('#tab-win-beta')).not.toHaveClass(/is-minimized/);
    await expect(page.locator('#terminal-win-beta')).not.toHaveClass(/unassigned/);
});

test('arranging tiles every window and closing a window ends its session', async ({ page }) => {
    await enterWindowMode(page);
    for (const name of ['alpha', 'beta', 'gamma']) {
        if (name !== 'alpha') await page.locator('#newTabBtn').click();
        await connect(page, `win-${name}`, `${name}.example`);
    }

    await page.locator('[data-window-arrange="tile"]').click();
    await expect.poll(async () => {
        const rects = await page.locator('#terminalGrid > .ws-window').evaluateAll(frames => (
            frames.map(frame => frame.getBoundingClientRect().toJSON())
        ));
        return rects.every((a, index) => rects.every((b, other) => (
            index === other
            || a.right <= b.left + 1 || b.right <= a.left + 1
            || a.bottom <= b.top + 1 || b.bottom <= a.top + 1
        )));
    }).toBe(true);

    await page.locator('[data-window-arrange="cascade"]').click();
    await expect.poll(async () => new Set(await page.locator('#terminalGrid > .ws-window')
        .evaluateAll(frames => frames.map(frame => frame.style.left))).size).toBe(3);

    await windowFor(page, 'win-gamma').locator('.ws-window-close').click();
    await expect(page.locator('#tab-win-gamma')).toHaveCount(0);
    await expect(page.locator('#terminalGrid > .ws-window:not(.is-closing)')).toHaveCount(2);
    expect(await page.evaluate(() => window.__windowEvents.some(entry => (
        entry.event === 'ssh_disconnect' && entry.payload.session_id === 'win-gamma'
    )))).toBe(true);
});

test('split layouts take the front-most windows and window placement returns', async ({ page }) => {
    await enterWindowMode(page);
    await connect(page, 'win-alpha', 'alpha.example');
    await page.locator('#newTabBtn').click();
    await connect(page, 'win-beta', 'beta.example');
    await dragBy(page, windowFor(page, 'win-alpha').locator('.ws-window-heading'), 90, 40);
    const placed = await box(windowFor(page, 'win-alpha'));

    await page.locator('.split-btn[data-layout="2"]').click();
    await expect(page.locator('#terminalGrid')).toHaveClass(/split-2/);
    await expect(page.locator('.ws-window')).toHaveCount(0);
    await expect(page.locator('.terminal-pane[data-pane-index="0"] #terminal-win-alpha')).toBeAttached();
    await expect(page.locator('.terminal-pane[data-pane-index="1"] #terminal-win-beta')).toBeAttached();
    expect(await page.evaluate(() => localStorage.getItem('webssh.workspace.windowMode'))).toBe('off');

    await page.locator('.split-btn[data-layout="windows"]').click();
    await expect.poll(async () => box(windowFor(page, 'win-alpha'))).toEqual(placed);
});

test('window mode survives a reload and steps aside on phones', async ({ page }) => {
    await enterWindowMode(page);
    await page.reload();
    await expect(page.locator('#terminalGrid')).toHaveClass(/window-mode/);

    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.locator('#terminalGrid')).toHaveClass(/split-1/);
    await expect(page.locator('.ws-window')).toHaveCount(0);

    await page.setViewportSize({ width: 1600, height: 960 });
    await expect(page.locator('#terminalGrid')).toHaveClass(/window-mode/);
});

test('keyboard window focus selects the correct session and supports move and resize', async ({page}) => {
    await enterWindowMode(page);
    await connect(page, 'win-alpha', 'alpha.example');
    await connect(page, 'win-beta', 'beta.example');
    const frame = windowFor(page, 'win-alpha');
    await frame.locator('.ws-window-titlebar').focus();
    expect(await page.evaluate(() => SessionManager.getActiveSession())).toBe('win-alpha');
    const before = await box(frame);
    await page.keyboard.press('ArrowRight');
    await expect.poll(async () => (await box(frame)).x).toBe(before.x + 16);
    await page.keyboard.press('Alt+ArrowRight');
    await expect.poll(async () => (await box(frame)).width).toBe(before.width + 16);
    await page.keyboard.press('Enter');
    await expect(frame).toHaveClass(/is-maximized/);
    await page.keyboard.press('Enter');
    await expect(frame).not.toHaveClass(/is-maximized/);
});

test('footer uses the selected connection and the actual transfer queue, including disconnects', async ({page}) => {
    await enterWindowMode(page);
    await connect(page, 'win-alpha', 'alpha.example');
    await expect(page.locator('#workspaceStatusTarget')).toHaveText('alpha.example:22');
    await expect(page.locator('#workspaceStatusUser')).toHaveText('ops');
    await expect(page.locator('#workspaceStatusState')).toHaveText('Connected');
    await expect(page.locator('#workspaceStatusTrust')).toHaveCount(0);
    await page.evaluate(() => {
        window.sftpFileManager.transferQueue = [{id: 'content-check', status: 'complete', name: 'file.txt'}];
        window.dispatchEvent(new Event('file-transfer-queue-change'));
        SessionManager.updateSessionStatus('win-alpha', 'disconnected');
    });
    await expect(page.locator('#workspaceStatusTransferCount')).toHaveText('1');
    await expect(page.locator('#workspaceStatusState')).toHaveText('Session disconnected');
    await page.evaluate(() => {
        SessionManager.updateSessionStatus('win-alpha', 'connected');
        window.socket.connected = false;
        window.socket.listeners('disconnect').forEach(fn => fn('transport close'));
    });
    await expect(page.locator('#workspaceStatusState')).not.toHaveClass(/connected/);
    await expect(page.locator('#workspaceStatusState')).toHaveText('Connection lost. Reconnecting...');
});

test('window layout retains each restored session and its placement after reload', async ({page}) => {
    await enterWindowMode(page);
    const seeded = await page.evaluate(() => new Promise(resolve => window.socket.emit('e2e_workspace_restore', {count: 3}, resolve)));
    expect(seeded.ok).toBe(true);
    try {
        await page.reload();
        await page.locator('#workspaceNavBtn').click();
        await expect(page.locator('.session-tab')).toHaveCount(3);
        await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(3);
        const id = await page.evaluate(() => SessionManager.getAllSessions()[0].id);
        await page.locator(`#tab-${id}`).click();
        const frame = windowFor(page, id);
        await frame.locator('.ws-window-maximize').click();
        await expect(frame).toHaveClass(/is-maximized/);
        await page.evaluate(() => AuthSessionGuard.saveRestore(window, document, sessionStorage));
        await page.reload();
        await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'workspaces');
        await expect(page.locator('.session-tab')).toHaveCount(3);
        await expect(windowFor(page, id)).toHaveClass(/is-maximized/);
        await page.locator('#contextCommandsTab').click();
        await expect(page.locator('.session-command-results')).toContainText('E2E command');
    } finally {
        await page.evaluate(() => new Promise(resolve => window.socket.emit('e2e_workspace_restore', {count: 0}, resolve)));
    }
});

for (const [language, label] of Object.entries({en: 'Minimize', de: 'Minimieren', vi: 'Thu nhỏ', fr: 'Réduire', es: 'Minimizar', zh: '最小化'})) {
    test(`window controls and live content remain translated in ${language}`, async ({page}) => {
        await enterWindowMode(page);
        await connect(page, 'win-alpha', 'alpha.example');
        await page.evaluate(lang => i18n.setLanguage(lang), language);
        await expect(windowFor(page, 'win-alpha').locator('.ws-window-minimize')).toHaveAttribute('aria-label', label);
        await expect(page.locator('#workspaceStatusTarget')).toHaveText('alpha.example:22');
        await expect(page.locator('#workspaceStatusUser')).toHaveText('ops');
        await assertNoExternalRequests(page);
    });
}

for (const theme of ['glass', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'obsidian', 'retro', 'cyberpunk-neon', 'emerald-matrix']) {
    test(`window frames inherit ${theme} and keep terminal content mounted`, async ({page}, testInfo) => {
        await enterWindowMode(page);
        await connect(page, 'win-alpha', 'alpha.example');
        await connect(page, 'win-beta', 'beta.example');
        await page.evaluate(theme => {
            document.body.dataset.theme = theme;
            TerminalManager.applyThemeToAll();
            TerminalManager.terminals['win-alpha'].write('ops@alpha:~$ pwd\r\n/home/ops\r\n');
        }, theme);
        await page.locator('[data-window-arrange="tile"]').click();
        const frame = windowFor(page, 'win-alpha');
        await expect(frame).toBeVisible();
        await expect(frame).not.toHaveClass(/is-gliding/);
        const colors = await frame.locator('.ws-window-titlebar').evaluate(el => {
            const style = getComputedStyle(el);
            return {foreground: style.color, background: style.backgroundColor};
        });
        expect(colors.foreground).not.toBe(colors.background);
        expect(await page.evaluate(() => document.querySelectorAll('#terminal-win-alpha').length)).toBe(1);
        await expect(page.locator('.ws-window .xterm')).toHaveCount(2);
        if (['glass', 'paper', 'cyberpunk-neon'].includes(theme)) {
            await page.screenshot({path: testInfo.outputPath(`${theme}-windows.png`)});
        }
        await assertNoExternalRequests(page);
    });
}

test('dense tiling never overlaps windows even when cells are smaller than manual resize limits', async ({page}) => {
    await page.setViewportSize({width: 1280, height: 800});
    await enterWindowMode(page);
    for (let index = 0; index < 12; index++) await connect(page, `win-${index}`, `host-${index}.example`);
    await page.locator('[data-window-arrange="tile"]').click();
    await expect(page.locator('.ws-window.is-gliding')).toHaveCount(0);
    const rectangles = await page.locator('#terminalGrid > .ws-window').evaluateAll(elements => elements.map(el => {
        const {x, y, width, height} = el.getBoundingClientRect();
        return {x, y, width, height};
    }));
    expect(rectangles).toHaveLength(12);
    for (let i = 0; i < rectangles.length; i++) {
        for (let j = i + 1; j < rectangles.length; j++) {
            const a = rectangles[i], b = rectangles[j];
            expect(a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y).toBe(true);
        }
    }
    expect(await page.evaluate(() => Object.keys(SessionManager.sessions).length)).toBe(12);
    await page.setViewportSize({width: 1280, height: 500});
    await expect(page.locator('#terminalGrid')).toHaveClass(/split-1/);
    expect(await page.evaluate(() => Object.keys(SessionManager.sessions).length)).toBe(12);
});

test('plus creates another window even while an empty host launcher is open', async ({page}) => {
    await login(page);
    await page.locator('[data-layout="windows"]').click();
    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(1);
    await page.locator('#newTabBtn').click();
    await expect(page.locator('#terminalGrid > .ws-window')).toHaveCount(2);
});

test('dragging beyond an edge and resizing the workspace keep complete windows visible', async ({page}) => {
    await enterWindowMode(page);
    await connect(page, 'win-boundary', 'boundary.example');
    const frame = windowFor(page, 'win-boundary');
    await dragBy(page, frame.locator('.ws-window-titlebar'), -1300, 200);
    await page.setViewportSize({width: 980, height: 700});
    await expect.poll(() => page.evaluate(() => {
        const grid = document.getElementById('terminalGrid');
        const bounds = grid.getBoundingClientRect();
        return [...grid.querySelectorAll(':scope > .ws-window:not([hidden])')].every(node => {
            const r = node.getBoundingClientRect();
            return r.left >= bounds.left && r.top >= bounds.top
                && r.right <= bounds.right + 1 && r.bottom <= bounds.bottom + 1;
        });
    })).toBe(true);
    await page.screenshot({path: test.info().outputPath('contained-windows.png')});
});
