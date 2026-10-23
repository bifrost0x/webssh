const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

async function terminalFor(page, tmux) {
    await login(page);
    await page.evaluate(useTmux => {
        SessionManager.createSession({
            session_id: 'scroll-regression', host: 'scroll.example', port: 22,
            username: 'operator', display_name: 'Scroll regression', use_tmux: useTmux,
        });
        SessionManager.setSplitLayout(1);
        SessionManager.assignSessionToPane('scroll-regression', 0);
        SessionManager.setActivePane(0);
    }, tmux);
    await expect.poll(() => page.evaluate(() => (
        TerminalManager.terminalReady[TerminalManager.sessionTerminals['scroll-regression']?.[0]]
    ))).toBe(true);
    await page.evaluate(async useTmux => {
        const terminal = TerminalManager.terminals[TerminalManager.sessionTerminals['scroll-regression'][0]];
        window.__scrollInputs = [];
        terminal.onData(data => window.__scrollInputs.push(data));
        // The alternate screen and SGR mouse protocol requested by tmux mouse mode.
        const content = useTmux ? '\x1b[?1049h\x1b[?1000h\x1b[?1006h'
            : Array.from({length: 200}, (_, index) => `history ${index}`).join('\r\n');
        await new Promise(resolve => terminal.write(content, resolve));
    }, tmux);
}

test.afterEach(async ({page}) => { await assertNoExternalRequests(page); });

test('wheel reaches the tmux mouse protocol instead of shell history keys', async ({page}) => {
    await terminalFor(page, true);
    await page.locator('.terminal-pane.active .xterm-screen').hover();
    await page.mouse.wheel(0, -180);
    await expect.poll(() => page.evaluate(() => window.__scrollInputs.join(''))).toMatch(/\x1b\[<64;/);
    expect(await page.evaluate(() => window.__scrollInputs.join(''))).not.toMatch(/\x1b(?:\[A|OA)/);
});

test('ordinary shell wheel still scrolls local history without remote input', async ({page}) => {
    await terminalFor(page, false);
    const before = await page.evaluate(() => {
        const terminal = TerminalManager.terminals[TerminalManager.sessionTerminals['scroll-regression'][0]];
        terminal.scrollToBottom();
        return terminal.buffer.active.viewportY;
    });
    expect(before).toBeGreaterThan(0);
    await page.locator('.terminal-pane.active .xterm-screen').hover();
    await page.mouse.wheel(0, -180);
    await expect.poll(() => page.evaluate(() => (
        TerminalManager.terminals[TerminalManager.sessionTerminals['scroll-regression'][0]].buffer.active.viewportY
    ))).toBeLessThan(before);
    expect(await page.evaluate(() => window.__scrollInputs)).toEqual([]);
});

test.describe('touch tmux scrolling', () => {
    test.use({viewport: {width: 390, height: 844}, hasTouch: true, isMobile: true});
    test('swipe is forwarded as tmux wheel input', async ({page}) => {
        await terminalFor(page, true);
        await page.locator('.terminal-pane.active .xterm-screen').evaluate(screen => {
            const rect = screen.getBoundingClientRect();
            const options = {
                bubbles: true, cancelable: true, pointerType: 'touch', pointerId: 41,
                clientX: rect.x + rect.width / 2,
            };
            const surface = screen.closest('.xterm');
            for (const [type, offset] of [['pointerdown', 60], ['pointermove', 180], ['pointerup', 180]]) {
                surface.dispatchEvent(new PointerEvent(type, {...options, clientY: rect.y + offset}));
            }
        });
        await expect.poll(() => page.evaluate(() => window.__scrollInputs.join(''))).toMatch(/\x1b\[<64;/);
    });
});
