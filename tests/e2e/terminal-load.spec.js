const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

// Measure the transport/renderer rather than trace snapshot overhead.
test.use({ trace: 'off', viewport: { width: 1920, height: 1080 } });

test.afterEach(async ({ page }) => {
    await page.evaluate(() => { window.socket?.disconnect(); });
});

for (const transport of ['polling', 'websocket']) {
    test(`20 active TUIs retain state without reconnecting over ${transport}`, async ({ page }) => {
        test.setTimeout(60000);
        await page.route('**/static/js/app.js?*', async route => {
            const response = await route.fetch();
            const body = (await response.text()).replace('autoConnect: false,',
                `autoConnect: false, transports: ['${transport}'], upgrade: false,`);
            await route.fulfill({ response, body });
        });
        const networkFailures = [];
        let maxPollingPackets = 0;
        page.on('requestfailed', request => networkFailures.push({
            url: request.url(), error: request.failure()?.errorText,
        }));
        page.on('request', request => {
            if (request.method() === 'POST' && request.url().includes('/socket.io/')) {
                maxPollingPackets = Math.max(maxPollingPackets, (request.postData() || '').split('\x1e').length);
            }
        });
        await login(page);
        await expect.poll(() => page.evaluate(() => window.socket.io.engine.transport.name)).toBe(transport);
        await page.evaluate(() => {
            window.__loadDisconnects = [];
            window.__loadDone = null;
            window.__loadAcks = 0;
            window.__loadReceived = 0;
            const handle = TerminalManager.handleSocketOutput.bind(TerminalManager);
            TerminalManager.handleSocketOutput = (data, ack) => {
                window.__loadReceived++;
                return handle(data, () => { window.__loadAcks++; ack?.(); });
            };
            window.socket.on('disconnect', (reason, details) => window.__loadDisconnects.push({
                reason, message: details?.message, description: details?.description,
            }));
            window.socket.on('e2e_output_load_done', result => { window.__loadDone = result; });
            for (let i = 0; i < 20; i++) {
                SessionManager.createSession({ session_id: `load-${i}`, host: 'fixture.local',
                    username: 'fixture', port: 22, connected: true });
            }
        });
        await page.evaluate(() => SessionManager.switchSession('load-0'));
        await expect.poll(() => page.evaluate(() => Object.values(TerminalManager.terminalReady)
            .filter(Boolean).length)).toBe(20);
        await page.evaluate(() => new Promise(resolve => window.socket.emit('e2e_output_load', resolve)));
        // Reproduce an ordinary main-thread pause followed by a burst of real ACKs.
        await page.evaluate(() => { const until = performance.now() + 300; while (performance.now() < until) {} });
        await expect.poll(() => page.evaluate(() => window.__loadDone), { timeout: 45000 }).not.toBeNull().catch(async error => {
            console.log('NETWORK DIAGNOSTICS', { networkFailures, maxPollingPackets });
            console.log('LOAD DIAGNOSTICS', await page.evaluate(() => ({ acks: window.__loadAcks,
                received: window.__loadReceived, disconnects: window.__loadDisconnects,
                sequences: TerminalManager.lastOutputSequences,
                callbacks: Object.fromEntries(Object.entries(TerminalManager.terminalWriteCallbacks).map(([key, callbacks]) => [key, callbacks.size])) })));
            throw error;
        });
        const result = await page.evaluate(() => ({
            done: window.__loadDone, disconnects: window.__loadDisconnects,
            acks: window.__loadAcks, received: window.__loadReceived,
        }));
        // A producer watchdog abort must be distinguished from missing renderer
        // ACKs. Keep this bounded completion record even when a later check fails.
        console.log('TUI LOAD COMPLETION', JSON.stringify({transport, ...result, disconnects: result.disconnects.slice(0, 5)}));
        expect(result.done.aborted).toBe(false);
        expect(result.done.counts).toEqual(Array(20).fill(240));
        expect(maxPollingPackets).toBeLessThanOrEqual(16);
        expect(result.done.peak).toBeLessThanOrEqual(8);
        expect(result.done.peak).toBeGreaterThan(0);
        await expect.poll(() => page.evaluate(() => window.__loadAcks)).toBe(4800);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(1920);
        expect(result.disconnects).toEqual([]);
        for (const index of [0, 10, 19]) {
            await page.evaluate(i => SessionManager.switchSession(`load-${i}`), index);
            await expect.poll(() => page.evaluate(i => {
                const terminal = TerminalManager.terminals[`load-${i}`];
                return { text: terminal.buffer.active.getLine(0).translateToString(true).slice(0, `stream-${i} frame-240 END`.length),
                    mode: terminal.buffer.active.type, paste: terminal.modes.bracketedPasteMode,
                    cursor: terminal.modes.applicationCursorKeysMode };
            }, index)).toEqual({ text: `stream-${index} frame-240 END`,
                mode: 'alternate', paste: true, cursor: true });
        }
    });
}
