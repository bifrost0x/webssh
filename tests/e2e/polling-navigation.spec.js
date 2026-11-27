const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

test.afterEach(async ({ page }, testInfo) => {
    // Browser-context disposal does not guarantee a polling close packet. Release
    // the surviving channel so later cases do not consume its admission slot.
    if (!testInfo.title.includes('polling channel') && !testInfo.title.startsWith('polling ')) return;
    if (page.isClosed() || !await page.evaluate(() => Boolean(window.socket?.connected))) return;
    await page.unroute('**/socket.io/**');
    const closed = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname.startsWith('/socket.io/')
        && (response.request().postData() || '').split('\x1e').includes('1'));
    await page.evaluate(() => window.socket.disconnect());
    expect((await closed).ok()).toBe(true);
});

test('polling reconnects after an aborted request without a redundant close POST', async ({ page }) => {
    await page.route('**/static/js/app.js?*', async route => {
        const response = await route.fetch();
        const source = await response.text();
        expect(source.match(/autoConnect: false,/g)).toHaveLength(1);
        await route.fulfill({ response, body: source.replace('autoConnect: false,',
            "autoConnect: false, transports: ['polling'], upgrade: false,") });
    });
    await login(page);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const oldSid = await page.evaluate(() => {
        window.pollingReconnectErrors = [];
        window.socket.io.engine.on('error', error => window.pollingReconnectErrors.push({
            message: error.message, status: error.description,
        }));
        return window.socket.io.engine.id;
    });
    const closePosts = [];
    page.on('request', request => {
        const url = new URL(request.url());
        if (url.pathname.startsWith('/socket.io') && url.searchParams.get('sid') === oldSid
            && request.method() === 'POST' && request.postData() === '1') closePosts.push(request.url());
    });
    let aborted = false;
    await page.route('**/socket.io/**', async route => {
        const request = route.request();
        if (!aborted && request.method() === 'GET'
            && new URL(request.url()).searchParams.get('sid') === oldSid) {
            aborted = true;
            await route.abort('failed');
        } else await route.continue();
    });
    // Complete the outstanding poll so its successor exercises the real failure.
    await page.evaluate(() => window.socket.emit('e2e_workspace_restore', { count: 0 }, () => {}));
    await expect.poll(() => aborted).toBe(true);
    await expect.poll(() => page.evaluate(previous => Boolean(window.socket.connected
        && window.socket.io.engine.id && window.socket.io.engine.id !== previous), oldSid)).toBe(true);
    const response = await page.evaluate(() => new Promise(resolve => {
        window.socket.timeout(3000).emit('e2e_workspace_restore', { count: 0 }, (error, result) => {
            resolve({ error: Boolean(error), ok: result?.ok });
        });
    }));
    expect(response).toEqual({ error: false, ok: true });
    expect(await page.evaluate(() => window.pollingReconnectErrors))
        .toEqual([{ message: 'xhr poll error', status: 0 }]);
    expect(closePosts).toEqual([]);
    expect(errors).toEqual([]);
});

test('cancelled reload preserves the draft and a working polling channel', async ({ page }) => {
    await page.route('**/static/js/app.js?*', async route => {
        const response = await route.fetch();
        const source = await response.text();
        expect(source.match(/autoConnect: false,/g)).toHaveLength(1);
        await route.fulfill({
            response,
            body: source.replace('autoConnect: false,',
                "autoConnect: false, transports: ['polling'], upgrade: false,"),
        });
    });
    await login(page);
    const checkChannel = () => page.evaluate(() => new Promise(resolve => {
        window.socket.timeout(3000).emit('e2e_workspace_restore', { count: 0 }, (error, result) => {
            resolve({ error: Boolean(error), ok: result?.ok });
        });
    }));
    expect(await checkChannel()).toEqual({ error: false, ok: true });

    await page.locator('#commandLibraryBtn').click();
    await page.locator('#addCommandBtn').click();
    const draft = page.locator('#commandFormName');
    await draft.fill('Keep this draft');
    const cancelled = page.waitForEvent('dialog').then(async dialog => {
        expect(dialog.type()).toBe('beforeunload');
        await dialog.dismiss();
    });
    await page.evaluate(() => setTimeout(() => location.reload(), 0));
    await cancelled;

    await expect(page).toHaveURL(/\/$/);
    await expect(draft).toHaveValue('Keep this draft');
    expect(await checkChannel()).toEqual({ error: false, ok: true });
});

// The same behaviour on the transport the page actually uses, so that it
// holds for a server without long polling (ADR 0005): the Socket.IO
// upgrade of the Python release and the WebSocket endpoint of the Go
// release are both reached through page.routeWebSocket.
const realtimeSocket = /\/(socket\.io\/\?.*transport=websocket|ws(\?.*)?$)/;

const channelWorks = page => page.evaluate(() => new Promise(resolve => {
    window.socket.timeout(3000).emit('e2e_workspace_restore', { count: 0 }, (error, result) => {
        resolve({ error: Boolean(error), ok: result?.ok });
    });
}));

test('the realtime channel reconnects after its connection drops', async ({ page }) => {
    const sockets = [];
    await page.routeWebSocket(realtimeSocket, ws => {
        ws.connectToServer();
        sockets.push(ws);
    });
    await login(page);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await expect.poll(() => sockets.length).toBeGreaterThan(0);
    expect(await channelWorks(page)).toEqual({ error: false, ok: true });
    const opened = sockets.length;
    await sockets.at(-1).close({ code: 1001, reason: 'going away' });
    await expect.poll(() => sockets.length).toBeGreaterThan(opened);
    await expect.poll(() => page.evaluate(() => window.socket.connected)).toBe(true);
    expect(await channelWorks(page)).toEqual({ error: false, ok: true });
    expect(errors).toEqual([]);
});

test('cancelled reload preserves the draft and a working realtime channel', async ({ page }) => {
    await login(page);
    expect(await channelWorks(page)).toEqual({ error: false, ok: true });

    await page.locator('#commandLibraryBtn').click();
    await page.locator('#addCommandBtn').click();
    const draft = page.locator('#commandFormName');
    await draft.fill('Keep this draft');
    const cancelled = page.waitForEvent('dialog').then(async dialog => {
        expect(dialog.type()).toBe('beforeunload');
        await dialog.dismiss();
    });
    await page.evaluate(() => setTimeout(() => location.reload(), 0));
    await cancelled;

    await expect(page).toHaveURL(/\/$/);
    await expect(draft).toHaveValue('Keep this draft');
    expect(await channelWorks(page)).toEqual({ error: false, ok: true });
});
