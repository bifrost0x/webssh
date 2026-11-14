const {test, expect} = require('playwright/test');
const {login, openWorkspace, installSshConnectTrap, assertNoExternalRequests} = require('./helpers');
const path = require('node:path');
const fs = require('node:fs');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

async function savePresets(page, presets) {
    const response = await page.request.put('/api/account/workspace-presets', {
        headers: {'X-CSRFToken': await page.locator('meta[name="csrf-token"]').getAttribute('content')},
        data: {presets}
    });
    expect(response.ok()).toBe(true);
}

async function addExistingSessions(page, count = 1) {
    await page.evaluate(count => {
        const original = window.socket.emit.bind(window.socket);
        window.__presetSessionEvents = [];
        window.socket.emit = (event, payload, ...rest) => {
            if (payload?.session_id?.startsWith('preset-live-')) {
                window.__presetSessionEvents.push(event);
                return window.socket;
            }
            return original(event, payload, ...rest);
        };
        for (let index = 0; index < count; index++) {
            const id = 'preset-live-' + index;
            window.socket.listeners('ssh_connected').forEach(listener => listener({
                session_id: id, host: 'lab.example', port: 22, username: 'ops',
                client_request_id: 'reconnect_' + id
            }));
            TerminalManager.writeOutput(id, 'ops@lab:~$ ');
        }
        window.__presetTerminal = document.getElementById('terminal-preset-live-0');
    }, count);
}

for (const width of [1440, 390]) {
    test(`named presets apply directly by keyboard and preserve terminals at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await installSshConnectTrap(page);
        const host = await page.evaluate(() => ProfileManager.profiles[0].id);
        const name = '<img src=x onerror=alert(1)> ' + 'Workspace'.repeat(5);
        await savePresets(page, [
            {id: 'single', name, layout: 1, profile_ids: [host]},
            {id: 'split', name: 'Operations split', layout: 2, profile_ids: []}
        ]);
        const picker = page.locator('#workspaceLayoutPicker');
        const summary = picker.locator('summary');
        await summary.click();
        await picker.locator('.split-btn[data-layout="4"]').click();
        await summary.focus();
        await page.keyboard.press('Enter');
        const preset = picker.getByRole('button', {name, exact: true});
        await expect(preset).toBeVisible();
        await expect(picker.locator('#workspacePresetOptions img')).toHaveCount(0);
        await expect(picker.getByRole('button', {name: 'Operations split', exact: true})).toBeVisible();
        await preset.focus();
        const bounds = await preset.boundingBox();
        expect(bounds.x).toBeGreaterThanOrEqual(0);
        expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
        expect(await preset.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
        const folder = path.join(process.cwd(), 'plans', 'workspace-preset-dropdown');
        fs.mkdirSync(folder, {recursive: true});
        await page.screenshot({path: path.join(folder, `dropdown-${width}.png`)});
        await page.keyboard.press('Enter');
        await expect(picker).not.toHaveAttribute('open', '');
        await expect(summary).toBeFocused();
        await expect(page.getByRole('dialog')).toHaveCount(0);
        expect(await page.evaluate(() => SessionManager.layout)).toBe(1);

        await page.evaluate(() => SessionManager.applyPaneAssignments(4, [null, null, null, null]));
        await addExistingSessions(page);
        await page.evaluate(() => SessionManager.applyPaneAssignments(4, [null, null, null, 'preset-live-0']));
        await summary.click();
        await expect(preset).toBeEnabled();
        await preset.click();
        await expect(page.locator('#terminal-preset-live-0')).toBeVisible();
        expect(await page.evaluate(() => ({
            layout: SessionManager.layout,
            slots: SessionManager.paneAssignments,
            sameTerminal: window.__presetTerminal === document.getElementById('terminal-preset-live-0'),
            sessionEvents: window.__presetSessionEvents.filter(event => ['ssh_disconnect', 'ssh_input'].includes(event)),
            connections: window.__sshConnectAttempts
        }))).toEqual({layout: 1, slots: ['preset-live-0'], sameTerminal: true, sessionEvents: [], connections: []});
        await summary.click();
        await page.keyboard.press('Escape');
        await expect(summary).toBeFocused();
        await expect(picker).not.toHaveAttribute('open', '');
    });
}

test('saving, reloading, removing and other-tab changes update dropdown presets', async ({page}) => {
    await login(page);
    await savePresets(page, []);
    const picker = page.locator('#workspaceLayoutPicker');
    const options = page.locator('#workspacePresetOptions');
    await picker.locator('summary').click();
    await picker.locator('#workspacePresetsBtn').click();
    let dialog = page.getByRole('dialog', {name: 'Workspace presets', exact: true});
    await dialog.getByLabel('Preset name', {exact: true}).fill('Morning checks');
    await dialog.getByLabel('Panes', {exact: true}).selectOption('2');
    await dialog.getByRole('button', {name: 'Save preset', exact: true}).click();
    await expect(dialog.getByRole('status')).toHaveText('Preset saved.');
    await expect(options.locator('.workspace-preset-name')).toHaveText(['Morning checks']);
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await page.reload();
    await openWorkspace(page);
    await picker.locator('summary').click();
    await expect(options.getByRole('button', {name: 'Morning checks', exact: true})).toBeVisible();
    await picker.locator('#workspacePresetsBtn').click();
    dialog = page.getByRole('dialog', {name: 'Workspace presets', exact: true});
    await dialog.getByRole('button', {name: 'Remove preset', exact: true}).click();
    await expect(dialog.getByText('No presets yet. Save a layout and host selection below.')).toBeVisible();
    await expect(options.locator('button[data-workspace-preset-id]')).toHaveCount(0);
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await savePresets(page, [{id: 'external', name: 'Saved in another tab', layout: 4, profile_ids: []}]);
    await picker.locator('summary').click();
    await expect(options.getByRole('button', {name: 'Saved in another tab', exact: true})).toBeVisible();
    await picker.locator('summary').click();
    await savePresets(page, [{id: 'external', name: 'Renamed elsewhere', layout: 1, profile_ids: []}]);
    await picker.locator('summary').click();
    await expect(options.getByRole('button', {name: 'Renamed elsewhere', exact: true})).toBeVisible();
    await expect(options.getByRole('button', {name: 'Saved in another tab', exact: true})).toHaveCount(0);
});

test('failed preset loading offers retry while built-in layouts remain usable', async ({page}) => {
    await login(page);
    let fail = true;
    await page.route('**/api/account/workspace-presets', route => route.fulfill(fail
        ? {status: 503, json: {error: 'Temporarily unavailable'}}
        : {json: {presets: [{id: 'retry', name: 'Recovered preset', layout: 2, profile_ids: []}]}}
    ));
    const picker = page.locator('#workspaceLayoutPicker');
    await picker.locator('summary').click();
    await expect(picker.getByRole('alert')).toBeVisible();
    await picker.locator('.split-btn[data-layout="4"]').click();
    expect(await page.evaluate(() => SessionManager.layout)).toBe(4);
    await picker.locator('summary').click();
    const retry = picker.getByRole('button', {name: 'Retry', exact: true});
    await expect(retry).toBeVisible();
    fail = false;
    await retry.click();
    const preset = picker.getByRole('button', {name: 'Recovered preset', exact: true});
    await expect(preset).toBeVisible();
    await expect(preset).toBeFocused();
    await expect(picker.getByRole('alert')).toHaveCount(0);
    await preset.click();
    expect(await page.evaluate(() => SessionManager.layout)).toBe(2);
});

test('pending refresh disables old presets until current account choices arrive', async ({page}) => {
    await login(page);
    await savePresets(page, [{id: 'old', name: 'Old choice', layout: 1, profile_ids: []}]);
    const picker = page.locator('#workspaceLayoutPicker');
    await picker.locator('summary').click();
    await expect(picker.getByRole('button', {name: 'Old choice', exact: true})).toBeVisible();
    await picker.locator('summary').click();
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    await page.route('**/api/account/workspace-presets', async route => {
        await pending;
        await route.fulfill({json: {presets: [{id: 'new', name: 'Current choice', layout: 2, profile_ids: []}]}});
    });
    try {
        await picker.locator('summary').click();
        await expect(picker.getByRole('status')).toBeVisible();
        await expect(picker.getByRole('button', {name: 'Old choice', exact: true})).toBeDisabled();
    } finally {
        release();
    }
    await expect(picker.getByRole('button', {name: 'Current choice', exact: true})).toBeEnabled();
    await expect(picker.getByRole('button', {name: 'Old choice', exact: true})).toHaveCount(0);
});

test('failed manager saves never add unsaved choices to the layout menu', async ({page}) => {
    await login(page);
    await savePresets(page, [{id: 'saved', name: 'Existing preset', layout: 1, profile_ids: []}]);
    const picker = page.locator('#workspaceLayoutPicker');
    await picker.locator('summary').click();
    await expect(picker.getByRole('button', {name: 'Existing preset', exact: true})).toBeVisible();
    await picker.locator('#workspacePresetsBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Workspace presets', exact: true});
    await dialog.getByLabel('Preset name', {exact: true}).fill('Unsaved choice');
    await page.route('**/api/account/workspace-presets', route => route.request().method() === 'PUT'
        ? route.fulfill({status: 503, json: {error: 'Temporarily unavailable'}})
        : route.continue());
    await dialog.getByRole('button', {name: 'Save preset', exact: true}).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
    await expect(dialog.getByRole('button', {name: 'Save preset', exact: true})).toBeEnabled();
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await picker.locator('summary').click();
    await expect(picker.getByRole('button', {name: 'Existing preset', exact: true})).toBeVisible();
    await expect(picker.getByRole('button', {name: 'Unsaved choice', exact: true})).toHaveCount(0);
});

test('a delayed refresh cannot replace a newly saved preset with old data', async ({page}) => {
    await login(page);
    const previous = [{id: 'existing', name: 'Existing choice', layout: 1, profile_ids: []}];
    await savePresets(page, previous);
    const picker = page.locator('#workspaceLayoutPicker');
    const names = picker.locator('.workspace-preset-name');
    await picker.locator('summary').click();
    await picker.locator('#workspacePresetsBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Workspace presets', exact: true});
    await dialog.getByLabel('Preset name', {exact: true}).fill('Newly saved choice');
    let releaseSave, releaseLoad, markLoadStarted;
    const pendingSave = new Promise(resolve => { releaseSave = resolve; });
    const pendingLoad = new Promise(resolve => { releaseLoad = resolve; });
    const loadStarted = new Promise(resolve => { markLoadStarted = resolve; });
    await page.route('**/api/account/workspace-presets', async route => {
        if (route.request().method() === 'PUT') {
            await pendingSave;
            await route.fulfill({json: {presets: route.request().postDataJSON().presets}});
        } else {
            markLoadStarted();
            await pendingLoad;
            await route.fulfill({json: {presets: previous}});
        }
    });
    try {
        await dialog.getByRole('button', {name: 'Save preset', exact: true}).click();
        await expect(dialog.getByRole('button', {name: 'Save preset', exact: true})).toBeDisabled();
        await dialog.getByRole('button', {name: 'Close', exact: true}).click();
        await picker.locator('summary').click();
        await loadStarted;
        releaseSave();
        await expect(names).toHaveText(['Existing choice', 'Newly saved choice']);
        const saved = picker.getByRole('button', {name: 'Newly saved choice', exact: true});
        await saved.focus();
        const response = page.waitForResponse(result => result.url().endsWith('/api/account/workspace-presets') && result.request().method() === 'GET');
        releaseLoad();
        await (await response).finished();
        await expect(saved).toBeVisible();
        await expect(saved).toBeFocused();
        await expect(names).toHaveText(['Existing choice', 'Newly saved choice']);
    } finally {
        releaseSave();releaseLoad();
    }
});

test('a preset refuses to discard more than four floating sessions', async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await installSshConnectTrap(page);
    await savePresets(page, [{id: 'single', name: 'Single saved layout', layout: 1, profile_ids: []}]);
    await page.evaluate(() => SessionManager.setWindowMode(true));
    await addExistingSessions(page, 5);
    expect(await page.evaluate(() => SessionManager.paneAssignments.filter(Boolean).length)).toBe(5);
    const before = await page.evaluate(() => SessionManager.paneAssignments);
    const picker = page.locator('#workspaceLayoutPicker');
    await picker.locator('summary').click();
    await picker.getByRole('button', {name: 'Single saved layout', exact: true}).click();
    await expect(picker.getByRole('alert')).toContainText('more than four floating windows');
    await expect(picker.getByRole('alert')).toBeFocused();
    expect(await page.evaluate(() => SessionManager.paneAssignments)).toEqual(before);
    expect(await page.evaluate(() => SessionManager.windowMode)).toBe(true);
    expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
    expect(await page.evaluate(() => window.__presetSessionEvents.filter(event => ['ssh_disconnect', 'ssh_input'].includes(event)))).toEqual([]);
});
