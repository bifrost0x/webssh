const {test, expect} = require('playwright/test');
const {assertNoExternalRequests, login, openProfileManagement} = require('./helpers');

/** Serve the global settings from memory and record what the page writes. */
async function mockSettings(page, values, answer = body => body) {
    const writes = [];
    await page.route('**/admin/api/settings', route => {
        const request = route.request();
        if (request.method() === 'POST') {
            const body = request.postDataJSON();
            writes.push(body);
            Object.assign(values, answer(body));
        }
        return route.fulfill({json: values});
    });
    return writes;
}

async function confirmStepUp(page) {
    await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
}

test('Herdr switch shows the stored setting', async ({page}) => {
    await login(page);
    await mockSettings(page, {registration_enabled: true, herdr_enabled: true});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    await expect(toggle).toHaveAccessibleName('Herdr Enabled');
    await expect(toggle).toHaveAccessibleDescription(/Disabled by default\. Disabling stops all Herdr queries/);
});

test('enabling Herdr sends only that setting after additional authentication', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    await toggle.check();
    await confirmStepUp(page);
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();
    expect(writes).toEqual([{herdr_enabled: true}]);
});

test('Herdr switch follows the server answer instead of the click', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false}, () => ({herdr_enabled: false}));
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await toggle.check();
    await confirmStepUp(page);
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    expect(writes).toHaveLength(1);
});

test('cancelled authentication restores the Herdr switch and writes nothing', async ({page}) => {
    await login(page);
    const writes = await mockSettings(page, {registration_enabled: true, herdr_enabled: false});
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    await toggle.check();
    await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
    await expect(toggle).toBeDisabled();
    await page.locator('#stepUpCancelButton').click();
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    expect(writes).toEqual([]);
});

/** Switch the real integration setting through the protected admin control. */
async function setIntegration(page, enabled) {
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingHerdr');
    await expect(toggle).toBeEnabled();
    if (await toggle.isChecked() !== enabled) {
        await toggle.setChecked(enabled);
        await confirmStepUp(page);
        await expect(toggle).toBeEnabled();
    }
    await expect(toggle).toBeChecked({checked: enabled});
    await page.goto('/');
    await expect(page.locator('meta[name="herdr-enabled"]')).toHaveAttribute('content', String(enabled));
}

async function openHostEditor(page, name) {
    await openProfileManagement(page);
    if (name) {
        await page.locator('.profile-management-item').filter({hasText: name}).locator('.profile-inspect-button').click();
    } else {
        await page.locator('#newProfileBtn').click();
    }
    await expect(page.locator('#profileEditorForm')).toBeVisible();
    const advanced = page.locator('#profileAdvancedSettingsCard');
    if (!await advanced.evaluate(element => element.open)) await advanced.locator('summary').click();
}

const emitAck = (page, event, data) => page.evaluate(([name, payload]) => new Promise(resolve => {
    window.socket.emit(name, payload, resolve);
}), [event, data]);

/** Delete the hosts a case saved and wait until the server confirms, so no later spec sees them. */
async function deleteHosts(page, names) {
    await page.waitForFunction(() => window.ProfileManager?.profilesLoaded === true);
    const remaining = await page.evaluate(hostNames => Promise.all(ProfileManager.profiles
        .filter(profile => hostNames.includes(profile.name))
        .map(profile => new Promise(resolve => {
            window.socket.emit('delete_profile', {profile_id: profile.id}, answer => resolve(answer?.success === true));
        }))), names);
    expect(remaining.every(Boolean)).toBe(true);
}

const savedHost = (page, name) => page.evaluate(hostName => {
    const host = ProfileManager.profiles.find(profile => profile.name === hostName);
    return host ? {herdr: host.herdr, use_herdr: host.use_herdr, use_tmux: host.use_tmux} : null;
}, name);

for (const width of [390, 1440]) {
    test(`host editor offers Herdr as the only alternative to tmux at ${width}px`, async ({page}) => {
        const name = `Herdr host ${width}`;
        await page.setViewportSize({width, height: 900});
        await login(page);
        try {
            await setIntegration(page, true);
            await openHostEditor(page);
            const option = page.locator('#profileEditorHerdr');
            const herdrMode = page.locator('#profileEditorModeHerdr');
            const reason = page.locator('#profileEditorHerdrModeReason');
            await expect(page.locator('#profileEditorTmuxGroup')).toBeHidden();
            await expect(option).not.toBeChecked();
            await expect(herdrMode).toBeDisabled();
            await expect(reason).toContainText('Turn on “Herdr on this host”');

            await page.locator('#profileEditorName').fill(name);
            await page.locator('#profileEditorHost').fill('fixture.invalid');
            await page.locator('#profileEditorUsername').fill('test');
            await option.check();
            await expect(reason).toBeHidden();
            await herdrMode.check();
            await expect(page.locator('#profileEditorModeTmux')).not.toBeChecked();

            await page.locator('#profileEditorPostConnectMode').selectOption('free_text');
            await expect(herdrMode).toBeDisabled();
            await expect(page.locator('#profileEditorModeShell')).toBeChecked();
            await expect(reason).toContainText('cannot be combined with “Run after connecting”');
            await page.locator('#profileEditorPostConnectMode').selectOption('none');
            await herdrMode.check();

            await page.locator('#profileEditorForm button[type="submit"]').first().click();
            await expect.poll(() => savedHost(page, name)).toEqual({herdr: true, use_herdr: true, use_tmux: false});

            await page.reload();
            await openHostEditor(page, name);
            await expect(option).toBeChecked();
            await expect(herdrMode).toBeChecked();
            await expect(herdrMode).toBeEnabled();

            await setIntegration(page, false);
            await openHostEditor(page, name);
            await expect(page.locator('#profileEditorHerdrDisabled')).toBeVisible();
            await expect(option).toBeChecked();
            await expect(option).toBeDisabled();
            await expect(herdrMode).toBeChecked();
            await expect(herdrMode).toBeDisabled();
            await page.locator('#profileEditorModeShell').check();
            await page.locator('#profileEditorForm button[type="submit"]').first().click();
            await expect.poll(() => savedHost(page, name)).toEqual({herdr: true, use_herdr: false, use_tmux: false});
            await assertNoExternalRequests(page);
        } finally {
            await setIntegration(page, false);
            await deleteHosts(page, [name]);
        }
    });
}

test('host editor is unchanged while the Herdr integration is off', async ({page}) => {
    await login(page);
    await expect(page.locator('meta[name="herdr-enabled"]')).toHaveAttribute('content', 'false');
    await openHostEditor(page);
    await expect(page.locator('#profileEditorHerdrBlock')).toBeHidden();
    await expect(page.locator('#profileEditorUseTmux')).toBeVisible();
});

/** Saved hosts with the Herdr option and fixture sessions of this user that the server treats as connected. */
async function herdrHosts(page, names, {useHerdr = false, sessions = names} = {}) {
    const ids = [];
    for (const name of names) {
        const answer = await emitAck(page, 'save_profile', {
            name, host: `${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.example`, port: 22, username: 'dev',
            auth_type: 'password', herdr: true, use_herdr: useHerdr,
        });
        expect(answer.success).toBe(true);
        ids.push(answer.profile.id);
    }
    const seeded = await emitAck(page, 'e2e_herdr_sessions', {
        profile_ids: ids.filter((_id, index) => sessions.includes(names[index])),
    });
    expect(seeded.ok).toBe(true);
    return {profileIds: ids, sessionIds: seeded.session_ids};
}

async function cleanUpHerdr(page, names) {
    await emitAck(page, 'e2e_herdr_sessions', {profile_ids: []}).catch(() => {});
    await deleteHosts(page, names);
    const token = await page.locator('meta[name="csrf-token"]').getAttribute('content').catch(() => null);
    if (token) {
        await page.request.put('/api/overview/preferences', {data: {panels: null}, headers: {'X-CSRFToken': token}});
    }
    await setIntegration(page, false);
}

async function openAgents(page) {
    // Phones reach the primary navigation through the More menu.
    if (!await page.locator('#overviewNavBtn').isVisible()) await page.locator('#mobileMoreBtn').click();
    await page.locator('#overviewNavBtn').click();
    const panel = page.locator('#odAgents');
    await expect(panel).toBeVisible();
    await panel.scrollIntoViewIfNeeded();
    return panel;
}

/** Record snapshot requests; answers come from the server unless the test supplies them by session. */
async function watchSnapshots(page, answers = null) {
    await page.evaluate(mocked => {
        window.__herdrCalls = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ack) => {
            if (event !== 'request_herdr_snapshot') return original(event, data, ack);
            window.__herdrCalls.push({session: data.session_id, at: Date.now()});
            if (!mocked) return original(event, data, ack);
            setTimeout(() => ack(mocked[data.session_id]), 20);
            return window.socket;
        };
    }, answers);
}
/**
 * watchSnapshots for the page loaded next: the answers are in place before
 * the panel asks for the first time, however soon the restored sessions
 * arrive after the reload.
 */
async function watchSnapshotsFromLoad(page, answers) {
    await page.addInitScript(mocked => {
        let current;
        Object.defineProperty(window, 'socket', {configurable: true, get: () => current, set: value => {
            current = value;
            if (!value || value.__herdrWatched) return;
            value.__herdrWatched = true;
            window.__herdrCalls = [];
            const original = value.emit.bind(value);
            value.emit = (event, data, ack) => {
                if (event !== 'request_herdr_snapshot') return original(event, data, ack);
                window.__herdrCalls.push({session: data.session_id, at: Date.now()});
                setTimeout(() => ack(mocked[data.session_id]), 20);
                return value;
            };
        }});
    }, answers);
}
const snapshotCalls = page => page.evaluate(() => window.__herdrCalls.length);
const execCount = async page => (await emitAck(page, 'e2e_herdr_exec_count', {})).count;
const hostGroup = (panel, name) => panel.locator('.od-agents-host').filter({has: panel.page().locator('h3', {hasText: name})});

for (const width of [1440, 390]) {
    test.describe(`Herdr overview at ${width}px`, () => {
        test.beforeEach(async ({page}) => {
            await page.setViewportSize({width, height: 900});
        });

        test('agents read through the own session appear as text and open their session', async ({page}) => {
            const names = [`Agents pipeline ${width}`];
            await login(page);
            try {
                await setIntegration(page, true);
                const {sessionIds} = await herdrHosts(page, names, {useHerdr: true});
                await page.reload();
                const panel = await openAgents(page);
                const group = hostGroup(panel, names[0]);
                // Recorded snapshot of the tested release plus one hostile agent, parsed by the server.
                await expect(group.locator('.od-agent')).toHaveCount(4);
                await expect(group.locator('.od-agent-status').first()).toContainText('Working');
                await expect(group.locator('.od-agent').nth(1))
                    .toHaveAccessibleName(/^reviewer, tester, \/home\/deploy, Status reported by Herdr: Blocked/);
                const hostile = group.locator('.od-agent').nth(3);
                await expect(hostile.locator('.od-agent-label')).toHaveText('<img src=x onerror="window.__herdrInjected=1">');
                await expect(hostile.locator('.od-agent-cwd')).toHaveText('/srv/"><script>window.__herdrInjected=2</script>');
                expect(await panel.locator('img, script').count()).toBe(0);
                expect(await page.evaluate(() => window.__herdrInjected)).toBeUndefined();
                await expect(page.locator('#odAgentsHint')).toBeVisible();
                expect(await execCount(page)).toBeGreaterThan(0);

                await group.locator('.od-agent').first().click();
                await expect(page.locator('#connectionOverview')).toBeHidden();
                expect(await page.evaluate(() => SessionManager.getActiveSession())).toBe(sessionIds[0]);
                await expect(page.locator(`#tab-${sessionIds[0]} .tab-herdr-badge`)).toHaveCount(1);
                await assertNoExternalRequests(page);
            } finally {
                await cleanUpHerdr(page, names);
            }
        });

        test('every reason has its own state and busy passes silently', async ({page}) => {
            // Two protected setting changes, eight hosts and snapshots half a
            // second apart exceed the default budget on a loaded runner. A
            // timeout here also skipped the cleanup and left hosts behind for
            // the next test of the same account.
            test.slow();
            const reasons = ['not_installed', 'no_server', 'incompatible', 'timeout', 'invalid', 'unavailable', 'busy'];
            const names = [...reasons.map(reason => `Agents ${reason} ${width}`), `Agents offline ${width}`];
            await login(page);
            try {
                await setIntegration(page, true);
                const {sessionIds} = await herdrHosts(page, names, {sessions: names.slice(0, reasons.length)});
                await watchSnapshotsFromLoad(page, Object.fromEntries(sessionIds.map((id, index) => [id,
                    {success: false, agents: [], truncated: false, reason: reasons[index]}])));
                await page.reload();
                const panel = await openAgents(page);
                const texts = new Set();
                for (const [index, reason] of reasons.entries()) {
                    const group = hostGroup(panel, names[index]);
                    if (reason === 'busy') {
                        await expect(group).toHaveAttribute('aria-busy', 'true');
                        await expect(group.locator('.od-agents-state')).toHaveCount(0);
                        continue;
                    }
                    const state = group.locator(`.od-agents-state[data-reason="${reason}"]`);
                    // Hosts are asked about half a second apart.
                    await expect(state).toBeVisible({timeout: 10_000});
                    texts.add(await state.textContent());
                }
                const offline = hostGroup(panel, names.at(-1)).locator('.od-agents-state[data-reason="disconnected"]');
                await expect(offline).toContainText('Not connected');
                await expect(offline.getByRole('button', {name: `Connect ${names.at(-1)}`})).toBeVisible();
                texts.add(await offline.textContent());
                expect(texts.size).toBe(reasons.length);
            } finally {
                await cleanUpHerdr(page, names);
            }
        });

        test('a hidden panel stops asking and an old tab gets disabled without a command on the host', async ({page}) => {
            test.slow();
            const names = [`Agents switch ${width}`];
            await login(page);
            try {
                await setIntegration(page, true);
                await herdrHosts(page, names);
                await page.reload();
                await watchSnapshots(page);
                const panel = await openAgents(page);
                await expect(hostGroup(panel, names[0]).locator('.od-agent')).toHaveCount(4);

                // Customize: hide the panel; nothing is asked while it is hidden.
                await page.locator('#overviewCustomize').click();
                await page.getByRole('button', {name: 'Hide Agents'}).click();
                await page.locator('#odLayoutDone').click();
                await expect(panel).toBeHidden();
                const hiddenAt = await snapshotCalls(page);
                await page.waitForTimeout(12_000);
                expect(await snapshotCalls(page)).toBe(hiddenAt);
                await page.locator('#overviewCustomize').click();
                await page.locator('#odHiddenPanels [data-show-panel="agents"]').click();
                await page.locator('#odLayoutDone').click();
                await expect.poll(() => snapshotCalls(page)).toBeGreaterThan(hiddenAt);

                // An administrator turns Herdr off in another tab; this tab keeps its open panel.
                const admin = await page.context().newPage();
                await setIntegration(admin, false);
                await admin.close();
                const commands = await execCount(page);
                await expect(page.locator('#odAgentsDisabled')).toBeVisible({timeout: 15_000});
                await expect(page.locator('#odAgentsDisabled')).toContainText('turned off by an administrator');
                await expect(page.locator('#odAgentsHosts')).toBeHidden();
                const stoppedAt = await snapshotCalls(page);
                await page.waitForTimeout(12_000);
                expect(await snapshotCalls(page)).toBe(stoppedAt);
                expect(await execCount(page)).toBe(commands);
            } finally {
                await cleanUpHerdr(page, names);
            }
        });

        test('a refused authentication leaves the integration off', async ({page}) => {
            await login(page);
            await page.goto('/settings#integrations');
            const toggle = page.locator('#settingHerdr');
            await expect(toggle).toBeEnabled();
            await toggle.check();
            await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
            await page.locator('#stepUpPassword').fill('not-the-password');
            // The dialog stays open with the refusal so the password can be retried.
            await page.locator('#stepUpSubmit').click();
            await expect(page.locator('#stepUpError')).toHaveText('Authentication failed. Check the value and try again.');
            await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
            await page.locator('#stepUpCancelButton').click();
            await expect(page.locator('#stepUpModal')).not.toHaveClass(/show/);
            await expect(toggle).toBeEnabled();
            await expect(toggle).not.toBeChecked();
            await page.goto('/');
            await expect(page.locator('meta[name="herdr-enabled"]')).toHaveAttribute('content', 'false');
            await expect(page.locator('#odAgents')).toHaveCount(0);
        });
    });
}
