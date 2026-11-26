const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

// Sessions are simulated: requests that name an "idbar-" session never reach
// the server, and the connection itself is announced by a synthetic event.
async function simulateSessions(page) {
    await page.evaluate(() => {
        const originalEmit = window.socket.emit.bind(window.socket);
        window.socket.emit = function identityTestEmit(event, payload, ...rest) {
            const sessionId = payload?.session_id;
            if (typeof sessionId === 'string' && sessionId.startsWith('idbar-')) {
                rest.find(item => typeof item === 'function')?.({ success: false, error: 'simulated session' });
                return window.socket;
            }
            return originalEmit(event, payload, ...rest);
        };
        const base = ProfileManager.profiles[0];
        const host = (id, name, facts) => ({...base, id, name, host: `${id}.identity.test`, username: 'ops', port: 22,
            group: null, jump_host_id: null, socks_proxy_id: null, detection_state: 'detected', ...facts});
        ProfileManager.setProfiles([
            host('paper', 'Paperless', {detected_platform: 'ubuntu', detected_os_version: '24.04', detected_virt: 'vm',
                detected_services: ['docker', 'postgresql', 'redis', 'paperless', 'nginx']}),
            host('pve', 'pve1', {detected_platform: 'proxmox', detected_os_version: '9.1', detected_virt: 'bare-metal'}),
            host('cloud', 'Nextcloud', {detected_platform: 'debian', detected_services: ['apache', 'mariadb', 'nextcloud']}),
            host('fw', 'opnsense', {detected_platform: 'opnsense', detected_services: ['wireguard', 'unbound']}),
            // Saved, but nothing is known about the machine yet.
            host('plain', 'plainhost', {detection_state: 'pending', detected_platform: null, detected_services: [],
                detected_virt: null, platform_icon: null, role_override: null, detected_graphical: null}),
        ]);
    });
}

async function connect(page, id, {username = 'ops', profile = id} = {}) {
    await page.evaluate(([sessionId, user, profileId]) => {
        window.socket.listeners('ssh_connected').forEach(listener => listener({
            session_id: `idbar-${sessionId}`, host: `${profileId}.identity.test`, port: 22, username: user,
            profile_id: profileId, client_request_id: `reconnect_idbar-${sessionId}`,
        }));
    }, [id, username, profile]);
    await expect(page.locator(`#tab-idbar-${id}`)).toBeVisible();
}

async function setLayout(page, layout) {
    await page.locator('#workspaceLayoutPicker > summary').click();
    await page.locator(`.split-btn[data-layout="${layout}"]`).click();
}

const bar = (page, id) => page.locator('.terminal-pane').filter({has: page.locator(`#terminal-idbar-${id}`)})
    .locator(':scope > .session-identity-bar');

// The terminal shows whole rows only, inside its pane and below the bar.
async function terminalFits(page, id) {
    return page.evaluate(sessionId => {
        const wrapper = document.getElementById(`terminal-${sessionId}`);
        const pane = wrapper.closest('.terminal-pane');
        const term = TerminalManager.terminals[sessionId];
        const cell = term._core._renderService.dimensions.css.cell.height;
        const paneBox = pane.getBoundingClientRect();
        const box = wrapper.getBoundingClientRect();
        const barBox = pane.querySelector(':scope > .session-identity-bar')?.getBoundingClientRect();
        const style = getComputedStyle(pane);
        const inner = paneBox.bottom - parseFloat(style.paddingBottom) - parseFloat(style.borderBottomWidth);
        const xterm = wrapper.querySelector('.xterm');
        const available = xterm.clientHeight - parseFloat(getComputedStyle(xterm).paddingTop)
            - parseFloat(getComputedStyle(xterm).paddingBottom);
        return {
            insidePane: box.bottom <= inner + 0.5 && box.top >= paneBox.top,
            belowBar: !barBox || box.top >= barBox.bottom - 0.5,
            rows: term.rows,
            expectedRows: Math.floor(available / cell),
        };
    }, `idbar-${id}`);
}

test('a pane with a session names its host above the terminal', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await connect(page, 'paper');
    const identity = bar(page, 'paper');
    await expect(identity).toHaveCount(1);
    await expect(identity).toHaveAttribute('data-role', 'docs');
    await expect(identity).toHaveAttribute('role', 'note');
    await expect(identity).toHaveAttribute('aria-label', 'Documents · Paperless · Ubuntu 24.04 · VM · Paperless, Docker, nginx, PostgreSQL');
    await expect(identity.locator('.session-identity-role')).toHaveText('Documents');
    await expect(identity.locator('.session-identity-name')).toHaveText('Paperless');
    await expect(identity.locator('.session-identity-system')).toHaveText('Ubuntu 24.04');
    await expect(identity.locator('.session-identity-virt')).toHaveText('VM');
    const tiles = identity.locator('.session-identity-service');
    await expect(tiles).toHaveCount(4);
    await expect(tiles.first()).toHaveAttribute('data-service', 'paperless');
    await expect(tiles.first()).toHaveAttribute('title', 'Paperless');
    for (const tile of await tiles.all()) await expect(tile).toBeVisible();
    // The bar is one slim line and the terminal below it shows whole rows only.
    const height = await identity.evaluate(element => element.getBoundingClientRect().height);
    expect(height).toBeGreaterThanOrEqual(22);
    expect(height).toBeLessThanOrEqual(30);
    await expect.poll(() => terminalFits(page, 'paper')).toMatchObject({insidePane: true, belowBar: true});
    const fit = await terminalFits(page, 'paper');
    expect(fit.rows).toBe(fit.expectedRows);
    // No profile or host data reaches the bar as markup.
    expect(await identity.evaluate(element => element.querySelectorAll('script, img, a').length)).toBe(0);
    await assertNoExternalRequests(page);
});

test('empty panes, launchers and sessions off their saved endpoint show no identity', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await setLayout(page, 2);
    await expect(page.locator('.terminal-pane')).toHaveCount(2);
    await expect(page.locator('.session-identity-bar')).toHaveCount(0);
    await connect(page, 'other', {username: 'root', profile: 'paper'});
    await expect(page.locator('#terminal-idbar-other')).toBeVisible();
    await expect(page.locator('.session-identity-bar')).toHaveCount(0);
    await connect(page, 'paper');
    await expect(page.locator('.session-identity-bar')).toHaveCount(1);
    // Opening the connection launcher over a session hides that session's bar.
    const index = await page.evaluate(() => SessionManager.paneAssignments.indexOf('idbar-paper'));
    expect(await page.evaluate(paneIndex => SessionManager.showConnectionLauncher(paneIndex), index)).toBe(true);
    await expect(page.locator('.terminal-pane .profile-launcher')).toHaveCount(1);
    await expect(page.locator('.session-identity-bar')).toHaveCount(0);
    await page.evaluate(paneIndex => SessionManager.restoreConnectionLauncher(paneIndex), index);
    await expect(page.locator('.session-identity-bar')).toHaveCount(1);
});

test('a saved host without facts keeps the terminal layout of a pane without a saved host', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    const layout = id => page.evaluate(sessionId => {
        const wrapper = document.getElementById(`terminal-${sessionId}`);
        const pane = wrapper.closest('.terminal-pane');
        return {pane: pane.dataset.paneIndex, offset: Math.round(wrapper.getBoundingClientRect().top - pane.getBoundingClientRect().top),
            height: Math.round(wrapper.getBoundingClientRect().height), rows: TerminalManager.terminals[sessionId].rows};
    }, `idbar-${id}`);
    // The same pane shows a session without a saved host, then one whose saved host has no facts.
    await connect(page, 'other', {username: 'root', profile: 'paper'});
    await expect.poll(() => terminalFits(page, 'other')).toMatchObject({insidePane: true});
    const plainLayout = await layout('other');
    await connect(page, 'plain');
    await expect(page.locator('#tab-idbar-plain')).toHaveAttribute('data-role', 'server');
    await expect(page.locator('.session-identity-bar')).toHaveCount(0);
    await expect.poll(() => terminalFits(page, 'plain')).toMatchObject({insidePane: true});
    expect(await layout('plain')).toEqual(plainLayout);
    // The line comes back once detection has something to say.
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile.id === 'plain'
        ? {...profile, detected_virt: 'vm'} : profile))));
    await expect(bar(page, 'plain')).toHaveCount(1);
    await expect(bar(page, 'plain').locator('.session-identity-virt')).toHaveText('VM');
    await expect.poll(() => terminalFits(page, 'plain')).toMatchObject({insidePane: true, belowBar: true});
    await expect.poll(async () => (await layout('plain')).rows).toBeLessThan(plainLayout.rows);
});

test('a pane lets go of its old identity line before it is redrawn', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await connect(page, 'pve');
    await connect(page, 'paper');
    await expect(bar(page, 'paper')).toHaveCount(1);
    await page.evaluate(() => {
        window.__released = [];
        const release = HostPlatform.releaseFits;
        HostPlatform.releaseFits = root => {
            window.__released.push({pane: root.classList.contains('terminal-pane'), bar: Boolean(root.querySelector?.('.session-identity-bar')),
                tab: root.classList.contains('session-tab')});
            return release(root);
        };
    });
    await page.locator('#tab-idbar-pve .tab-label').click();
    await expect(page.locator('.terminal-pane').first().locator('.session-identity-bar')).toHaveAttribute('data-role', 'hypervisor');
    expect(await page.evaluate(() => window.__released)).toContainEqual({pane: true, bar: true, tab: false});
    await page.evaluate(() => SessionManager.removeSessionUI('idbar-paper'));
    expect(await page.evaluate(() => window.__released)).toContainEqual({pane: false, bar: false, tab: true});
});

test('the bar follows profile updates and the session a pane shows', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await connect(page, 'pve');
    await connect(page, 'paper');
    const pane = page.locator('.terminal-pane').first();
    await expect(pane.locator('.session-identity-bar')).toHaveAttribute('data-role', 'docs');
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile.id === 'paper'
        ? {...profile, detected_services: ['jellyfin', 'docker']} : profile))));
    await expect(pane.locator('.session-identity-bar')).toHaveAttribute('data-role', 'media');
    await expect(pane.locator('.session-identity-service')).toHaveCount(2);
    await page.locator('#tab-idbar-pve .tab-label').click();
    await expect(pane.locator('.session-identity-bar')).toHaveAttribute('data-role', 'hypervisor');
    await expect(pane.locator('.session-identity-system')).toHaveText('Proxmox 9.1');
    await expect(pane.locator('.session-identity-virt')).toHaveText('Bare Metal');
    await expect(pane.locator('.session-identity-service')).toHaveCount(0);
    // A detection result for the running session reaches the bar too.
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile.id === 'pve'
        ? {...profile, role_override: 'backup'} : profile))));
    await expect(pane.locator('.session-identity-bar')).toHaveAttribute('data-role', 'backup');
    await expect(pane.locator('.session-identity-role')).toHaveText('Backup');
    // A language switch relabels the line.
    await page.locator('#tab-idbar-paper .tab-label').click();
    await page.evaluate(() => i18n.setLanguage('de'));
    await expect(pane.locator('.session-identity-role')).toHaveText('Medien');
    await page.evaluate(() => i18n.setLanguage('en'));
    await expect(pane.locator('.session-identity-role')).toHaveText('Media');
});

test('four split panes keep their bars inside the pane at 1366x768', async ({ page }) => {
    const resizeLoops = [];
    page.on('console', message => { if (/ResizeObserver/.test(message.text())) resizeLoops.push(message.text()); });
    page.on('pageerror', error => { if (/ResizeObserver/.test(error.message)) resizeLoops.push(error.message); });
    await page.setViewportSize({width: 1366, height: 768});
    await login(page);
    await simulateSessions(page);
    await setLayout(page, 4);
    for (const id of ['paper', 'pve', 'cloud', 'fw']) await connect(page, id);
    await expect(page.locator('.session-identity-bar')).toHaveCount(4);
    const results = await page.locator('.session-identity-bar').evaluateAll(bars => bars.map(element => {
        const pane = element.closest('.terminal-pane').getBoundingClientRect();
        const box = element.getBoundingClientRect();
        const text = element.querySelector('.session-identity-text');
        return {left: box.left >= pane.left - 0.5, right: box.right <= pane.right + 0.5, height: box.height,
            overflow: element.scrollWidth - element.clientWidth, textShown: text.clientWidth > 40};
    }));
    for (const result of results) {
        expect(result).toMatchObject({left: true, right: true, textShown: true});
        expect(result.overflow).toBeLessThanOrEqual(0);
        expect(result.height).toBeLessThanOrEqual(30);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(1366);
    for (const id of ['paper', 'pve', 'cloud', 'fw']) {
        await expect.poll(() => terminalFits(page, id)).toMatchObject({insidePane: true, belowBar: true});
        const fit = await terminalFits(page, id);
        expect(fit.rows, id).toBe(fit.expectedRows);
    }
    // Shrinking the window refits bars and logos without a resize feedback loop.
    await page.setViewportSize({width: 900, height: 700});
    await page.setViewportSize({width: 1366, height: 768});
    await expect.poll(() => terminalFits(page, 'paper')).toMatchObject({insidePane: true, belowBar: true});
    expect(resizeLoops).toEqual([]);
});

test('a narrow pane drops service logos whole before cutting the host name', async ({ page }) => {
    await page.setViewportSize({width: 360, height: 740});
    await login(page);
    await simulateSessions(page);
    await connect(page, 'paper');
    const identity = page.locator('.session-identity-bar');
    await expect(identity).toHaveCount(1);
    await expect.poll(() => identity.locator('.session-identity-service:visible').count()).toBeLessThan(4);
    const state = await identity.evaluate(element => {
        const tiles = [...element.querySelectorAll('.session-identity-service')];
        const text = element.querySelector('.session-identity-text');
        const style = getComputedStyle(text);
        const right = text.getBoundingClientRect().right - parseFloat(style.paddingRight) - parseFloat(style.borderRightWidth);
        return {
            // Measured in fractions: rounded widths miss a cut of less than a pixel.
            textCut: text.lastElementChild.getBoundingClientRect().right > right + 0.01,
            visibleTiles: tiles.filter(tile => !tile.hidden).length,
            overflow: element.scrollWidth - element.clientWidth,
            hiddenOutOfTree: tiles.filter(tile => tile.hidden).every(tile => tile.offsetWidth === 0),
            page: document.documentElement.scrollWidth,
        };
    });
    expect(state.overflow).toBeLessThanOrEqual(0);
    expect(state.hiddenOutOfTree).toBe(true);
    expect(state.page).toBeLessThanOrEqual(360);
    if (state.textCut) expect(state.visibleTiles).toBe(0);
});

test('a tab name cut by a fraction of a pixel still makes its logos give way', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await page.evaluate(() => applyTheme('glass'));
    await simulateSessions(page);
    await page.evaluate(() => {
        const gateway = ProfileManager.profiles.find(profile => profile.id === 'fw');
        ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile === gateway ? {...profile, name: 'Gateway'} : profile)));
    });
    await setLayout(page, 4);
    for (const id of ['paper', 'pve', 'cloud', 'fw']) await connect(page, id);
    const tab = page.locator('#tab-idbar-fw');
    await expect(tab).toHaveAttribute('data-role', 'network');
    await expect.poll(() => tab.evaluate(element => {
        const name = element.querySelector('.tab-host-name');
        const range = document.createRange();
        range.selectNodeContents(name);
        const style = getComputedStyle(name);
        const inner = name.getBoundingClientRect().width - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        const whole = range.getBoundingClientRect().width <= inner + 0.01;
        const tiles = [...element.querySelectorAll('.tab-service')].filter(tile => !tile.hidden).length;
        return whole || tiles === 0;
    })).toBe(true);
});

test('floating windows carry the identity in their title bar, not in a second line', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await setLayout(page, 'windows');
    await expect(page.locator('#terminalGrid')).toHaveClass(/window-mode/);
    await connect(page, 'paper');
    const frame = page.locator('#terminalGrid > .ws-window').filter({has: page.locator('#terminal-idbar-paper')});
    await expect(frame.locator('.ws-window-subtitle')).toContainText('Documents · Ubuntu 24.04 · VM');
    await expect(frame).toHaveAttribute('data-role', 'docs');
    await expect(frame.locator('.ws-window-badges .session-identity-service')).toHaveCount(4);
    await expect(frame.locator('.session-identity-bar')).toHaveCount(0);
    // In a narrow window the logos give way before the identity text is cut.
    await frame.evaluate(element => { element.style.width = '470px'; });
    await expect.poll(() => frame.evaluate(element => {
        const subtitle = element.querySelector('.ws-window-subtitle');
        const lead = subtitle.querySelector('.ws-window-identity');
        const style = getComputedStyle(subtitle);
        const right = subtitle.getBoundingClientRect().right - parseFloat(style.paddingRight);
        const tiles = [...element.querySelectorAll('.ws-window-services .session-identity-service')].filter(tile => !tile.hidden);
        return {whole: lead.getBoundingClientRect().right <= right + 0.01, someHidden: tiles.length < 4,
            ok: lead.getBoundingClientRect().right <= right + 0.01 || tiles.length === 0};
    })).toMatchObject({ok: true, someHidden: true});
    await frame.evaluate(element => { element.style.width = ''; });
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile.id === 'paper'
        ? {...profile, detected_services: ['jellyfin']} : profile))));
    await expect(frame.locator('.ws-window-subtitle')).toContainText('Media');
    await expect(frame.locator('.ws-window-badges .session-identity-service')).toHaveCount(1);
    // Leaving window mode brings the bar back into the pane.
    await setLayout(page, 1);
    await expect(bar(page, 'paper')).toHaveAttribute('data-role', 'media');
});

test('a focused window keeps its focus tint under the role tint', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await setLayout(page, 'windows');
    await connect(page, 'paper');
    await connect(page, 'pve');
    const frame = id => page.locator('#terminalGrid > .ws-window').filter({has: page.locator(`#terminal-idbar-${id}`)});
    const surface = id => frame(id).locator('.ws-window-titlebar').evaluate(element => getComputedStyle(element).backgroundColor);
    await expect(frame('paper')).toHaveAttribute('data-role', 'docs');
    await expect(frame('pve')).toHaveAttribute('data-role', 'hypervisor');
    await frame('paper').locator('.ws-window-titlebar').click({position: {x: 40, y: 18}});
    await expect(frame('paper')).toHaveClass(/is-focused/);
    await expect(frame('pve')).not.toHaveClass(/is-focused/);
    expect(await surface('paper')).not.toBe(await surface('pve'));
});

const THEMES = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];

test('the identity line stays legible for every role in every theme', async ({ page }) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await simulateSessions(page);
    await connect(page, 'paper');
    await page.addStyleTag({content: '*, *::before, *::after { transition: none !important; }'});
    for (const theme of THEMES) {
        const results = await page.evaluate(theme => {
            applyTheme(theme);
            const parse = value => {
                const probe = document.createElement('canvas').getContext('2d');
                probe.fillStyle = '#000';
                probe.fillStyle = value;
                probe.fillRect(0, 0, 1, 1);
                const transparent = /^(transparent|rgba\(0, 0, 0, 0\))$/.test(value);
                const [r, g, b, a] = probe.getImageData(0, 0, 1, 1).data;
                probe.clearRect(0, 0, 1, 1);
                return {channels: [r, g, b], alpha: transparent ? 0 : a / 255};
            };
            const mix = (top, alpha, bottom) => top.map((v, i) => v * alpha + bottom[i] * (1 - alpha));
            const luminance = channels => channels.map(v => v / 255)
                .map(v => (v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4))
                .reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0);
            const ratio = (a, b) => {
                const [x, y] = [luminance(a), luminance(b)];
                return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
            };
            const bar = document.querySelector('.session-identity-bar');
            // Layers from the first opaque ancestor up to the bar's own colour.
            const layers = [];
            for (let node = bar; node; node = node.parentElement) {
                const colour = parse(getComputedStyle(node).backgroundColor);
                layers.unshift(colour);
                if (colour.alpha >= 1) break;
            }
            const base = layers.reduce((under, layer) => mix(layer.channels, layer.alpha, under), [0, 0, 0]);
            const saved = bar.dataset.role;
            const results = [];
            for (const role of HostIdentity.ROLES) {
                bar.dataset.role = role;
                const accent = parse(getComputedStyle(bar).getPropertyValue('--role').trim());
                // The tint is strongest at the left edge, where the role name sits.
                const surface = mix(accent.channels, 0.16, base);
                const colour = selector => parse(getComputedStyle(bar.querySelector(selector)).color).channels;
                results.push({role,
                    glyph: ratio(colour('.session-identity-glyph'), surface),
                    label: ratio(colour('.session-identity-role'), surface),
                    name: ratio(colour('.session-identity-name'), surface),
                    system: ratio(colour('.session-identity-system'), base)});
            }
            bar.dataset.role = saved;
            return results;
        }, theme);
        for (const result of results) {
            expect.soft(result.glyph, `${theme} ${result.role} glyph`).toBeGreaterThanOrEqual(3);
            expect.soft(result.label, `${theme} ${result.role} label`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.name, `${theme} ${result.role} name`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.system, `${theme} ${result.role} system`).toBeGreaterThanOrEqual(4.5);
        }
    }
    await page.emulateMedia({forcedColors: 'active'});
    const forced = await page.locator('.session-identity-bar').evaluate(bar => {
        const reference = document.createElement('span');
        reference.style.color = 'CanvasText';
        document.body.append(reference);
        const colours = [getComputedStyle(bar.querySelector('.session-identity-role')).color,
            getComputedStyle(bar.querySelector('.session-identity-glyph')).color, getComputedStyle(reference).color];
        reference.remove();
        return colours;
    });
    expect(forced[0]).toBe(forced[2]);
    expect(forced[1]).toBe(forced[2]);
});
