const {test, expect} = require('playwright/test');
const {login, waitForInventory, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

const THEMES = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];
const IDENTITY = ['detected_platform', 'detected_family', 'detected_os_id', 'detected_os_version', 'detected_virt',
    'detected_container_access', 'detected_guests', 'detected_graphical', 'detected_services', 'detection_state',
    'platform_checked_at', 'services_checked_at', 'role_override', 'platform_icon', 'greeting_platform'];

async function openOverview(page, width = 1440) {
    await page.setViewportSize({width, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    const ids = await page.evaluate(() => ProfileManager.profiles.map(profile => profile.id));
    await page.route('**/api/overview/status', route => route.fulfill({json: {hosts: ids.map(id => ({id, state: 'ready'}))}}));
    await page.goto('/');
    await waitForInventory(page);
    await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
    await installSshConnectTrap(page);
    return ids;
}

// Replaces the identity facts of the first hosts; every other host keeps none.
async function seed(page, patches) {
    await page.evaluate(([patches, fields]) => {
        const now = Math.floor(Date.now() / 1000);
        const base = ProfileManager.profiles[0];
        const bare = profile => Object.fromEntries(Object.entries(profile).filter(([key]) => !fields.includes(key)));
        ProfileManager.setProfiles(patches.map((patch, index) => ({
            ...bare(base), id: `identity-${index}`, name: `identity-${index}`, group: null, jump_host_id: null, socks_proxy_id: null,
            ...Object.fromEntries(Object.entries(patch).map(([key, value]) => [key, value === 'NOW' ? now : value])),
        })));
    }, [patches, IDENTITY]);
}

const PROXMOX = {detected_platform: 'proxmox', detected_os_version: '8.2', detected_virt: 'bare-metal', detected_guests: 7,
    detection_state: 'detected', platform_checked_at: 'NOW'};
const PAPERLESS = {detected_platform: 'ubuntu', detected_os_version: '24.04', detected_virt: 'vm',
    detected_services: ['docker', 'postgresql', 'redis', 'paperless'], detection_state: 'detected', platform_checked_at: 'NOW'};
const card = (page, index) => page.locator(`#overviewHostList .od-host[data-host-id="identity-${index}"]`);

test('host cards show the role, machine, system and service logos of each host', async ({page}) => {
    await openOverview(page);
    await seed(page, [PROXMOX, PAPERLESS, {}, {...PAPERLESS, detected_container_access: 'denied'}, {...PROXMOX, detected_guests: 0}]);

    const proxmox = card(page, 0);
    await expect(proxmox).toHaveAttribute('data-role', 'hypervisor');
    await expect(proxmox.locator('.od-host-top > .od-role')).toHaveText(/Hypervisor/);
    await expect(proxmox.locator('.od-host-logo .od-virt')).toHaveText('Bare Metal');
    await expect(proxmox.locator('.od-host-os')).toHaveText('Proxmox 8.2');
    await expect(proxmox.locator('.od-fact-chip[data-kind="guests"]')).toHaveText(/7 guests/);
    await expect(proxmox.locator('.od-service-chip')).toHaveCount(0);
    await expect(card(page, 4).locator('.od-fact-chip')).toHaveCount(0);

    const paperless = card(page, 1);
    await expect(paperless).toHaveAttribute('data-role', 'docs');
    await expect(paperless.locator('.od-role')).toHaveText(/Documents/);
    await expect(paperless.locator('.od-virt')).toHaveText('VM');
    await expect(paperless.locator('.od-host-os')).toHaveText('Ubuntu 24.04');
    const chips = paperless.locator('.od-service-chip');
    await expect(chips).toHaveCount(4);
    // The service that names the role leads.
    expect(await chips.evaluateAll(nodes => nodes.map(node => [node.dataset.service, node.getAttribute('aria-label')])))
        .toEqual([['paperless', 'Paperless'], ['docker', 'Docker'], ['postgresql', 'PostgreSQL'], ['redis', 'Redis']]);
    await expect(chips.first().locator('.host-service-icon[aria-hidden="true"]')).toHaveCount(1);
    await expect(paperless.getByRole('img', {name: 'Paperless', exact: true})).toHaveCount(1);
    await expect(chips.first()).toHaveAttribute('title', /Paperless/);
    await expect(paperless.locator('.od-fact-chip')).toHaveCount(0);
    await expect(paperless.locator('.od-hint-chip')).toHaveCount(0);

    const plain = card(page, 2);
    await expect(plain).toHaveAttribute('data-role', 'server');
    await expect(plain.locator('.od-role')).toHaveText(/Server/);
    await expect(plain.locator('.od-host-os')).toHaveCount(0);
    await expect(plain.locator('.od-virt')).toHaveCount(0);
    await expect(plain.locator('.od-host-profile > summary')).toHaveAttribute('aria-label', 'Host profile: identity-2');
    await expect(plain.locator('.od-host-profile > summary')).toHaveText('Host profile');
    // Cards keep their own height: opening one profile leaves its row neighbours alone.
    const rows = () => page.evaluate(() => ['identity-0', 'identity-1'].map(id => {
        const rect = document.querySelector(`#overviewHostList .od-host[data-host-id="${id}"]`).getBoundingClientRect();
        return {top: Math.round(rect.top), height: rect.height};
    }));
    const [, before] = await rows();
    await proxmox.locator('.od-host-profile > summary').click();
    await expect(proxmox.locator('.od-host-profile')).toHaveAttribute('open', '');
    const [opened, after] = await rows();
    expect(opened.top).toBe(after.top);
    expect(opened.height).toBeGreaterThan(after.height + 40);
    expect(Math.abs(after.height - before.height)).toBeLessThanOrEqual(1);
    await plain.locator('.od-host-profile > summary').click();
    const profile = plain.locator('.od-host-profile');
    await expect(profile).toContainText('Not detected yet');
    await expect(profile).toContainText('default');
    await expect(profile).not.toContainText(/undefined|NaN|null/);

    const denied = card(page, 3);
    const hint = denied.locator('.od-hint-chip[data-kind="containers"]');
    await expect(hint).toHaveText(/Containers not readable/);
    await expect(hint).toHaveAttribute('title', /Docker socket/);

    await page.evaluate(() => window.i18n.setLanguage('de'));
    await expect(paperless.locator('.od-role')).toHaveText(/Dokumente/);
    await expect(proxmox.locator('.od-fact-chip[data-kind="guests"]')).toHaveText(/7 Gäste/);
    await expect(proxmox.locator('.od-virt')).toHaveText('Bare Metal');
    await expect(denied.locator('.od-hint-chip')).toHaveText(/Container nicht lesbar/);
    await page.evaluate(() => window.i18n.setLanguage('en'));
    // Replacement patterns in a host name are text, not instructions.
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => (profile.id === 'identity-2'
        ? {...profile, name: "db $& box $' $$"} : profile))));
    await expect(plain.locator('.od-host-profile > summary')).toHaveAttribute('aria-label', "Host profile: db $& box $' $$");
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});

test('the host profile explains the role and the detection, and stays open across updates', async ({page}) => {
    await openOverview(page);
    await seed(page, [PAPERLESS, {...PROXMOX, role_override: 'backup'}, {...PAPERLESS, platform_checked_at: 1700000000},
        {...PAPERLESS, platform_icon: 'ubuntu', detected_platform: 'debian'}]);

    const derived = card(page, 0);
    const summary = derived.locator('.od-host-profile > summary');
    await summary.click();
    const profile = derived.locator('.od-host-profile');
    await expect(profile).toHaveAttribute('open', '');
    await expect(profile.locator('dt')).toHaveText(['System', 'Machine', 'Services', 'Role', 'Detection']);
    await expect(profile.locator('dd').nth(0)).toHaveText('Ubuntu 24.04');
    await expect(profile.locator('dd').nth(1)).toHaveText('VM');
    await expect(profile.locator('dd').nth(2)).toHaveText('Paperless, Docker, PostgreSQL, Redis');
    await expect(profile.locator('dd').nth(3)).toHaveText(/Documents.*derived from Paperless/);
    await expect(profile.locator('dd').nth(4)).toContainText('Detected after SSH connection');
    await expect(profile.locator('dd').nth(4)).toContainText('next check not before');
    await expect(profile).not.toHaveClass(/od-stale/);

    // A profile update rebuilds the card; the open profile and the focus survive it.
    await summary.focus();
    await page.evaluate(() => {
        ProfileManager.setProfiles(ProfileManager.profiles.map(item => item.id === 'identity-0'
            ? {...item, detected_services: [...item.detected_services, 'grafana']} : item));
    });
    await expect(derived.locator('.od-service-chip')).toHaveCount(5);
    await expect(derived.locator('.od-host-profile')).toHaveAttribute('open', '');
    await expect(derived.locator('.od-host-profile > summary')).toBeFocused();

    const manual = card(page, 1);
    await expect(manual).toHaveAttribute('data-role', 'backup');
    await expect(manual.locator('.od-role')).toHaveText(/Backup/);
    await expect(manual.locator('.od-fact-chip[data-kind="guests"]')).toHaveCount(0);
    await manual.locator('.od-host-profile > summary').click();
    await expect(manual.locator('.od-host-profile dd').nth(2)).toHaveText(/Backup.*manual/);
    await expect(manual.locator('.od-host-profile dd').nth(1)).toHaveText('Bare Metal · 7 guests');

    // A chosen platform is named in the system row; detection keeps its own wording.
    const manualPlatform = card(page, 3);
    await expect(manualPlatform.locator('.od-host-os')).toHaveText('Ubuntu (manual choice)');
    await manualPlatform.locator('.od-host-profile > summary').click();
    const detection = manualPlatform.locator('.od-host-profile dd').last();
    await expect(detection).toContainText('Detected after SSH connection');
    await expect(detection).not.toContainText(/manual/i);

    const stale = card(page, 2);
    await stale.locator('.od-host-profile > summary').click();
    await expect(stale.locator('.od-host-profile')).toHaveClass(/od-stale/);
    await expect(stale.locator('.od-host-profile')).toContainText('Older than 7 days');
    expect(await sshAttempts(page)).toEqual([]);
});

test('more than five services fold into a counter and the card fits at 360px', async ({page}) => {
    await openOverview(page, 360);
    const services = await page.evaluate(() => Object.keys(HostPlatform.serviceLabels).slice(0, 24));
    expect(services).toHaveLength(24);
    await seed(page, [{...PAPERLESS, name: 'n'.repeat(80), detected_services: services, detected_container_access: 'denied',
        detected_os_id: 'omarchy', detected_os_version: null, detected_family: 'archlinux', detected_platform: 'archlinux', detected_virt: 'bare-metal'}]);
    const host = card(page, 0);
    const chips = host.locator('.od-service-chip');
    await expect(chips).toHaveCount(6);
    await expect(chips.last()).toHaveText('+19');
    await expect(chips.last()).toHaveAttribute('aria-label', /^\+19: \S/);
    const rest = await page.evaluate(ids => HostPlatform.services({detected_services: ids}), services);
    expect((await chips.last().getAttribute('title')).split(', ')).toHaveLength(rest.length - 5);
    await expect(host.locator('.od-host-os')).toHaveText('Omarchy · Arch Linux-based');
    await host.locator('.od-host-profile > summary').click();
    const escaped = await host.evaluate(item => {
        const bounds = item.getBoundingClientRect();
        return [...item.querySelectorAll('*')].filter(element => {
            if (!element.getClientRects().length) return false;
            const rect = element.getBoundingClientRect();
            return rect.right > bounds.right + 1 || rect.left < bounds.left - 1;
        }).map(element => element.className);
    });
    expect(escaped).toEqual([]);
    expect(await page.locator('#connectionOverview').evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
});

test('the machine badge keeps clear of the host text in every language and width', async ({page}) => {
    await openOverview(page);
    await seed(page, ['bare-metal', 'vm', 'lxc', 'container', 'wsl'].map(virt => ({...PAPERLESS, detected_virt: virt})));
    for (const width of [360, 768, 1440]) {
        await page.setViewportSize({width, height: 900});
        for (const language of ['en', 'de', 'es', 'fr', 'vi', 'zh']) {
            await page.evaluate(language => window.i18n.setLanguage(language), language);
            await expect(page.locator('#overviewHostList .od-virt')).toHaveCount(5);
            await expect.poll(() => page.evaluate(() => window.i18n.getLanguage())).toBe(language);
            const clashes = await page.locator('#overviewHostList .od-host').evaluateAll(items => items.flatMap(item => {
                const badge = item.querySelector('.od-virt').getBoundingClientRect();
                const bounds = item.getBoundingClientRect();
                const texts = [...item.querySelectorAll('.od-host-copy > *')].map(element => element.getBoundingClientRect());
                const problems = texts.filter(text => text.left - badge.right < 6).map(text => `gap ${Math.round(text.left - badge.right)}`);
                if (badge.left < bounds.left) problems.push('outside card');
                return problems.map(problem => `${item.querySelector('.od-virt').textContent}: ${problem}`);
            }));
            expect(clashes, `${language} at ${width}px`).toEqual([]);
        }
    }
    await page.evaluate(() => window.i18n.setLanguage('en'));
});

test('role tints keep the card text, pill and tiles readable in every theme', async ({page}) => {
    await openOverview(page);
    const roles = await page.evaluate(() => HostIdentity.ROLES);
    await seed(page, roles.map(role => ({...PAPERLESS, detected_services: ['docker', 'immich'], role_override: role})));
    await expect(page.locator('#overviewHostList .od-host[data-role]')).toHaveCount(roles.length);
    for (const theme of THEMES) {
        const results = await page.evaluate(theme => {
            document.body.dataset.theme = theme;
            const parse = value => {
                const numbers = value.match(/[\d.]+/g).map(Number);
                const srgb = value.startsWith('color(');
                const channels = numbers.slice(0, 3).map(v => (srgb ? v * 255 : v));
                const alpha = value.includes('/') || value.startsWith('rgba') ? numbers[3] : 1;
                return {channels, alpha: alpha ?? 1};
            };
            const colours = value => value.match(/(rgba?|color)\([^)]*\)/g) || [];
            const over = (top, bottom) => top.channels.map((v, i) => v * top.alpha + bottom[i] * (1 - top.alpha));
            // The opaque colour an element paints, built from its own and its ancestors' backgrounds.
            const behind = element => {
                const layers = [];
                for (let node = element; node; node = node.parentElement) {
                    const colour = parse(getComputedStyle(node).backgroundColor);
                    if (colour.alpha > 0) layers.push(colour);
                    if (colour.alpha >= 1) break;
                }
                return layers.reverse().reduce((bottom, top) => over(top, bottom), [255, 255, 255]);
            };
            const luminance = channels => channels.map(v => v / 255)
                .map(v => (v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4))
                .reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0);
            const ratio = (a, b) => {
                const [x, y] = [luminance(a), luminance(b)];
                return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
            };
            const ink = element => parse(getComputedStyle(element).color).channels;
            return [...document.querySelectorAll('#overviewHostList .od-host[data-role]')].map(item => {
                const base = behind(item);
                // Both ends of the role gradient are surfaces the content may sit on.
                const surfaces = [base, ...colours(getComputedStyle(item).backgroundImage).map(stop => over(parse(stop), base))];
                const probe = document.createElement('span');
                probe.style.color = 'var(--role)';
                item.append(probe);
                const accent = ink(probe);
                probe.remove();
                const pill = item.querySelector('.od-role');
                const pillLayer = parse(getComputedStyle(pill).backgroundColor);
                const tile = item.querySelector('.od-host-logo');
                const virt = item.querySelector('.od-virt');
                const service = item.querySelector('.od-service-chip');
                const min = values => Math.min(...values);
                return {
                    role: item.dataset.role,
                    accent: min(surfaces.map(surface => ratio(accent, surface))),
                    pill: min(surfaces.map(surface => ratio(ink(pill), over(pillLayer, surface)))),
                    name: min(surfaces.map(surface => ratio(ink(item.querySelector('.od-host-name')), surface))),
                    os: min(surfaces.map(surface => ratio(ink(item.querySelector('.od-host-os')), surface))),
                    tile: ratio(ink(tile.querySelector('.host-platform-icon')), behind(tile)),
                    virt: ratio(ink(virt), behind(virt)),
                    service: ratio(ink(service.querySelector('.host-service-icon')), behind(service)),
                };
            });
        }, theme);
        expect(results).toHaveLength(roles.length);
        for (const result of results) {
            const label = `${theme} ${result.role}`;
            expect.soft(result.accent, `${label} accent`).toBeGreaterThanOrEqual(3);
            expect.soft(result.pill, `${label} pill text`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.name, `${label} name`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.os, `${label} system line`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.tile, `${label} platform icon`).toBeGreaterThanOrEqual(3);
            expect.soft(result.virt, `${label} machine badge`).toBeGreaterThanOrEqual(4.5);
            expect.soft(result.service, `${label} service logo`).toBeGreaterThanOrEqual(4.5);
        }
    }
});

test('the overview search finds hosts by role, platform and service', async ({page}) => {
    await openOverview(page);
    await seed(page, [PROXMOX, PAPERLESS, {}]);
    const search = page.locator('#overviewSearch');
    const cards = page.locator('#overviewHostList .od-host');
    await expect(cards).toHaveCount(3);

    await search.fill('paperless');
    await expect(cards).toHaveCount(1);
    await expect(card(page, 1)).toBeVisible();
    await search.fill('hypervisor');
    await expect(cards).toHaveCount(1);
    await expect(card(page, 0)).toBeVisible();
    await search.fill('ubuntu');
    await expect(cards).toHaveCount(1);
    await expect(card(page, 1)).toBeVisible();

    await page.evaluate(() => window.i18n.setLanguage('de'));
    await search.fill('dokumente');
    await expect(cards).toHaveCount(1);
    await expect(card(page, 1)).toBeVisible();
    await page.evaluate(() => window.i18n.setLanguage('en'));

    await search.fill('');
    await expect(cards).toHaveCount(3);
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});

test('the role tint leaves the live border and the hover and focus accents visible', async ({page}) => {
    await openOverview(page);
    await seed(page, [PAPERLESS, PAPERLESS]);
    const [first, second] = [card(page, 0), card(page, 1)];
    await expect(first).toHaveAttribute('data-role', 'docs');
    const border = item => item.evaluate(element => getComputedStyle(element).borderTopColor);
    await page.mouse.move(0, 0);
    const rest = await border(first);
    expect(await border(second)).toBe(rest);

    await second.evaluate(element => { element.dataset.state = 'live'; });
    expect(await border(second), 'live card').not.toBe(rest);
    expect(await border(first), 'idle card').toBe(rest);
    await second.evaluate(element => { element.dataset.state = 'ready'; });

    await first.hover();
    await expect.poll(() => border(first), {message: 'hover'}).not.toBe(rest);
    await page.mouse.move(0, 0);
    await expect.poll(() => border(first)).toBe(rest);

    await first.locator('button, a, summary').first().focus();
    await expect.poll(() => border(first), {message: 'focus-within'}).not.toBe(rest);
});
