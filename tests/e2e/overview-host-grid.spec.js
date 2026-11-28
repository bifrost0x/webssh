const {test, expect} = require('playwright/test');
const {login, waitForInventory, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// The host cards of the overview form an even grid: the cards of a row are
// equally tall, status and actions sit at the bottom on one line, the
// machine badge keeps off the platform tile, the panel heading never covers
// a card, and details open outside the card.
const THEMES = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];
const WIDTHS = [1440, 1280, 1024, 390];

// Hosts of a homelab: facts of different length, so the cards differ in content.
function homelab() {
    const now = Math.floor(Date.now() / 1000);
    const seen = extra => ({detection_state: 'detected', platform_checked_at: now - 3600, services_checked_at: now - 3600, ...extra});
    return [
        {id: 'grid-hypervisor', name: 'hypervisor-1', host: '192.0.2.10', username: 'root', group: 'Homelab',
            ...seen({detected_platform: 'proxmox', detected_os_version: '8.2', detected_virt: 'bare-metal', detected_guests: 7, detected_services: []})},
        {id: 'grid-backup', name: 'backup-1', host: '192.0.2.11', username: 'root', group: 'Homelab',
            ...seen({detected_platform: 'debian', detected_os_version: '12', detected_virt: 'vm', detected_services: []})},
        {id: 'grid-media', name: 'media-1', host: '192.0.2.12', username: 'media', group: 'Homelab',
            ...seen({detected_platform: 'ubuntu', detected_os_version: '24.04', detected_virt: 'vm',
                detected_services: ['docker', 'jellyfin', 'sonarr', 'radarr', 'prowlarr', 'bazarr', 'qbittorrent'],
                detected_maintenance: {checked_at: now - 7200, updates: 14, security_updates: 3, reboot_required: true}})},
        {id: 'grid-worker', name: 'Worker', host: '198.51.100.20', username: 'ops', group: 'Lokal',
            ...seen({detected_platform: 'archlinux', detected_family: 'archlinux', detected_os_id: 'omarchy', detected_os_version: '4.5.0',
                detected_virt: 'bare-metal', detected_graphical: true, detected_services: ['docker']})},
        {id: 'grid-router', name: 'router-1', host: '192.0.2.13', username: 'root', group: 'LXC',
            ...seen({detected_platform: 'debian', detected_os_version: '12', detected_virt: 'lxc', detected_services: []})},
        {id: 'grid-dns', name: 'dns-1', host: '192.0.2.2', username: 'pi', group: 'LXC',
            ...seen({detected_platform: 'raspberrypi', detected_os_version: '12', detected_virt: 'bare-metal', detected_services: ['pihole', 'unbound']})},
        {id: 'grid-cloud', name: 'cloud-1', host: '192.0.2.14', username: 'ops', group: 'Production',
            ...seen({detected_platform: 'ubuntu', detected_os_version: '22.04', detected_virt: 'vm', detected_services: ['nextcloud', 'apache', 'mariadb']})},
        {id: 'grid-legacy', name: 'legacy-fileserver-basement-rack-02', host: 'fs02.customer.example', username: 'administrator',
            group: 'Customer systems', detection_state: 'pending', detected_services: []},
    ];
}

async function openOverview(page, width, {panels} = {}) {
    await page.setViewportSize({width, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    if (panels !== undefined) {
        const csrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
        expect((await page.request.put('/api/overview/preferences', {data: {panels}, headers: {'X-CSRFToken': csrf}})).ok()).toBe(true);
        await page.reload();
        await waitForInventory(page);
    }
    const hosts = homelab();
    await page.route('**/api/overview/status', route => route.fulfill({json: {generated_at: Date.now() / 1000,
        hosts: hosts.map(host => ({id: host.id, state: 'ready'}))}}));
    await installSshConnectTrap(page);
    const readiness = page.waitForResponse('**/api/overview/status');
    await page.evaluate(list => {
        const base = ProfileManager.profiles[0];
        ProfileManager.setProfiles(list.map(item => ({port: 22, auth_type: 'password', key_id: null, favorite: false,
            jump_host_id: null, socks_proxy_id: null, startup_mode: base.startup_mode, ...item})));
    }, hosts);
    await readiness;
    await expect(page.locator('#overviewHostList .od-host[data-host-id]')).toHaveCount(hosts.length);
    await settle(page);
}

const settle = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));

// Problems of the host grid as text, empty when the grid is even.
function gridProblems(page) {
    return page.locator('#overviewHostList').evaluate(list => {
        const problems = [];
        const box = element => element.getBoundingClientRect();
        const area = (a, b) => Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left))
            * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
        const cards = [...list.querySelectorAll('.od-host[data-host-id]')];
        const rows = new Map();
        for (const card of cards) {
            const top = Math.round(box(card).top);
            rows.set(top, [...(rows.get(top) || []), card]);
            const name = card.dataset.hostId;
            const bar = card.querySelector('.od-host-bottom');
            const style = getComputedStyle(card);
            const inset = parseFloat(style.paddingBottom) + parseFloat(style.borderBottomWidth);
            if (box(card).bottom - box(bar).bottom > inset + 1) problems.push(`${name}: actions above the card bottom`);
            if ([...card.querySelectorAll(':scope > *')].some(part => part !== bar && box(part).top >= box(bar).bottom - 1 && part.getClientRects().length)) {
                problems.push(`${name}: content below the actions`);
            }
            const virt = card.querySelector('.od-virt');
            const tile = card.querySelector('.od-host-logo');
            const icon = tile.querySelector('.host-platform-icon, .material-icons');
            if (virt && area(box(virt), box(tile)) > 0) problems.push(`${name}: machine badge on the platform tile`);
            if (virt && icon && area(box(virt), box(icon)) > 0) problems.push(`${name}: machine badge on the platform icon`);
            const bounds = box(card);
            for (const part of card.querySelectorAll('*')) {
                if (!part.getClientRects().length) continue;
                const rect = box(part);
                if (rect.left < bounds.left - 1 || rect.right > bounds.right + 1) problems.push(`${name}: ${part.className} leaves the card`);
            }
        }
        [...rows.values()].forEach((row, index) => {
            const heights = row.map(card => box(card).height);
            if (Math.max(...heights) - Math.min(...heights) > 1) problems.push(`row ${index + 1}: heights ${heights.map(Math.round).join('/')}`);
            const bars = row.map(card => box(card.querySelector('.od-host-bottom')).top);
            if (Math.max(...bars) - Math.min(...bars) > 1) problems.push(`row ${index + 1}: actions at ${bars.map(Math.round).join('/')}`);
        });
        const head = list.closest('[data-panel]').querySelector('.od-panel-head');
        if (cards.length && box(head).bottom > box(cards[0]).top) problems.push('the heading covers the first row');
        if (list.closest('#connectionOverview').scrollWidth > list.closest('#connectionOverview').clientWidth + 1) problems.push('the overview scrolls sideways');
        return problems;
    });
}

for (const width of WIDTHS) {
    test(`host cards form an even grid in every theme at ${width}px`, async ({page}, testInfo) => {
        await openOverview(page, width);
        await page.mouse.move(0, 0);
        for (const theme of THEMES) {
            await page.evaluate(theme => { document.body.dataset.theme = theme; }, theme);
            await settle(page);
            expect(await gridProblems(page), `${theme} at ${width}px`).toEqual([]);
        }
        await page.evaluate(() => { document.body.dataset.theme = 'glass'; });
        await page.locator('section[data-panel="hosts"]').screenshot({path: testInfo.outputPath(`hosts-${width}.png`), animations: 'disabled'});
        // Rows of the same grid keep the same gap.
        const gaps = await page.locator('#overviewHostList').evaluate(list => {
            const cards = [...list.querySelectorAll('.od-host[data-host-id]')].map(card => card.getBoundingClientRect());
            const tops = [...new Set(cards.map(rect => Math.round(rect.top)))].sort((a, b) => a - b);
            return tops.slice(1).map((top, index) => top - Math.max(...cards.filter(rect => Math.round(rect.top) === tops[index]).map(rect => rect.bottom)));
        });
        for (const gap of gaps) expect(Math.abs(gap - gaps[0])).toBeLessThanOrEqual(1);
        expect(await sshAttempts(page)).toEqual([]);
        await assertNoExternalRequests(page);
    });
}

test('details open in a dialog and leave the grid as it is', async ({page}) => {
    await openOverview(page, 1440);
    const heights = () => page.locator('#overviewHostList .od-host[data-host-id]').evaluateAll(cards => cards.map(card => Math.round(card.getBoundingClientRect().height)));
    const before = await heights();
    const card = page.locator('#overviewHostList .od-host[data-host-id="grid-hypervisor"]');
    await expect(card.locator('details')).toHaveCount(0);
    // Logo, name and address are one button; it opens the details.
    const head = card.getByRole('button', {name: 'hypervisor-1, root@192.0.2.10', exact: true});
    await expect(head).toHaveAttribute('aria-haspopup', 'dialog');
    await expect(head).toHaveAttribute('aria-expanded', 'false');
    await head.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', {name: 'hypervisor-1'});
    await expect(dialog).toBeVisible();
    await expect(head).toHaveAttribute('aria-expanded', 'true');
    await expect(dialog.getByRole('button', {name: 'Close'})).toBeFocused();
    await expect(dialog.getByRole('heading', {name: 'Host profile'})).toBeVisible();
    await expect(dialog.getByRole('heading', {name: 'Configuration readiness'})).toBeVisible();
    await expect(dialog.locator('.od-host-profile dt')).toHaveText(['System', 'Machine', 'Role', 'Detection']);
    await expect(dialog.locator('.od-host-profile dd').nth(1)).toHaveText('Bare Metal · 7 guests');
    await expect(dialog.locator('.od-host-context')).toContainText('Configuration checks do not test login or permissions.');
    expect(await heights()).toEqual(before);
    // The dialog follows profile updates and keeps its focus.
    await dialog.getByRole('button', {name: 'Close'}).focus();
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(profile => profile.id === 'grid-hypervisor'
        ? {...profile, name: 'hypervisor-1 prime'} : profile)));
    await expect(page.getByRole('dialog', {name: 'hypervisor-1 prime'})).toBeVisible();
    await expect(page.getByRole('dialog', {name: 'hypervisor-1 prime'}).getByRole('button', {name: 'Close'})).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.locator('#overviewHostList [data-key="head:grid-hypervisor"]')).toBeFocused();
    await expect(page.locator('#overviewHostList [data-key="head:grid-hypervisor"]')).toHaveAttribute('aria-expanded', 'false');
    // A click on the card opens the details, a second click closes them.
    await page.locator('#overviewHostList [data-key="head:grid-hypervisor"]').click();
    await expect(page.getByRole('dialog', {name: 'hypervisor-1 prime'})).toBeVisible();
    await page.locator('#overviewHostList [data-key="head:grid-hypervisor"]').click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(await heights()).toEqual(before);
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});

test('the heading of a scrolling hosts panel never covers a card', async ({page}) => {
    // A panel with a stored height scrolls its own body, as after resizing it.
    try {
        await openOverview(page, 1280, {panels: [{id: 'hosts', w: 12, h: 60}]});
        const panel = page.locator('section[data-panel="hosts"]');
        await expect(panel).toHaveAttribute('data-fixed-height', 'true');
        const body = panel.locator('.od-panel-body');
        await panel.scrollIntoViewIfNeeded();
        const covered = () => page.evaluate(() => {
            const panel = document.querySelector('section[data-panel="hosts"]');
            const head = panel.querySelector('.od-panel-head').getBoundingClientRect();
            const body = panel.querySelector('.od-panel-body').getBoundingClientRect();
            const problems = [];
            if (head.bottom > body.top) problems.push('heading reaches into the scrolling area');
            const top = panel.querySelector('.od-panel-body').scrollTop < 1;
            // At the top nothing is cut; scrolled, the body clips what passed under the heading.
            for (const card of panel.querySelectorAll('.od-host[data-host-id]')) {
                const rect = card.getBoundingClientRect();
                if (top && rect.top < body.top - 0.5) problems.push(`${card.dataset.hostId} cut at the top`);
                const probe = document.elementFromPoint(rect.left + 20, (head.top + head.bottom) / 2);
                if (rect.top < head.bottom && card.contains(probe)) problems.push(`${card.dataset.hostId} painted over the heading`);
            }
            return {problems, separated: getComputedStyle(panel.querySelector('.od-panel-head'), '::after').opacity === '1'};
        });
        // At the top, a lifted (focused) first card stays whole.
        await page.locator('#overviewHostList .od-connect').first().focus();
        await settle(page);
        expect((await covered()).problems).toEqual([]);
        expect((await covered()).separated).toBe(false);
        // Scrolled, the heading is set off from the cards that pass under it.
        await body.evaluate(element => { element.scrollTop = 140; });
        await expect.poll(async () => (await covered()).separated).toBe(true);
        expect((await covered()).problems).toEqual([]);
        await body.evaluate(element => { element.scrollTop = 0; });
        await expect.poll(async () => (await covered()).separated).toBe(false);
    } finally {
        const csrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
        expect((await page.request.put('/api/overview/preferences', {data: {panels: null}, headers: {'X-CSRFToken': csrf}})).ok()).toBe(true);
    }
    await assertNoExternalRequests(page);
});
