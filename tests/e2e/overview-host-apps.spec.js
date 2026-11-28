const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// The overview names what runs on a host: apps as chips with their name
// (and logo where one is bundled) in at most two lines, then "+N"; what the
// host runs on (containers, web servers, databases, VPN) in one quiet line.
const THEMES = ['glass', 'paper'];
const WIDTHS = [1440, 1280, 1024, 390];

function hosts() {
    const now = Math.floor(Date.now() / 1000);
    const seen = extra => ({detection_state: 'detected', platform_checked_at: now - 3600, services_checked_at: now - 3600, ...extra});
    return [
        {id: 'apps-media', name: 'media-1', host: '192.0.2.12', username: 'media', group: 'Homelab',
            ...seen({detected_platform: 'ubuntu', detected_os_version: '24.04', detected_virt: 'vm',
                detected_services: ['docker', 'jellyfin', 'sonarr', 'radarr', 'prowlarr', 'bazarr', 'qbittorrent', 'overseerr', 'traefik', 'portainer', 'watchtower']})},
        {id: 'apps-cloud', name: 'cloud-1', host: '192.0.2.14', username: 'ops', group: 'Production',
            ...seen({detected_platform: 'debian', detected_os_version: '12', detected_virt: 'lxc', detected_services: ['apache', 'mariadb', 'nextcloud', 'redis']})},
        {id: 'apps-worker', name: 'Worker', host: '198.51.100.20', username: 'ops', group: 'Lokal',
            ...seen({detected_platform: 'archlinux', detected_virt: 'bare-metal', detected_services: ['docker']})},
        {id: 'apps-fresh', name: 'fresh-host', host: '198.51.100.9', username: 'ops', group: 'Lokal', detection_state: 'pending', detected_services: []},
        {id: 'apps-pve', name: 'hypervisor-1', host: '192.0.2.10', username: 'root', group: 'Homelab',
            ...seen({detected_platform: 'proxmox', detected_os_version: '8.2', detected_virt: 'bare-metal', detected_guests: 7, detected_services: []})},
        {id: 'apps-long', name: 'legacy-fileserver-basement-rack-02.customer.internal', host: 'fs02.customer-with-long-domain.example',
            username: 'administrator', group: 'Customer systems with a long group name',
            ...seen({detected_platform: 'ubuntu', detected_os_version: '22.04', detected_virt: 'vm', detected_container_access: 'denied',
                detected_services: ['docker', 'audiobookshelf', 'stirlingpdf', 'uptimekuma', 'paperless', 'postgresql']})},
        {id: 'apps-quiet', name: 'quiet', host: '198.51.100.3', username: 'ops', group: 'Lokal',
            ...seen({detected_platform: 'debian', detected_os_version: '12', detected_services: []})},
    ];
}

async function openOverview(page, width) {
    await page.setViewportSize({width, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    const list = hosts();
    await page.route('**/api/overview/status', route => route.fulfill({json: {generated_at: Date.now() / 1000,
        hosts: list.map(host => ({id: host.id, state: 'ready'}))}}));
    await installSshConnectTrap(page);
    const readiness = page.waitForResponse('**/api/overview/status');
    await page.evaluate(items => ProfileManager.setProfiles(items.map(item => ({port: 22, auth_type: 'password', key_id: null,
        favorite: false, jump_host_id: null, socks_proxy_id: null, ...item}))), list);
    await readiness;
    await expect(page.locator('#overviewHostList .od-host[data-host-id]')).toHaveCount(list.length);
    await settle(page);
}
const settle = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
const card = (page, id) => page.locator(`#overviewHostList .od-host[data-host-id="${id}"]`);

// Problems of the app chips and the grid, empty when every card fits.
function problems(page) {
    return page.locator('#overviewHostList').evaluate(list => {
        const found = [];
        const box = element => element.getBoundingClientRect();
        const cards = [...list.querySelectorAll('.od-host[data-host-id]')];
        for (const card of cards) {
            const name = card.dataset.hostId;
            const bounds = box(card);
            for (const part of card.querySelectorAll('*')) {
                if (!part.getClientRects().length) continue;
                const rect = box(part);
                if (rect.left < bounds.left - 1 || rect.right > bounds.right + 1) found.push(`${name}: ${part.className} leaves the card`);
            }
            const chips = [...card.querySelectorAll('.od-app')];
            const shown = chips.filter(chip => !chip.hidden && chip.getClientRects().length);
            const lines = new Set(shown.map(chip => Math.round(box(chip).top)));
            if (lines.size > 2) found.push(`${name}: chips in ${lines.size} lines`);
            if (card.querySelector('.od-app .host-service-monogram')) found.push(`${name}: a monogram stands in for a logo`);
            if (shown.some(chip => !chip.textContent.trim())) found.push(`${name}: a chip without its name`);
            const more = card.querySelector('.od-app-more');
            const hidden = chips.length - shown.length;
            if (more && (more.hidden ? hidden > 0 : more.textContent.trim() !== `+${hidden}`)) found.push(`${name}: +N says ${more.hidden ? 'nothing' : more.textContent} for ${hidden}`);
            if (!more && hidden) found.push(`${name}: ${hidden} hidden without +N`);
        }
        const rows = new Map();
        cards.forEach(card => {
            const top = Math.round(box(card).top);
            rows.set(top, [...(rows.get(top) || []), box(card).height]);
        });
        [...rows.values()].forEach((heights, index) => {
            if (Math.max(...heights) - Math.min(...heights) > 1) found.push(`row ${index + 1}: heights ${heights.map(Math.round).join('/')}`);
        });
        return found;
    });
}

for (const width of WIDTHS) {
    test(`app chips fit two lines and the cards keep one height at ${width}px`, async ({page}, testInfo) => {
        await openOverview(page, width);
        await page.mouse.move(0, 0);
        for (const theme of THEMES) {
            await page.evaluate(theme => { document.body.dataset.theme = theme; }, theme);
            await settle(page);
            await expect.poll(() => problems(page), {message: `${theme} at ${width}px`}).toEqual([]);
            await page.locator('section[data-panel="hosts"]').screenshot({path: testInfo.outputPath(`apps-${theme}-${width}.png`), animations: 'disabled'});
        }
        await assertNoExternalRequests(page);
    });
}

test('cards name the apps and say what the host runs on', async ({page}) => {
    await openOverview(page, 1440);
    const media = card(page, 'apps-media');
    const apps = media.getByRole('list', {name: 'Apps on media-1'});
    await expect(apps.locator('.od-app').first()).toHaveText('Jellyfin');
    await expect(apps.locator('.od-app').first().locator('.host-service-icon')).toHaveCount(1);
    expect(await apps.locator('.od-app').allTextContents()).toEqual(['Jellyfin', 'Bazarr', 'Overseerr', 'Prowlarr', 'qBittorrent', 'Radarr', 'Sonarr']);
    await expect(media.locator('.od-host-runs')).toHaveText('Runs on Traefik · Docker · Portainer · Watchtower');
    // A service without a bundled logo shows its name alone, never a monogram tile.
    const bazarr = apps.locator('.od-app[data-service="bazarr"]');
    await expect(bazarr).toHaveText('Bazarr');
    await expect(bazarr.locator('.host-service-icon, .host-service-monogram')).toHaveCount(0);
    // The machine kind is text in the system line.
    await expect(media.locator('.od-host-os')).toHaveText('Ubuntu 24.04');
    await expect(media.locator('.od-virt')).toHaveText('VM');
    expect(await media.locator('.od-host-logo .od-virt').count()).toBe(0);

    await expect(card(page, 'apps-cloud').locator('.od-app')).toHaveText(['Nextcloud']);
    await expect(card(page, 'apps-cloud').locator('.od-host-runs')).toHaveText('Runs on Apache · MariaDB · Redis');
    await expect(card(page, 'apps-worker').locator('.od-host-empty')).toHaveText('No apps detected');
    await expect(card(page, 'apps-worker').locator('.od-host-runs')).toHaveText('Runs on Docker');
    await expect(card(page, 'apps-fresh').locator('.od-host-empty')).toHaveText('Services are read on the next connection.');
    await expect(card(page, 'apps-quiet').locator('.od-host-empty')).toHaveText('No apps detected');
    await expect(card(page, 'apps-quiet').locator('.od-host-runs')).toHaveText('');
    await expect(card(page, 'apps-pve').locator('.od-fact-chip[data-kind="guests"]')).toHaveText(/7 guests/);
    await expect(card(page, 'apps-pve').locator('.od-host-empty')).toHaveCount(0);
    await expect(card(page, 'apps-long').locator('.od-hint-chip[data-kind="containers"]')).toHaveText(/Containers not readable/);

    // "+N" names what it hides and opens the details with every service.
    await page.setViewportSize({width: 1024, height: 900});
    const more = media.locator('.od-app-more');
    await expect(more).toBeVisible();
    const hidden = await apps.locator('.od-app[hidden]').allTextContents();
    expect(hidden.length).toBeGreaterThan(0);
    await expect(more).toHaveText(`+${hidden.length}`);
    await expect(more).toHaveAccessibleName(`${hidden.length} more apps: ${hidden.join(', ')}`);
    await expect(more).toHaveAttribute('aria-haspopup', 'dialog');
    await more.click();
    const details = page.getByRole('dialog', {name: 'media-1'});
    await expect(details).toBeVisible();
    for (const name of hidden) await expect(details.locator('.od-host-profile')).toContainText(name);
    await page.keyboard.press('Escape');
    await expect(more).toBeFocused();
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});
