const {test, expect} = require('playwright/test');
const {login, waitForInventory, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// The hosts pane keeps the order an account gives its cards: a flat list
// across groups, stored on the server in the overview preferences.
// Favourites always come first; the order applies inside the favourites
// and inside the other hosts.
// Go only (go_only in go-suite.json): the Python route refuses host_order,
// so the default Python run leaves this file out.

const csrf = page => page.locator('meta[name="csrf-token"]').getAttribute('content');
const resetOrder = async page => {
    const response = await page.request.put('/api/overview/preferences', {data: {host_order: null}, headers: {'X-CSRFToken': await csrf(page)}});
    expect(response.ok()).toBe(true);
};
const shown = page => page.locator('#overviewHostList .od-host[data-host-id]').evaluateAll(cards => cards.map(card => card.dataset.hostId));
const card = (page, id) => page.locator(`#overviewHostList .od-host[data-host-id="${id}"]`);
const handle = (page, id) => card(page, id).locator('.od-host-handle');
const status = page => page.locator('#odLayoutStatus');
const favourites = page => page.evaluate(() => ProfileManager.profiles.filter(item => item.favorite === true).map(item => item.id));
const stored = page => page.locator('#overviewPreferences').evaluate(element => JSON.parse(element.textContent).host_order ?? null);

async function open(page, width = 1440) {
    await page.setViewportSize({width, height: 1000});
    await login(page, 'e2e_admin', {workspace: false});
    await resetOrder(page);
    await page.reload();
    await waitForInventory(page);
    await installSshConnectTrap(page);
    await expect(page.locator('#overviewHostList .od-host[data-host-id]').first()).toBeVisible();
}
async function reload(page) {
    await page.reload();
    await waitForInventory(page);
    await expect(page.locator('#overviewHostList .od-host[data-host-id]').first()).toBeVisible();
}
// The order the server keeps, read from a freshly rendered page.
async function serverOrder(page) {
    const html = await (await page.request.get('/')).text();
    const block = html.match(/<script type="application\/json" id="overviewPreferences">([^<]*)<\/script>/);
    return JSON.parse(block[1]).host_order ?? null;
}
const saved = page => page.waitForResponse(response => response.url().endsWith('/api/overview/preferences') && response.request().method() === 'PUT');

test.afterEach(async ({page}) => { await resetOrder(page); });

test('the arrange mode moves hosts with the keyboard and the order survives a reload', async ({page}) => {
    await open(page);
    const before = await shown(page);
    const favs = await favourites(page);
    expect(favs.length).toBeGreaterThan(0);
    expect(before.slice(0, favs.length).sort()).toEqual([...favs].sort());
    expect(await stored(page)).toBeNull();

    const arrange = page.getByRole('button', {name: 'Arrange', exact: true});
    await expect(arrange).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('.od-host-handle')).toHaveCount(0);
    await arrange.click();
    await expect(arrange).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#odArrangeHint')).toContainText('arrow keys');
    await expect(page.getByRole('button', {name: 'Reset order'})).toBeDisabled();
    await expect(page.locator('.od-host-handle')).toHaveCount(before.length);
    // The actions of the cards rest while the hosts are arranged.
    const first = before[favs.length];
    await expect(card(page, first).locator('.od-host-bottom')).toHaveAttribute('inert', '');

    // A host after the favourites moves with the arrow keys, Home and End.
    const mover = before[favs.length + 2];
    const name = await card(page, mover).locator('.od-host-name').textContent();
    const total = before.length;
    await expect(handle(page, mover)).toHaveAccessibleName(`Move ${name}, position ${favs.length + 3} of ${total}`);
    await handle(page, mover).focus();
    const write = saved(page);
    await page.keyboard.press('ArrowUp');
    await expect.poll(() => shown(page)).toEqual([...before.slice(0, favs.length + 1), mover, before[favs.length + 1], ...before.slice(favs.length + 3)]);
    await expect(status(page)).toHaveText(`${name} moved to position ${favs.length + 2} of ${total}.`);
    await expect(handle(page, mover)).toBeFocused();
    expect((await write).ok()).toBe(true);
    await page.keyboard.press('Home');
    await expect.poll(async () => (await shown(page))[favs.length]).toBe(mover);
    await expect(status(page)).toHaveText(`${name} moved to position ${favs.length + 1} of ${total}.`);
    // Favourites always come first.
    await page.keyboard.press('ArrowUp');
    await expect(status(page)).toHaveText(`${name} is first after the favorites. Favorites always come first.`);
    await expect.poll(async () => (await shown(page))[favs.length]).toBe(mover);
    await page.keyboard.press('End');
    await expect.poll(async () => (await shown(page)).at(-1)).toBe(mover);
    await expect(status(page)).toHaveText(`${name} moved to position ${total} of ${total}.`);
    await page.keyboard.press('ArrowRight');
    await expect(status(page)).toHaveText(`${name} is already last.`);
    await page.keyboard.press('ArrowLeft');
    await expect.poll(async () => (await shown(page)).at(-2)).toBe(mover);
    const arranged = await shown(page);
    await expect.poll(() => serverOrder(page)).toEqual(arranged);
    await expect(page.getByRole('button', {name: 'Reset order'})).toBeEnabled();

    await page.getByRole('button', {name: 'Done'}).click();
    await expect(arrange).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('.od-host-handle')).toHaveCount(0);
    await expect(card(page, first).locator('.od-host-bottom')).not.toHaveAttribute('inert', '');

    await reload(page);
    expect(await shown(page)).toEqual(arranged);
    expect(await stored(page)).toEqual(arranged);
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});

test('dragging a card by its handle places it, favourites are no target, and reset restores the default order', async ({page}) => {
    await open(page);
    const before = await shown(page);
    const favs = (await favourites(page)).length;
    await page.getByRole('button', {name: 'Arrange', exact: true}).click();
    const [a, b, c] = before.slice(favs, favs + 3);

    // Status updates may rebuild the cards; read positions once they hold.
    const points = async (id, targetId) => {
        await expect.poll(() => page.evaluate(async () => {
            const firstCard = document.querySelector('#overviewHostList .od-host');
            await new Promise(resolve => setTimeout(resolve, 600));
            return firstCard?.isConnected === true;
        }), {timeout: 15000}).toBe(true);
        return page.locator('#overviewHostList').evaluate((list, [id, targetId]) => {
            const target = list.querySelector(`.od-host[data-host-id="${targetId}"]`);
            target.scrollIntoView({block: 'center'});
            const grip = list.querySelector(`.od-host[data-host-id="${id}"] .od-host-handle`).getBoundingClientRect();
            const box = target.getBoundingClientRect();
            return {from: {x: grip.x + grip.width / 2, y: grip.y + grip.height / 2}, to: {x: box.x, y: box.y, width: box.width, height: box.height}};
        }, [id, targetId]);
    };
    const drag = async (id, targetId, side) => {
        const {from, to} = await points(id, targetId);
        await page.mouse.move(from.x, from.y);
        await page.mouse.down();
        await page.mouse.move(side === 'before' ? to.x + to.width * 0.2 : to.x + to.width * 0.8, to.y + to.height / 2, {steps: 8});
        await expect(card(page, targetId)).toHaveAttribute('data-drop', side);
        await page.mouse.up();
    };
    await drag(c, a, 'before');
    await expect.poll(async () => (await shown(page)).slice(favs, favs + 3)).toEqual([c, a, b]);
    await expect(status(page)).toHaveText(new RegExp(`moved to position ${favs + 1} of ${before.length}\\.$`));
    await drag(a, b, 'after');
    await expect.poll(async () => (await shown(page)).slice(favs, favs + 3)).toEqual([c, b, a]);

    // A favourite is no target for the other hosts.
    if (favs) {
        const {from, to} = await points(c, before[0]);
        await page.mouse.move(from.x, from.y);
        await page.mouse.down();
        await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, {steps: 8});
        await expect(card(page, before[0])).not.toHaveAttribute('data-drop', /.+/);
        await page.mouse.up();
        await expect.poll(async () => (await shown(page)).slice(0, favs + 1)).toEqual([...before.slice(0, favs), c]);
    }
    const arranged = await shown(page);
    await expect.poll(() => serverOrder(page)).toEqual(arranged);
    await reload(page);
    expect(await shown(page)).toEqual(arranged);

    await page.getByRole('button', {name: 'Arrange', exact: true}).click();
    const write = saved(page);
    await page.getByRole('button', {name: 'Reset order'}).click();
    expect((await write).ok()).toBe(true);
    await expect.poll(() => shown(page)).toEqual(before);
    await expect(status(page)).toHaveText('The default order is back.');
    await reload(page);
    expect(await shown(page)).toEqual(before);
    expect(await stored(page)).toBeNull();
    await assertNoExternalRequests(page);
});

test('a search or filter locks the order and keeps it', async ({page}) => {
    await open(page, 390);
    const before = await shown(page);
    await page.getByRole('button', {name: 'Arrange', exact: true}).click();
    await page.locator('#overviewSearch').fill('Ops');
    await expect(page.locator('#odArrangeHint')).toHaveText('Clear the search and filters to change the order.');
    const visible = await shown(page);
    expect(visible.length).toBeGreaterThan(1);
    await expect(handle(page, visible[1])).toBeDisabled();
    await page.locator('#overviewSearch').fill('');
    await expect(page.locator('#odArrangeHint')).toContainText('arrow keys');
    await expect(handle(page, before.at(-1))).toBeEnabled();
    expect(await shown(page)).toEqual(before);
    // Touch-sized handles on a phone.
    const box = await handle(page, before.at(-1)).boundingBox();
    expect(box.height).toBeGreaterThanOrEqual(44);
    await handle(page, before.at(-1)).focus();
    await page.keyboard.press('Home');
    await expect.poll(async () => (await shown(page)).indexOf(before.at(-1))).toBe((await favourites(page)).length);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', {name: 'Arrange', exact: true})).toHaveAttribute('aria-pressed', 'false');
    await expect(page.getByRole('button', {name: 'Arrange', exact: true})).toBeFocused();
    await assertNoExternalRequests(page);
});
