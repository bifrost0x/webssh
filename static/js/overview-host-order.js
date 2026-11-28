/* Order of the overview host cards: a flat list of host ids per account,
   stored in the overview preferences. Favourites always come first; the
   saved order applies inside the favourites and inside the other hosts.
   Pure functions, exported for tests. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.OverviewHostOrder = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const favourite = host => host.favorite === true;

    /**
     * The hosts in pane order. `hosts` comes in the default order; without a
     * saved order it stays as it is. Hosts the order does not name (added
     * later) follow the named ones in their default order.
     */
    function arranged(hosts, order) {
        if (!Array.isArray(order)) return hosts;
        const rank = new Map(order.map((id, index) => [id, index]));
        const sort = list => list.map((host, index) => [host, rank.has(host.id) ? rank.get(host.id) : order.length + index])
            .sort((a, b) => a[1] - b[1]).map(([host]) => host);
        return [...sort(hosts.filter(favourite)), ...sort(hosts.filter(host => !favourite(host)))];
    }

    /** The hosts a card can trade places with: the favourites or the others. */
    function section(hosts, id) {
        const host = hosts.find(item => item.id === id);
        return host ? hosts.filter(item => favourite(item) === favourite(host)) : [];
    }

    /**
     * Moves a host to `index` inside its section (clamped). Returns the new
     * id order of the whole pane, or null when the host stays where it is.
     */
    function moveTo(hosts, id, index) {
        const peers = section(hosts, id);
        const from = peers.findIndex(item => item.id === id);
        const to = Math.max(0, Math.min(peers.length - 1, index));
        if (from < 0 || from === to) return null;
        const moved = peers.filter(item => item.id !== id);
        moved.splice(to, 0, peers[from]);
        const others = hosts.filter(item => favourite(item) !== favourite(peers[from]));
        return (favourite(peers[from]) ? [...moved, ...others] : [...others, ...moved]).map(item => item.id);
    }

    /** Where a host stands inside its section, zero-based. */
    function position(hosts, id) {
        const peers = section(hosts, id);
        return {index: peers.findIndex(item => item.id === id), count: peers.length};
    }

    /**
     * Places a host before or after another card of its section. Returns
     * the new id order, or null when the cards are in different sections
     * or nothing changes.
     */
    function place(hosts, id, targetId, after) {
        const peers = section(hosts, id);
        const target = peers.findIndex(item => item.id === targetId);
        const from = peers.findIndex(item => item.id === id);
        if (target < 0 || from < 0 || id === targetId) return null;
        const index = target + (after ? 1 : 0) - (from < target ? 1 : 0);
        return moveTo(hosts, id, index);
    }

    return {arranged, section, moveTo, position, place};
}));
