const test = require('node:test');
const assert = require('node:assert/strict');

// A resize observer that records what it watches and lets the test deliver entries.
const watched = new Set();
let deliver = null;
globalThis.ResizeObserver = class {
    constructor(callback) { deliver = targets => callback(targets.map(target => ({target}))); }
    observe(target) { watched.add(target); }
    unobserve(target) { watched.delete(target); }
};
const HostPlatform = require('../../static/js/host-platform.js');
require('../../static/js/host-identity.js');

const root = {isRoot: true};
function createElement(tag = 'span') {
    const element = {
        tagName: tag.toUpperCase(), children: [], parentNode: null, dataset: {}, attributes: {}, style: {},
        className: '', textContent: '', title: '', hidden: false, rendered: true,
        classList: {contains: name => String(element.className).split(/\s+/).includes(name)},
        get isConnected() {
            let node = this;
            while (node.parentNode) node = node.parentNode;
            return node === root;
        },
        get firstElementChild() { return this.children[0] || null; },
        setAttribute(name, value) { this.attributes[name] = String(value); },
        removeAttribute(name) { delete this.attributes[name]; },
        append(...nodes) { nodes.forEach(node => this.insertBefore(node, null)); },
        insertBefore(child, reference) {
            if (child.parentNode) child.parentNode.children = child.parentNode.children.filter(node => node !== child);
            child.parentNode = this;
            const index = reference ? this.children.indexOf(reference) : -1;
            this.children.splice(index < 0 ? this.children.length : index, 0, child);
            return child;
        },
        replaceWith(node) {
            const parent = this.parentNode;
            parent.insertBefore(node, this);
            this.remove();
        },
        remove() {
            if (!this.parentNode) return;
            this.parentNode.children = this.parentNode.children.filter(node => node !== this);
            this.parentNode = null;
        },
        contains(node) {
            for (let current = node; current; current = current.parentNode) if (current === this) return true;
            return false;
        },
        querySelector(selector) {
            const name = selector.slice(1);
            const visit = node => (String(node.className).split(/\s+/).includes(name) ? node : node.children.map(visit).find(Boolean));
            return this.children.map(visit).find(Boolean) || null;
        },
        // Not rendered while it or an ancestor is hidden or marked as not rendered.
        getClientRects() {
            for (let node = this; node && !node.isRoot; node = node.parentNode) if (!node.rendered) return [];
            return [{}];
        },
        scrollWidth: 0,
        clientWidth: 0,
    };
    return element;
}
const doc = {createElement};
const profile = services => ({id: 'h', name: 'host', host: 'h.example.test', username: 'ops', port: 22,
    detected_platform: 'debian', detection_state: 'detected', detected_services: services});
const session = {host: 'h.example.test', username: 'ops', port: 22, profileId: 'h'};
const barText = pane => pane.querySelector('.session-identity-text');

function mountedPane() {
    const pane = createElement('div');
    pane.parentNode = root;
    return pane;
}

test('a replaced or removed identity line stops being watched', () => {
    watched.clear();
    const pane = mountedPane();
    HostPlatform.markIdentityBar(pane, session, profile(['samba', 'docker']), doc);
    const first = barText(pane);
    assert.ok(watched.has(first));
    HostPlatform.markIdentityBar(pane, session, profile(['samba', 'nginx']), doc);
    const second = barText(pane);
    assert.notEqual(second, first);
    assert.equal(watched.has(first), false);
    assert.ok(watched.has(second));
    HostPlatform.markIdentityBar(pane, {...session, username: 'root'}, profile(['samba']), doc);
    assert.equal(pane.children.length, 0);
    assert.equal(watched.has(second), false);
});

test('tiles of a text that is not rendered are fitted once it shows', () => {
    watched.clear();
    const rail = mountedPane();
    rail.rendered = false;
    const name = createElement();
    const holder = createElement();
    const tiles = [createElement(), createElement()];
    holder.append(...tiles);
    rail.append(name, holder);
    // Two tiles are hidden from an earlier fit; a hidden rail measures nothing and changes nothing.
    tiles.forEach(tile => { tile.hidden = true; });
    HostPlatform.keepTilesFitting(holder, name);
    assert.deepEqual(tiles.map(tile => tile.hidden), [true, true]);
    assert.ok(watched.has(name));
    // Showing the rail resizes the name; the observer then fits the tiles.
    rail.rendered = true;
    deliver([name]);
    assert.deepEqual(tiles.map(tile => tile.hidden), [false, false]);
    assert.equal(holder.hidden, false);
});

test('releasing a container stops watching the texts inside it only', () => {
    watched.clear();
    const left = mountedPane();
    const right = mountedPane();
    for (const container of [left, right]) {
        const name = createElement();
        const holder = createElement();
        holder.append(createElement());
        container.append(name, holder);
        HostPlatform.keepTilesFitting(holder, name);
    }
    HostPlatform.releaseFits(left);
    assert.deepEqual([...watched], [right.children[0]]);
});
