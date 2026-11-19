const test = require('node:test');
const assert = require('node:assert/strict');
const HerdrControlBar = require('../../static/js/herdr-control-bar.js');

class FakeElement {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.attributes = {};
        this.dataset = {};
        this.listeners = {};
        this.hidden = false;
        this.textContent = '';
        this.title = '';
        this.className = '';
        const classes = new Set();
        this.classList = {
            toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)),
            contains: name => classes.has(name),
        };
    }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    getAttribute(name) { return this.attributes[name]; }
    appendChild(child) { this.children.push(child); return child; }
    addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
    querySelectorAll(selector) {
        assert.equal(selector, '[data-herdr-action]');
        return this.children.filter(child => child.dataset.herdrAction);
    }
    dispatch(type) {
        const event = {defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
        for (const listener of this.listeners[type] || []) listener(event);
        return event;
    }
}

const fakeDocument = {createElement: tag => new FakeElement(tag)};
const HERDR = {id: 's-herdr', connected: true, useHerdr: true, useTmux: false};

function harness({session = HERDR, confirm = () => Promise.resolve(true), storage} = {}) {
    const calls = [];
    const state = {session};
    const bar = new FakeElement('div');
    const toggleButton = new FakeElement('button');
    const controller = HerdrControlBar.create({
        bar, toggleButton, document: fakeDocument, storage,
        activeSession: () => state.session,
        send: (id, data) => { calls.push(['send', id, data]); return Promise.resolve(true); },
        focusTerminal: id => calls.push(['focus', id]),
        confirm: request => { calls.push(['confirm', request.message]); return confirm(request); },
        onLayoutChange: () => calls.push(['layout']),
        translate: key => key,
    });
    controller.render();
    const button = id => bar.children.find(child => child.dataset.herdrAction === id);
    return {bar, toggleButton, controller, calls, state, button};
}

const tick = () => new Promise(resolve => setImmediate(resolve));

test('every action sends exactly the Herdr prefix and its key', () => {
    assert.deepEqual(Object.fromEntries(HerdrControlBar.ACTIONS.map(action => [action.id, HerdrControlBar.bytesFor(action.id)])), {
        prefix: '\x02',
        splitRight: '\x02v',
        splitDown: '\x02-',
        zoom: '\x02z',
        previousPane: '\x02\x1b[Z',
        nextPane: '\x02\t',
        newTab: '\x02c',
        previousTab: '\x02p',
        nextTab: '\x02n',
        workspaces: '\x02w',
        sidebar: '\x02b',
        renamePane: '\x02P',
        help: '\x02?',
        settings: '\x02s',
        closePane: '\x02x',
    });
    assert.equal(HerdrControlBar.bytesFor('detach'), null);
    assert.equal(HerdrControlBar.ACTIONS.some(action => HerdrControlBar.bytesFor(action.id) === '\x02q'), false);
});

test('a click sends through the terminal input and gives the focus back', async () => {
    const h = harness();
    assert.equal(h.bar.hidden, false);
    const press = h.button('splitRight').dispatch('mousedown');
    assert.equal(press.defaultPrevented, true);
    h.button('splitRight').dispatch('click');
    await tick();
    assert.deepEqual(h.calls.filter(call => call[0] !== 'layout'), [
        ['send', 's-herdr', '\x02v'],
        ['focus', 's-herdr'],
    ]);
});

test('buttons carry a label, a tooltip with the key and no free text', () => {
    const h = harness();
    for (const button of h.bar.children) {
        assert.equal(button.type, 'button');
        assert.ok(button.getAttribute('aria-label'));
        assert.match(button.title, /\(Ctrl\+B( \S+)?\)$/);
    }
    assert.equal(h.bar.getAttribute('role'), 'toolbar');
    assert.equal(h.button('nextPane').title, 'Next pane (Ctrl+B Tab)');
});

test('the bar and its toggle exist only for Herdr sessions', () => {
    for (const session of [
        null,
        {id: 's-plain', connected: true, useHerdr: false},
        {id: 's-tmux', connected: true, useHerdr: true, useTmux: true},
        {id: 's-off', connected: false, useHerdr: true},
        {id: 's-flag', connected: true, useHerdr: 'true'},
    ]) {
        const h = harness({session});
        assert.equal(h.bar.hidden, true, JSON.stringify(session));
        assert.equal(h.toggleButton.hidden, true);
        assert.equal(h.controller.available(), false);
    }
});

test('actions never reach a session that is not a Herdr session', async () => {
    const h = harness({session: {id: 's-tmux', connected: true, useHerdr: true, useTmux: true}});
    assert.equal(await h.controller.run('splitRight'), false);
    assert.equal(await h.controller.run('unknown'), false);
    assert.deepEqual(h.calls, []);
});

test('closing a pane asks first and sends nothing when declined', async () => {
    const declined = harness({confirm: () => Promise.resolve(false)});
    assert.equal(await declined.controller.run('closePane'), false);
    assert.deepEqual(declined.calls.filter(call => call[0] !== 'layout').map(call => call[0]), ['confirm', 'focus']);

    const accepted = harness();
    assert.equal(await accepted.controller.run('closePane'), true);
    assert.deepEqual(accepted.calls.filter(call => call[0] !== 'layout'), [
        ['confirm', 'Close the focused Herdr pane? Programs running in it are ended.'],
        ['send', 's-herdr', '\x02x'],
        ['focus', 's-herdr'],
    ]);
});

test('a session switch during the confirmation cancels the close', async () => {
    let release;
    const h = harness({confirm: () => new Promise(resolve => { release = resolve; })});
    const closing = h.controller.run('closePane');
    h.state.session = {id: 's-other', connected: true, useHerdr: true};
    release(true);
    assert.equal(await closing, false);
    assert.equal(h.calls.some(call => call[0] === 'send'), false);
});

test('the toggle hides the bar, remembers the choice and survives broken storage', () => {
    const values = new Map();
    const storage = {getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value)};
    const h = harness({storage});
    assert.equal(h.toggleButton.hidden, false);
    assert.equal(h.toggleButton.getAttribute('aria-pressed'), 'true');
    h.toggleButton.dispatch('click');
    assert.equal(h.bar.hidden, true);
    assert.equal(h.toggleButton.getAttribute('aria-pressed'), 'false');
    assert.deepEqual([...values], [['webssh.herdrControlBar', 'off']]);
    assert.deepEqual(h.calls.slice(-2), [['layout'], ['focus', 's-herdr']]);
    assert.equal(harness({storage}).bar.hidden, true);

    const broken = {getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }};
    const fallback = harness({storage: broken});
    assert.equal(fallback.bar.hidden, false);
    fallback.toggleButton.dispatch('click');
    assert.equal(fallback.bar.hidden, true);
});

test('showing or hiding the bar asks the terminals to refit once per change', () => {
    const h = harness({session: null});
    assert.deepEqual(h.calls, []);
    h.state.session = HERDR;
    h.controller.render();
    h.controller.render();
    assert.deepEqual(h.calls, [['layout']]);
    h.state.session = null;
    h.controller.render();
    assert.deepEqual(h.calls, [['layout'], ['layout']]);
});
