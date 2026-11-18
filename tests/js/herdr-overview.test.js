const test = require('node:test');
const assert = require('node:assert/strict');

const herdr = require('../../static/js/herdr-overview.js');

function fakeDocument() {
    const doc = {activeElement: null, visibilityState: 'visible', listeners: {}, created: []};
    function element(tagName) {
        const listeners = {};
        const el = {
            tagName: tagName.toUpperCase(), children: [], parentNode: null, dataset: {}, attributes: {},
            hidden: false, className: '', title: '', type: '', dir: '', id: '', ownText: '',
            get textContent() {
                return this.ownText + this.children.map(child => child.textContent).join('');
            },
            set textContent(value) {
                this.children.forEach(child => { child.parentNode = null; });
                this.children = [];
                this.ownText = String(value);
            },
            set innerHTML(_value) { throw new Error('innerHTML must not be used'); },
            append(...nodes) {
                nodes.forEach(child => {
                    if (typeof child === 'string') throw new Error('append text through textContent');
                    child.parentNode = this;
                    this.children.push(child);
                });
            },
            replaceChildren(...nodes) {
                this.children.forEach(child => { child.parentNode = null; });
                this.children = [];
                this.ownText = '';
                this.append(...nodes);
            },
            setAttribute(name, value) { this.attributes[name] = String(value); },
            getAttribute(name) { return this.attributes[name] ?? null; },
            addEventListener(type, handler) { (listeners[type] ||= []).push(handler); },
            click() { (listeners.click || []).forEach(handler => handler({target: this})); },
            focus() { doc.activeElement = this; },
            contains(other) {
                for (let current = other; current; current = current.parentNode) if (current === this) return true;
                return false;
            },
        };
        doc.created.push(el);
        return el;
    }
    doc.createElement = element;
    const ids = {};
    doc.getElementById = id => ids[id] || null;
    doc.addEventListener = (type, handler) => { (doc.listeners[type] ||= []).push(handler); };
    const section = element('section');
    for (const id of ['odAgentsTotal', 'odAgentsHint', 'odAgentsHosts', 'odAgentsEmpty', 'odAgentsEmptyAction',
        'odAgentsDisabled', 'odAgentsFoot', 'odAgentsStatus']) {
        ids[id] = element(id === 'odAgentsEmptyAction' ? 'button' : 'div');
        ids[id].id = id;
        section.append(ids[id]);
    }
    ids.odAgentsDisabled.hidden = true;
    ids.odAgentsEmpty.hidden = true;
    section.hidden = true;
    return {doc, section, $: id => ids[id]};
}

function walk(root, visit) {
    visit(root);
    root.children.forEach(child => walk(child, visit));
}
function find(root, predicate) {
    const found = [];
    walk(root, el => { if (predicate(el)) found.push(el); });
    return found;
}
const byClass = (root, name) => find(root, el => el.className.split(' ').includes(name));
// Only rendered (not hidden) content counts as visible text.
function shownText(root) {
    if (root.hidden) return '';
    return root.ownText + root.children.map(shownText).join('');
}

function harness({profiles, sessions, enabled = true, translate} = {}) {
    const {doc, section, $} = fakeDocument();
    const view = {hidden: false};
    let clock = 1_700_000_000_000;
    let seq = 0;
    const timers = new Map();
    const requests = [];
    const opened = [];
    const connects = [];
    const hostsOpened = [];
    const windowListeners = {};
    const socketListeners = {};
    const state = {
        profiles: profiles || [{id: 'p1', name: 'web-01', herdr: true}],
        sessions: sessions || [{id: 's1', profileId: 'p1', connected: true, herdr: true}],
    };
    const controller = herdr.createController({
        doc, section, view, enabled, translate,
        win: {addEventListener: (type, handler) => { (windowListeners[type] ||= []).push(handler); }},
        socket: {
            emit(event, data, ack) { requests.push({event, data, ack, at: clock}); },
            on(event, handler) { socketListeners[event] = handler; },
        },
        profiles: () => state.profiles,
        sessions: () => state.sessions,
        language: () => 'en-GB',
        now: () => clock,
        setTimeout(fn, delay) { timers.set(++seq, {fn, at: clock + delay}); return seq; },
        clearTimeout(id) { timers.delete(id); },
        onOpenSession: (sessionId, profileId) => opened.push([sessionId, profileId]),
        onConnect: profileId => connects.push(profileId),
        onOpenHosts: () => hostsOpened.push(true),
    });
    controller.start();
    function advance(ms) {
        const end = clock + ms;
        for (;;) {
            const next = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
            if (!next) break;
            timers.delete(next[0]);
            clock = Math.max(clock, next[1].at);
            next[1].fn();
        }
        clock = end;
    }
    const reply = (index, result) => requests[index].ack(result);
    const ok = agents => ({success: true, agents, truncated: false, reason: null});
    const fail = reason => ({success: false, agents: [], truncated: false, reason});
    return {now: () => clock, controller, doc, section, view, $, state, requests, opened, connects, hostsOpened, timers, advance, reply, ok, fail,
        windowListeners, socketListeners, hosts: () => $('odAgentsHosts')};
}

const agent = (id, extra = {}) => ({id, kind: 'claude', label: `task ${id}`, cwd: `/srv/${id}`, status: 'working', ...extra});

test('statuses show an icon and a word as a hint from Herdr, unknown values become Unknown', () => {
    const h = harness();
    h.advance(0);
    const statuses = ['idle', 'working', 'blocked', 'done', 'unknown', 'paused', '__proto__', 7];
    h.reply(0, h.ok(statuses.map((status, index) => agent(`a${index}`, {status}))));
    const shown = byClass(h.hosts(), 'od-agent-status').map(el => [
        el.dataset.status, el.children[0].textContent, el.children[0].getAttribute('aria-hidden'), el.children[1].textContent, el.title]);
    assert.deepEqual(shown.slice(0, 6), [
        ['idle', 'pause_circle', 'true', 'Idle', 'Status reported by Herdr: Idle'],
        ['working', 'autorenew', 'true', 'Working', 'Status reported by Herdr: Working'],
        ['blocked', 'pan_tool', 'true', 'Blocked', 'Status reported by Herdr: Blocked'],
        ['done', 'check_circle', 'true', 'Done', 'Status reported by Herdr: Done'],
        ['unknown', 'help_outline', 'true', 'Unknown', 'Status reported by Herdr: Unknown'],
        ['unknown', 'help_outline', 'true', 'Unknown', 'Status reported by Herdr: Unknown'],
    ]);
    assert.equal(herdr.cleanAgents({agents: statuses.map((status, index) => agent(`a${index}`, {status}))})
        .agents.filter(item => item.status === 'unknown').length, 4);
    assert.equal(h.$('odAgentsHint').hidden, false);
    assert.equal(h.$('odAgentsTotal').textContent, String(statuses.length));
});

test('German status words follow the approved wording', () => {
    const words = {statusIdle: 'Untätig', statusWorking: 'Arbeitet', statusBlocked: 'Blockiert', statusDone: 'Fertig', statusUnknown: 'Unbekannt'};
    const h = harness({translate: key => words[key.slice(6)] || key});
    h.advance(0);
    h.reply(0, h.ok(['idle', 'working', 'blocked', 'done', 'unknown'].map((status, index) => agent(`a${index}`, {status}))));
    assert.deepEqual(byClass(h.hosts(), 'od-agent-status').map(el => el.children[1].textContent),
        ['Untätig', 'Arbeitet', 'Blockiert', 'Fertig', 'Unbekannt']);
});

test('every reason has its own state text; disconnected offers the existing Connect action', () => {
    const texts = new Map();
    for (const reason of ['not_installed', 'no_server', 'incompatible', 'timeout', 'invalid', 'unavailable']) {
        const h = harness();
        h.advance(0);
        h.reply(0, h.fail(reason));
        const [state] = byClass(h.hosts(), 'od-agents-state');
        assert.equal(state.dataset.reason, reason);
        texts.set(reason, state.children[1].textContent);
        assert.equal(byClass(h.hosts(), 'od-connect').length, 0, reason);
    }
    const h = harness({sessions: []});
    const [state] = byClass(h.hosts(), 'od-agents-state');
    assert.equal(state.dataset.reason, 'disconnected');
    texts.set('disconnected', state.children[1].textContent);
    assert.equal(h.requests.length, 0);
    const [connect] = byClass(h.hosts(), 'od-connect');
    assert.equal(connect.getAttribute('aria-label'), 'Connect web-01');
    connect.click();
    assert.deepEqual(h.connects, ['p1']);
    assert.equal(new Set(texts.values()).size, 7);
    // Unknown reasons from a newer server read as unavailable.
    const other = harness();
    other.advance(0);
    other.reply(0, other.fail('<b>new</b>'));
    assert.equal(byClass(other.hosts(), 'od-agents-state')[0].dataset.reason, 'unavailable');
});

test('foreign text stays literal text, loses control characters and is fully reachable when clipped', () => {
    const h = harness({profiles: [{id: 'p1', name: '<i>web</i>', herdr: true}]});
    h.advance(0);
    const longLabel = 'Migrate the billing service '.repeat(8);
    const longPath = `/home/deploy/${'nested/'.repeat(100)}end`;
    h.reply(0, h.ok([
        {id: 'x1', kind: 'claude', label: '<img src=x onerror=alert(1)>', cwd: '/tmp/"><script>alert(1)</script>', status: 'working',
            tokens: 4242, title: 'pane title', layout: {split: true}},
        {id: 'x2', kind: 'k\u0007i\u001bnd\u202e', label: `\u2066${longLabel}\u0085`, cwd: longPath, status: 'blocked'},
        {id: 'x3', kind: '', label: '', cwd: '', status: 'unknown'},
        {id: '<bad id>', kind: 'dropped', label: 'dropped', cwd: '/', status: 'idle'},
        {id: 'x1', kind: 'duplicate', label: 'duplicate', cwd: '/', status: 'idle'},
        'not an object',
    ]));
    const rows = byClass(h.hosts(), 'od-agent');
    assert.equal(rows.length, 3);
    assert.equal(rows[0].tagName, 'BUTTON');
    assert.equal(byClass(rows[0], 'od-agent-label')[0].textContent, '<img src=x onerror=alert(1)>');
    assert.equal(byClass(rows[0], 'od-agent-cwd')[0].textContent, '/tmp/"><script>alert(1)</script>');
    assert.equal(find(h.section, el => ['IMG', 'SCRIPT', 'I', 'B'].includes(el.tagName)).length, 0);
    const allowed = new Set(['SECTION', 'DIV', 'BUTTON', 'SPAN', 'BDI', 'P', 'H3', 'HEADER', 'UL', 'LI']);
    assert.deepEqual(h.doc.created.filter(el => !allowed.has(el.tagName)).map(el => el.tagName), []);
    const text = h.section.textContent;
    for (const hidden of ['4242', 'pane title', 'dropped', 'duplicate', 'split']) assert.equal(text.includes(hidden), false, hidden);
    assert.equal(find(h.hosts(), el => el.tagName === 'H3')[0].textContent, '<i>web</i>');

    const label = byClass(rows[1], 'od-agent-label')[0];
    assert.equal(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(rows[1].textContent), false);
    assert.equal(byClass(rows[1], 'od-agent-kind')[0].textContent, 'kind');
    assert.equal(label.textContent, longLabel.slice(0, 120));
    assert.equal(label.title, label.textContent);
    const cwd = byClass(rows[1], 'od-agent-cwd')[0];
    assert.equal(cwd.title, longPath.slice(0, 512));
    assert.equal(cwd.children[0].tagName, 'BDI');
    assert.equal(cwd.children[0].dir, 'ltr');
    assert.ok(rows[1].getAttribute('aria-label').includes(longPath.slice(0, 512)));
    assert.ok(rows[1].getAttribute('aria-label').includes(longLabel.slice(0, 120)));

    const empty = byClass(rows[2], 'od-agent-label')[0];
    assert.equal(empty.textContent, 'No label');
    assert.equal(empty.dataset.empty, 'true');
    assert.equal(byClass(rows[2], 'od-agent-cwd')[0].textContent, 'No working directory reported');
});

test('a list over the agent limit is cut and marked; more than six rows fold away', () => {
    const many = Array.from({length: 70}, (_, index) => agent(`w${index}`));
    const clean = herdr.cleanAgents({agents: many, truncated: false});
    assert.equal(clean.agents.length, 64);
    assert.equal(clean.truncated, true);
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok(many.slice(0, 9)));
    const items = find(h.hosts(), el => el.tagName === 'LI');
    assert.deepEqual(items.map(item => item.hidden), [false, false, false, false, false, false, true, true, true]);
    let [more] = byClass(h.hosts(), 'od-agents-more');
    assert.equal(more.textContent, 'Show 3 more');
    assert.equal(more.getAttribute('aria-expanded'), 'false');
    more.focus();
    more.click();
    [more] = byClass(h.hosts(), 'od-agents-more');
    assert.equal(more.textContent, 'Show fewer');
    assert.equal(more.getAttribute('aria-expanded'), 'true');
    assert.equal(h.doc.activeElement, more);
    assert.equal(find(h.hosts(), el => el.tagName === 'LI').every(item => !item.hidden), true);
    assert.equal(byClass(h.hosts(), 'od-agents-note').length, 0);
    h.advance(herdr.INTERVAL);
    h.reply(1, {...h.ok(many.slice(0, 9)), truncated: true});
    assert.match(shownText(h.hosts()), /Only the first 9 are listed/);
});

test('polls every 10 seconds, only for sessions with Herdr and one session per host', () => {
    const h = harness({
        profiles: [{id: 'p1', name: 'web-01', herdr: true}, {id: 'p2', name: 'db-01', herdr: false}, {id: 'p3', name: 'ci', herdr: true}],
        sessions: [
            {id: 's1', profileId: 'p1', connected: true, herdr: true},
            {id: 's1b', profileId: 'p1', connected: true, herdr: true},
            {id: 's2', profileId: 'p2', connected: true, herdr: true},
            {id: 's3', profileId: 'p3', connected: true, herdr: false},
            {id: 's4', profileId: null, connected: true, herdr: true},
        ],
    });
    h.advance(0);
    assert.deepEqual(h.requests.map(item => [item.event, item.data.session_id]), [['request_herdr_snapshot', 's1']]);
    assert.deepEqual(Object.keys(h.requests[0].data), ['session_id']);
    h.reply(0, h.ok([agent('a')]));
    h.advance(herdr.INTERVAL - 1);
    assert.equal(h.requests.length, 1);
    h.advance(1);
    assert.equal(h.requests.length, 2);
    assert.equal(h.requests[1].data.session_id, 's1');
    // The second host has no Herdr session and is listed as not connected.
    assert.equal(byClass(h.hosts(), 'od-agents-host').length, 2);
    assert.equal(h.controller.hostState('p3').kind, 'disconnected');
    assert.equal(h.controller.hostState('p2'), null);
});

test('polling pauses while the panel, the overview or the document is hidden', () => {
    for (const hide of [
        h => { h.section.dataset.userHidden = 'true'; },
        h => { h.view.hidden = true; },
        h => { h.doc.visibilityState = 'hidden'; },
    ]) {
        const h = harness();
        h.advance(0);
        h.reply(0, h.ok([agent('a')]));
        hide(h);
        h.controller.sync();
        assert.equal(h.controller.isPolling(), false);
        h.advance(herdr.INTERVAL * 5);
        assert.equal(h.requests.length, 1);
        h.section.dataset.userHidden = 'false';
        h.view.hidden = false;
        h.doc.visibilityState = 'visible';
        h.controller.sync();
        h.advance(0);
        assert.equal(h.requests.length, 2);
    }
    // Visibility events from the document pause and resume polling.
    const h = harness();
    h.doc.visibilityState = 'hidden';
    h.doc.listeners.visibilitychange.forEach(handler => handler());
    h.advance(herdr.INTERVAL * 3);
    assert.equal(h.requests.length, 0);
    h.doc.visibilityState = 'visible';
    h.doc.listeners.visibilitychange.forEach(handler => handler());
    h.advance(0);
    assert.equal(h.requests.length, 1);
});

test('busy is passed over silently and asked again after a short random delay', () => {
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok([agent('a')]));
    const before = shownText(h.hosts());
    h.advance(herdr.INTERVAL);
    h.reply(1, h.fail('busy'));
    assert.equal(shownText(h.hosts()), before);
    assert.equal(h.$('odAgentsStatus').textContent, '');
    assert.equal(h.controller.hostState('p1').interval, herdr.INTERVAL);
    h.advance(999);
    assert.equal(h.requests.length, 2);
    h.advance(2001);
    assert.equal(h.requests.length, 3);
});

test('three hosts all get an answer from a server that serves two at a time', () => {
    const profiles = ['p1', 'p2', 'p3'].map(id => ({id, name: id, herdr: true}));
    const sessions = profiles.map(profile => ({id: `s-${profile.id}`, profileId: profile.id, connected: true, herdr: true}));
    const h = harness({profiles, sessions});
    // A slow server: two queries run at once, a third is busy until a slot frees.
    let running = 0;
    const serve = () => {
        for (const request of h.requests) {
            if (request.handled) continue;
            request.handled = true;
            if (running >= 2) {
                request.ack(h.fail('busy'));
                continue;
            }
            running += 1;
            request.finishAt = request.at + 3000;
        }
        for (const request of h.requests) {
            if (request.finishAt !== undefined && !request.done && request.finishAt <= h.now()) {
                request.done = true;
                running -= 1;
                request.ack(h.ok([agent(request.data.session_id)]));
            }
        }
    };
    for (let elapsed = 0; elapsed < 8000; elapsed += 100) {
        h.advance(100);
        serve();
    }
    assert.deepEqual(profiles.map(profile => h.controller.hostState(profile.id).kind), ['agents', 'agents', 'agents']);
    // First questions are spread out rather than sent together.
    const first = profiles.map(profile => h.requests.find(request => request.data.session_id === `s-${profile.id}`).at);
    assert.equal(new Set(first).size, 3);
    // Busy is retried after one to three seconds, never at once.
    const busy = h.requests.filter(request => request.finishAt === undefined && request.handled);
    for (const request of busy) {
        const retry = h.requests.find(next => next.at > request.at && next.data.session_id === request.data.session_id);
        assert.ok(retry, 'busy host is asked again');
        assert.ok(retry.at - request.at >= 1000 && retry.at - request.at <= 3000, String(retry.at - request.at));
    }
});

test('busy retries stay bounded and then fall back to the interval', () => {
    const h = harness();
    h.advance(0);
    const gaps = [];
    for (let round = 0; round < 5; round += 1) {
        const index = h.requests.length - 1;
        h.reply(index, h.fail('busy'));
        while (h.requests.length === index + 1) h.advance(100);
        gaps.push(h.requests[index + 1].at - h.requests[index].at);
    }
    assert.ok(gaps.slice(0, 3).every(gap => gap >= 1000 && gap <= 3000), gaps.join());
    assert.ok(gaps.slice(3).every(gap => gap >= herdr.INTERVAL), gaps.join());
    // A served answer allows quick retries again.
    h.reply(h.requests.length - 1, h.ok([agent('a')]));
    h.advance(herdr.INTERVAL);
    h.reply(h.requests.length - 1, h.fail('busy'));
    const before = h.requests.length;
    h.advance(3000);
    assert.equal(h.requests.length, before + 1);
});

test('disabled ends polling and shows the reason', () => {
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok([agent('a')]));
    h.advance(herdr.INTERVAL);
    h.reply(1, h.fail('disabled'));
    assert.equal(h.$('odAgentsDisabled').hidden, false);
    assert.equal(h.$('odAgentsHosts').hidden, true);
    assert.equal(h.$('odAgentsHint').hidden, true);
    assert.equal(h.$('odAgentsTotal').textContent, '');
    assert.equal(h.$('odAgentsStatus').textContent, 'Herdr was turned off by an administrator. Agents are no longer read.');
    h.controller.sync();
    h.windowListeners['session-workspace-change'].forEach(handler => handler());
    h.advance(herdr.MAX_INTERVAL * 10);
    assert.equal(h.requests.length, 2);
    assert.equal(h.timers.size, 0);
});

test('not_enabled takes the host out of the panel without a reload', () => {
    const h = harness({
        profiles: [{id: 'p1', name: 'web-01', herdr: true}, {id: 'p2', name: 'ci', herdr: true}],
        sessions: [{id: 's1', profileId: 'p1', connected: true, herdr: true}, {id: 's2', profileId: 'p2', connected: true, herdr: true}],
    });
    // The second host is asked shortly after the first.
    h.advance(500);
    h.reply(0, h.fail('not_enabled'));
    h.reply(1, h.ok([agent('a')]));
    assert.deepEqual(byClass(h.hosts(), 'od-agents-host').map(el => el.dataset.host), ['p2']);
    h.advance(herdr.INTERVAL);
    assert.deepEqual(h.requests.slice(2).map(item => item.data.session_id), ['s2']);
    // Turning the option on again elsewhere brings the host back once the list changes.
    h.windowListeners['profile-list-change'].forEach(handler => handler());
    assert.deepEqual(byClass(h.hosts(), 'od-agents-host').map(el => el.dataset.host), ['p1', 'p2']);
});

test('timeouts double the distance up to 60 seconds and the first success resets it', () => {
    const h = harness();
    const gaps = [];
    h.advance(0);
    for (const answer of ['timeout', 'timeout', 'timeout', 'timeout', 'busy', 'success', 'timeout']) {
        const index = h.requests.length - 1;
        const repliedAt = h.now();
        h.reply(index, answer === 'success' ? h.ok([agent('a')]) : h.fail(answer));
        while (h.requests.length === index + 1) h.advance(100);
        gaps.push(h.requests[index + 1].at - repliedAt);
    }
    // Busy leaves the backoff as it is and is retried after one to three seconds.
    assert.deepEqual([...gaps.slice(0, 4), ...gaps.slice(5)], [20000, 40000, 60000, 60000, 10000, 20000]);
    assert.ok(gaps[4] >= 1000 && gaps[4] <= 3000, String(gaps[4]));
    assert.deepEqual([10000, 'timeout', 'timeout', 'timeout', 'timeout'].slice(1).reduce((list, reason) => [...list, herdr.nextInterval(list.at(-1), reason)], [10000]),
        [10000, 20000, 40000, 60000, 60000]);
    assert.equal(herdr.nextInterval(60000, null), 10000);
    assert.equal(herdr.nextInterval(40000, 'unavailable'), 40000);
});

test('a lost acknowledgement ends after a bound and polling continues', () => {
    const h = harness();
    h.advance(0);
    h.advance(30000);
    assert.equal(h.controller.hostState('p1').kind, 'unavailable');
    assert.equal(h.requests.length, 2);
    // A late answer to the expired request changes nothing.
    h.reply(0, h.ok([agent('late')]));
    assert.equal(h.controller.hostState('p1').agents, 0);
});

test('a list read earlier stays visible but marked stale after timeout, invalid or unavailable', () => {
    for (const reason of ['timeout', 'invalid', 'unavailable']) {
        const h = harness();
        h.advance(0);
        h.reply(0, h.ok([agent('a')]));
        h.advance(herdr.INTERVAL);
        h.reply(1, h.fail(reason));
        const [group] = byClass(h.hosts(), 'od-agents-host');
        assert.equal(group.dataset.stale, 'true', reason);
        assert.equal(byClass(group, 'od-agent').length, 1);
        assert.match(shownText(group), /Not refreshed since \d\d:\d\d:\d\d/);
        assert.match(h.$('odAgentsStatus').textContent, /^web-01: Not refreshed since/);
    }
    for (const reason of ['disconnected', 'not_installed', 'no_server', 'incompatible']) {
        const h = harness();
        h.advance(0);
        h.reply(0, h.ok([agent('a')]));
        h.advance(herdr.INTERVAL);
        h.reply(1, h.fail(reason));
        const [group] = byClass(h.hosts(), 'od-agents-host');
        assert.equal(group.dataset.stale, undefined, reason);
        assert.equal(byClass(group, 'od-agent').length, 0, reason);
    }
    // Losing the WebSSH connection keeps the list, stale, and stops asking.
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok([agent('a')]));
    h.socketListeners.disconnect();
    assert.equal(byClass(h.hosts(), 'od-agents-host')[0].dataset.stale, 'true');
    h.advance(herdr.INTERVAL * 3);
    assert.equal(h.requests.length, 1);
    h.socketListeners.connect();
    h.advance(0);
    assert.equal(h.requests.length, 2);
    h.reply(1, h.ok([agent('a')]));
    assert.equal(byClass(h.hosts(), 'od-agents-host')[0].dataset.stale, undefined);
});

test('a row opens its session; rows keep focus across refreshes and carry a full name', () => {
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok([agent('a'), agent('b', {kind: 'codex', label: 'fix tests', cwd: '/srv/api', status: 'blocked'})]));
    let row = byClass(h.hosts(), 'od-agent')[1];
    assert.equal(row.getAttribute('aria-label'),
        'fix tests, codex, /srv/api, Status reported by Herdr: Blocked, Open the session on web-01');
    row.focus();
    h.advance(herdr.INTERVAL);
    h.reply(1, h.ok([agent('a'), agent('b', {status: 'done'})]));
    row = byClass(h.hosts(), 'od-agent')[1];
    assert.equal(h.doc.activeElement, row);
    assert.equal(row.dataset.key, 'agent:p1:b');
    row.click();
    assert.deepEqual(h.opened, [['s1', 'p1']]);
    // Status changes of single agents are not announced.
    assert.equal(h.$('odAgentsStatus').textContent, '');
});

test('host state changes are announced, the first list is not', () => {
    const h = harness();
    h.advance(0);
    assert.equal(byClass(h.hosts(), 'od-agents-host')[0].getAttribute('aria-busy'), 'true');
    h.reply(0, h.ok([agent('a')]));
    assert.equal(h.$('odAgentsStatus').textContent, '');
    h.advance(herdr.INTERVAL);
    h.reply(1, h.fail('no_server'));
    assert.equal(h.$('odAgentsStatus').textContent, 'web-01: No Herdr server is running on this host. WebSSH does not start one.');
});

test('the empty state appears when no host uses Herdr and leads to the hosts', () => {
    const h = harness({profiles: [{id: 'p1', name: 'web-01'}], sessions: [{id: 's1', profileId: 'p1', connected: true, herdr: false}]});
    assert.equal(h.section.hidden, false);
    assert.equal(h.$('odAgentsEmpty').hidden, false);
    assert.equal(h.$('odAgentsHint').hidden, true);
    assert.equal(h.$('odAgentsFoot').hidden, true);
    h.advance(herdr.INTERVAL * 3);
    assert.equal(h.requests.length, 0);
    h.$('odAgentsEmptyAction').click();
    assert.deepEqual(h.hostsOpened, [true]);
});

test('the panel stays hidden and silent while the integration is off', () => {
    const h = harness({enabled: false});
    h.advance(herdr.INTERVAL * 3);
    assert.equal(h.section.hidden, true);
    assert.equal(h.requests.length, 0);
    assert.deepEqual(h.windowListeners, {});
});

test('a session that disappears replaces the list with the not connected state', () => {
    const h = harness();
    h.advance(0);
    h.reply(0, h.ok([agent('a')]));
    h.state.sessions = [];
    h.windowListeners['session-workspace-change'].forEach(handler => handler());
    assert.equal(h.controller.hostState('p1').kind, 'disconnected');
    h.advance(herdr.INTERVAL * 2);
    assert.equal(h.requests.length, 1);
    // A reconnect asks right away with the new session.
    h.state.sessions = [{id: 's9', profileId: 'p1', connected: true, herdr: true}];
    h.windowListeners['session-workspace-change'].forEach(handler => handler());
    h.advance(0);
    assert.equal(h.requests[1].data.session_id, 's9');
});
