/* Agents panel of the overview board: what Herdr reports on hosts whose saved
 * connection opts in. It only reads, through the user's own connected
 * session, and never acts on an agent. Everything in an answer is foreign
 * data and reaches the page through textContent and attributes only. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.HerdrOverview = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const INTERVAL = 10000;
    const MAX_INTERVAL = 60000;
    // The server ends a query after three seconds; a lost acknowledgement must not stall the host.
    const ACK_TIMEOUT = 10000;
    const VISIBLE_ROWS = 6;
    const MAX_AGENTS = 64;
    const LIMITS = {kind: 120, label: 120, cwd: 512};
    const ID_PATTERN = /^[A-Za-z0-9:_-]{1,64}$/;
    // C0, DEL, C1 and the bidirectional marks, embeddings, overrides and isolates.
    const UNSAFE = /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/g;

    const STATUS = {
        idle: ['pause_circle', 'herdr.statusIdle'],
        working: ['autorenew', 'herdr.statusWorking'],
        blocked: ['pan_tool', 'herdr.statusBlocked'],
        done: ['check_circle', 'herdr.statusDone'],
        unknown: ['help_outline', 'herdr.statusUnknown'],
    };
    // keep: a list read earlier stays visible, marked as stale.
    const REASONS = {
        disconnected: {icon: 'link_off', key: 'herdr.reasonDisconnected', tone: '', keep: false},
        not_installed: {icon: 'extension_off', key: 'herdr.reasonNotInstalled', tone: '', keep: false},
        no_server: {icon: 'power_off', key: 'herdr.reasonNoServer', tone: '', keep: false},
        incompatible: {icon: 'sync_problem', key: 'herdr.reasonIncompatible', tone: 'warning', keep: false},
        timeout: {icon: 'timer_off', key: 'herdr.reasonTimeout', tone: 'warning', keep: true},
        invalid: {icon: 'error_outline', key: 'herdr.reasonInvalid', tone: 'warning', keep: true},
        unavailable: {icon: 'help_outline', key: 'herdr.reasonUnavailable', tone: 'warning', keep: true},
    };

    const TEXT = {
        agentsTitle: 'Agents',
        statusIdle: 'Idle',
        statusWorking: 'Working',
        statusBlocked: 'Blocked',
        statusDone: 'Done',
        statusUnknown: 'Unknown',
        statusPrefix: 'Status reported by Herdr: {status}',
        openSession: 'Open the session on {host}',
        noLabel: 'No label',
        noCwd: 'No working directory reported',
        updated: 'As of {time}',
        stale: 'Not refreshed since {time}. The agents shown may have changed.',
        truncated: 'Herdr reported more agents than WebSSH reads. Only the first {count} are listed.',
        showMore: 'Show {count} more',
        showLess: 'Show fewer',
        noAgents: 'Herdr is running. It reports no agents right now.',
        reasonDisconnected: 'Not connected. Agents are only read while a session of yours is open.',
        reasonNotInstalled: 'Herdr was not found on this host.',
        reasonNoServer: 'No Herdr server is running on this host. WebSSH does not start one.',
        reasonIncompatible: 'The Herdr version on this host is not supported by this WebSSH version.',
        reasonTimeout: 'Herdr did not answer in time. WebSSH asks again shortly.',
        reasonInvalid: 'Herdr answered with data that WebSSH could not read.',
        reasonUnavailable: 'Agents could not be read from this session.',
        reasonDisabled: 'Herdr was turned off by an administrator. Agents are no longer read.',
        loading: 'Reading agents from Herdr',
        connect: 'Connect',
    };

    function cleanText(value, max) {
        if (typeof value !== 'string') return '';
        return Array.from(value.replace(UNSAFE, '')).slice(0, max).join('');
    }

    /** Reduce an answer to known fields within the agreed limits. */
    function cleanAgents(result) {
        const source = Array.isArray(result?.agents) ? result.agents : [];
        const agents = [];
        const seen = new Set();
        let truncated = result?.truncated === true;
        for (const agent of source) {
            if (agents.length >= MAX_AGENTS) {
                truncated = true;
                break;
            }
            if (!agent || typeof agent !== 'object') continue;
            const id = typeof agent.id === 'string' && ID_PATTERN.test(agent.id) ? agent.id : '';
            if (!id || seen.has(id)) continue;
            seen.add(id);
            agents.push({
                id,
                kind: cleanText(agent.kind, LIMITS.kind),
                label: cleanText(agent.label, LIMITS.label),
                cwd: cleanText(agent.cwd, LIMITS.cwd),
                status: typeof agent.status === 'string' && Object.hasOwn(STATUS, agent.status) ? agent.status : 'unknown',
            });
        }
        return {agents, truncated};
    }

    /** Polling distance after an answer: doubled after a timeout, reset by success. */
    function nextInterval(current, reason) {
        if (!reason) return INTERVAL;
        if (reason === 'timeout') return Math.min(MAX_INTERVAL, Math.max(INTERVAL, current) * 2);
        return current;
    }

    function createController(options) {
        const {doc, win, socket, section} = options;
        const view = options.view || section;
        const enabled = options.enabled === true;
        const profiles = options.profiles || (() => []);
        const sessions = options.sessions || (() => []);
        const profilesLoaded = options.profilesLoaded || (() => true);
        const now = options.now || Date.now;
        const setTimer = options.setTimeout || ((fn, delay) => win.setTimeout(fn, delay));
        const clearTimer = options.clearTimeout || (id => win.clearTimeout(id));
        const language = options.language || (() => undefined);
        const $ = id => doc.getElementById(id);
        const entries = new Map();
        const excluded = new Set();
        const expanded = new Set();
        const lastKinds = new Map();
        let order = [];
        let disabled = false;
        let transportDown = false;

        function t(key, values = {}) {
            let text = options.translate?.(key);
            if (!text || text === key) text = TEXT[key.slice('herdr.'.length)] || key;
            return Object.entries(values).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)), text);
        }
        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined) element.textContent = text;
            return element;
        };
        const icon = name => {
            const element = node('span', 'material-icons', name);
            element.setAttribute('aria-hidden', 'true');
            return element;
        };
        const clock = timestamp => {
            try {
                return new Intl.DateTimeFormat(language() || undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit'}).format(timestamp);
            } catch {
                return new Date(timestamp).toLocaleTimeString();
            }
        };

        function visible() {
            return enabled && !disabled && !transportDown && !view.hidden && !section.hidden
                && section.dataset.userHidden !== 'true' && doc.visibilityState !== 'hidden';
        }

        function stop(entry) {
            clearTimer(entry.timer);
            clearTimer(entry.guard);
            entry.timer = entry.guard = entry.token = null;
        }

        function hosts() {
            return profiles().filter(profile => profile && profile.herdr === true
                && typeof profile.id === 'string' && !excluded.has(profile.id));
        }

        /** One connected session per host, kept stable while it stays eligible. */
        function pickSession(profile, entry) {
            const candidates = sessions().filter(session => session && session.profileId === profile.id
                && session.connected === true && session.herdr === true && typeof session.id === 'string');
            return candidates.find(session => session.id === entry.sessionId) || candidates[0] || null;
        }

        function schedule(entry) {
            if (!entry.sessionId || entry.timer || entry.token) return;
            entry.timer = setTimer(() => {
                entry.timer = null;
                poll(entry);
            }, Math.max(0, entry.nextAt - now()));
        }

        function poll(entry) {
            if (!visible() || !entry.sessionId || entry.token || entries.get(entry.profileId) !== entry) return;
            const token = {};
            entry.token = token;
            entry.guard = setTimer(() => answer(entry, token, {success: false, reason: 'unavailable'}), ACK_TIMEOUT);
            socket.emit('request_herdr_snapshot', {session_id: entry.sessionId}, result => answer(entry, token, result));
        }

        function answer(entry, token, result) {
            if (entry.token !== token) return;
            clearTimer(entry.guard);
            entry.token = entry.guard = null;
            if (entries.get(entry.profileId) !== entry) return;
            const given = typeof result?.reason === 'string' ? result.reason : '';
            const reason = result?.success === true ? null
                : (Object.hasOwn(REASONS, given) || ['busy', 'not_enabled', 'disabled'].includes(given) ? given : 'unavailable');
            if (reason === 'disabled') {
                disabled = true;
                entries.forEach(stop);
                render();
                return;
            }
            if (reason === 'not_enabled') {
                excluded.add(entry.profileId);
                stop(entry);
                entries.delete(entry.profileId);
                render();
                return;
            }
            if (!reason) {
                const clean = cleanAgents(result);
                Object.assign(entry, {kind: 'agents', reason: null, stale: false, at: now(), ...clean});
            } else if (reason !== 'busy') {
                if (REASONS[reason].keep && entry.at) {
                    entry.stale = true;
                } else {
                    Object.assign(entry, {kind: 'reason', reason, stale: false, at: 0, agents: [], truncated: false});
                }
            }
            if (reason !== 'busy') entry.interval = nextInterval(entry.interval, reason);
            entry.nextAt = now() + entry.interval;
            if (visible()) schedule(entry);
            render();
        }

        function sync() {
            if (!enabled) {
                section.hidden = true;
                return;
            }
            if (disabled) {
                render();
                return;
            }
            const listed = hosts();
            const ids = new Set(listed.map(profile => profile.id));
            entries.forEach((entry, id) => {
                if (ids.has(id)) return;
                stop(entry);
                entries.delete(id);
            });
            listed.forEach(profile => {
                let entry = entries.get(profile.id);
                if (!entry) {
                    entry = {profileId: profile.id, sessionId: undefined, kind: 'loading', reason: null, stale: false, at: 0,
                        agents: [], truncated: false, interval: INTERVAL, nextAt: 0, timer: null, guard: null, token: null};
                    entries.set(profile.id, entry);
                }
                entry.name = profile.name || profile.host || profile.id;
                if (transportDown) {
                    if (entry.at) entry.stale = true;
                    return;
                }
                const session = pickSession(profile, entry);
                const sessionId = session ? session.id : null;
                if (sessionId === entry.sessionId) return;
                stop(entry);
                entry.sessionId = sessionId;
                entry.interval = INTERVAL;
                entry.nextAt = 0;
                if (!sessionId) {
                    Object.assign(entry, {kind: 'reason', reason: 'disconnected', stale: false, at: 0, agents: [], truncated: false});
                } else if (entry.at) {
                    entry.stale = true;
                } else {
                    Object.assign(entry, {kind: 'loading', reason: null});
                }
            });
            order = listed.map(profile => profile.id);
            if (visible()) {
                entries.forEach(schedule);
            } else {
                entries.forEach(entry => {
                    clearTimer(entry.timer);
                    entry.timer = null;
                });
            }
            render();
        }

        function note(className, iconName, text, tone) {
            const line = node('p', className);
            if (tone) line.dataset.tone = tone;
            line.append(icon(iconName), node('span', '', text));
            return line;
        }

        function agentRow(entry, agent, keys) {
            const [statusIcon, statusKey] = STATUS[agent.status];
            const statusText = t(statusKey);
            const row = node('button', 'od-row od-agent');
            row.type = 'button';
            row.dataset.key = `agent:${entry.profileId}:${agent.id}`;
            keys.set(row.dataset.key, row);
            const label = agent.label || agent.kind;
            row.setAttribute('aria-label', [
                label || t('herdr.noLabel'),
                agent.label && agent.kind ? agent.kind : '',
                agent.cwd || t('herdr.noCwd'),
                t('herdr.statusPrefix', {status: statusText}),
                t('herdr.openSession', {host: entry.name}),
            ].filter(Boolean).join(', '));
            const copy = node('span', 'od-agent-copy');
            const name = node('span', 'od-agent-label', label || t('herdr.noLabel'));
            if (label) name.title = label;
            else name.dataset.empty = 'true';
            const meta = node('span', 'od-agent-meta');
            if (agent.label && agent.kind) {
                const kind = node('span', 'od-agent-kind', agent.kind);
                kind.title = agent.kind;
                meta.append(kind);
            }
            // The path is clipped at its start so the project folder stays readable.
            const cwd = node('span', 'od-agent-cwd');
            const path = node('bdi', '', agent.cwd || t('herdr.noCwd'));
            path.dir = 'ltr';
            cwd.append(path);
            if (agent.cwd) cwd.title = agent.cwd;
            else cwd.dataset.empty = 'true';
            meta.append(cwd);
            copy.append(name, meta);
            const status = node('span', 'od-agent-status');
            status.dataset.status = agent.status;
            status.title = t('herdr.statusPrefix', {status: statusText});
            status.append(icon(statusIcon), node('span', '', statusText));
            row.append(icon('smart_toy'), copy, status, icon('chevron_right'));
            row.addEventListener('click', () => options.onOpenSession?.(entry.sessionId, entry.profileId));
            const item = node('li');
            item.append(row);
            return item;
        }

        function hostGroup(entry, index, keys) {
            const group = node('section', 'od-agents-host');
            group.dataset.host = entry.profileId;
            const title = node('h3', '', entry.name);
            title.id = `odAgentsHost${index}`;
            title.title = entry.name;
            group.setAttribute('aria-labelledby', title.id);
            const head = node('header', 'od-agents-host-head');
            head.append(title);
            group.append(head);
            if (entry.kind === 'loading') {
                group.setAttribute('aria-busy', 'true');
                const loading = node('span', 'sr-only', t('herdr.loading'));
                group.append(loading, node('div', 'od-skeleton od-agents-skeleton'), node('div', 'od-skeleton od-agents-skeleton'));
                return group;
            }
            if (entry.kind === 'reason') {
                const reason = REASONS[entry.reason];
                const state = note('od-agents-state', reason.icon, t(reason.key), reason.tone);
                state.dataset.reason = entry.reason;
                if (entry.reason === 'disconnected' && options.onConnect) {
                    const connect = node('button', 'od-connect');
                    connect.type = 'button';
                    connect.dataset.key = `connect:${entry.profileId}`;
                    keys.set(connect.dataset.key, connect);
                    const shared = options.translate?.('connection.actionConnect');
                    const label = shared && shared !== 'connection.actionConnect' ? shared : TEXT.connect;
                    connect.setAttribute('aria-label', `${label} ${entry.name}`);
                    connect.append(icon('terminal'), node('span', '', label));
                    connect.addEventListener('click', () => options.onConnect(entry.profileId));
                    state.append(connect);
                }
                group.append(state);
                return group;
            }
            const time = clock(entry.at);
            const updated = node('span', 'od-agents-updated');
            updated.append(icon(entry.stale ? 'history' : 'schedule'), node('span', '', t('herdr.updated', {time})));
            head.append(updated);
            if (entry.stale) {
                group.dataset.stale = 'true';
                group.append(note('od-agents-note', 'history', t('herdr.stale', {time}), 'warning'));
            }
            if (!entry.agents.length) {
                group.append(note('od-agents-note', 'check', t('herdr.noAgents')));
                return group;
            }
            const list = node('ul', 'od-agents-list');
            const open = expanded.has(entry.profileId);
            entry.agents.forEach((agent, position) => {
                const item = agentRow(entry, agent, keys);
                item.hidden = !open && position >= VISIBLE_ROWS;
                list.append(item);
            });
            group.append(list);
            if (entry.agents.length > VISIBLE_ROWS) {
                const more = node('button', 'od-link od-agents-more',
                    open ? t('herdr.showLess') : t('herdr.showMore', {count: entry.agents.length - VISIBLE_ROWS}));
                more.type = 'button';
                more.dataset.key = `more:${entry.profileId}`;
                keys.set(more.dataset.key, more);
                more.setAttribute('aria-expanded', String(open));
                more.addEventListener('click', () => {
                    if (open) expanded.delete(entry.profileId);
                    else expanded.add(entry.profileId);
                    render();
                });
                group.append(more);
            }
            if (entry.truncated) group.append(note('od-agents-note', 'info', t('herdr.truncated', {count: entry.agents.length})));
            return group;
        }

        function kindOf(entry) {
            if (entry.kind === 'reason') return entry.reason;
            return entry.stale ? 'stale' : entry.kind;
        }

        function announce(message) {
            const status = $('odAgentsStatus');
            if (status) status.textContent = message;
        }

        /** Announce changes of a host's state, never every status change of an agent. */
        function announceChanges(list) {
            const messages = [];
            list.forEach(entry => {
                const kind = kindOf(entry);
                const previous = lastKinds.get(entry.profileId);
                lastKinds.set(entry.profileId, kind);
                if (previous === undefined || previous === kind || kind === 'loading') return;
                if (previous === 'loading' && kind === 'agents') return;
                const text = kind === 'agents' ? t('herdr.updated', {time: clock(entry.at)})
                    : kind === 'stale' ? t('herdr.stale', {time: clock(entry.at)})
                    : t(REASONS[kind].key);
                messages.push(`${entry.name}: ${text}`);
            });
            [...lastKinds.keys()].forEach(id => { if (!entries.has(id)) lastKinds.delete(id); });
            if (messages.length) announce(messages.join(' '));
        }

        function render() {
            if (!enabled) return;
            const active = doc.activeElement;
            const focusKey = active && section.contains?.(active) ? active.dataset?.key : null;
            const list = order.map(id => entries.get(id)).filter(Boolean);
            const keys = new Map();
            const total = list.reduce((sum, entry) => sum + (entry.kind === 'agents' ? entry.agents.length : 0), 0);
            $('odAgentsTotal').textContent = !disabled && total ? String(total) : '';
            $('odAgentsHosts').hidden = disabled;
            $('odAgentsHosts').replaceChildren(...(disabled ? [] : list.map((entry, index) => hostGroup(entry, index, keys))));
            $('odAgentsEmpty').hidden = disabled || !profilesLoaded() || list.length > 0;
            const wasDisabled = $('odAgentsDisabled').hidden === false;
            $('odAgentsDisabled').hidden = !disabled;
            $('odAgentsHint').hidden = disabled || !list.length;
            $('odAgentsFoot').hidden = disabled || !list.length;
            if (disabled) {
                if (!wasDisabled) announce(t('herdr.reasonDisabled'));
            } else {
                announceChanges(list);
            }
            if (focusKey && !section.contains?.(active)) keys.get(focusKey)?.focus({preventScroll: true});
        }

        function start() {
            if (!enabled) {
                section.hidden = true;
                return;
            }
            section.hidden = false;
            $('odAgentsEmptyAction')?.addEventListener('click', () => options.onOpenHosts?.());
            doc.addEventListener?.('visibilitychange', sync);
            win.addEventListener?.('session-workspace-change', sync);
            win.addEventListener?.('primary-workspace-change', sync);
            win.addEventListener?.('languageChanged', render);
            win.addEventListener?.('profile-list-change', () => {
                // A host turned on again elsewhere is asked again; the server decides.
                excluded.clear();
                sync();
            });
            socket.on?.('disconnect', () => {
                transportDown = true;
                entries.forEach(stop);
                sync();
            });
            socket.on?.('connect', () => {
                transportDown = false;
                sync();
            });
            // Hiding the panel through Customize changes only this attribute.
            if (win.MutationObserver) {
                const observer = new win.MutationObserver(sync);
                observer.observe(section, {attributes: true, attributeFilter: ['data-user-hidden', 'hidden']});
                if (view !== section) observer.observe(view, {attributes: true, attributeFilter: ['hidden']});
            }
            sync();
        }

        return {
            start,
            sync,
            render,
            isPolling: visible,
            hostState: id => {
                const entry = entries.get(id);
                return entry ? {kind: kindOf(entry), sessionId: entry.sessionId, interval: entry.interval, agents: entry.agents.length} : null;
            },
        };
    }

    return {INTERVAL, MAX_INTERVAL, MAX_AGENTS, VISIBLE_ROWS, cleanText, cleanAgents, nextInterval, createController};
}));
