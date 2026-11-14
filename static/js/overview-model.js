/* Overview dashboard model: pure functions, no DOM. Exported for tests. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.OverviewModel = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const DAY = 24 * 60 * 60 * 1000;

    function destination(profile) {
        const port = Number(profile.port || 22);
        return `${profile.username ? `${profile.username}@` : ''}${profile.host || ''}${port === 22 ? '' : `:${port}`}`;
    }

    function sameEndpoint(entry, profile) {
        return String(entry.host || '') === String(profile.host || '')
            && Number(entry.port || 22) === Number(profile.port || 22)
            && String(entry.username || '') === String(profile.username || '');
    }

    /**
     * Combine saved hosts with server readiness, open sessions and an optional
     * reachability result. State precedence: live > broken > unreachable >
     * action > ready. "unknown" means readiness has not loaded yet.
     */
    function hosts({profiles = [], jumps = [], jumpsLoaded = false, sessions = [], readiness = null, reachability = null} = {}) {
        const jumpById = new Map(jumps.map(jump => [jump.id, jump]));
        const ready = new Map((readiness || []).map(item => [item.id, item]));
        const seen = new Set();
        return profiles.filter(profile => profile && typeof profile.id === 'string' && !seen.has(profile.id) && seen.add(profile.id))
            .map(profile => {
                const jump = profile.jump_host_id ? jumpById.get(profile.jump_host_id) : null;
                const route = !profile.jump_host_id ? {kind: 'direct', name: null, id: null}
                    : jump ? {kind: 'jump', name: String(jump.name || jump.host || ''), id: jump.id}
                        : {kind: jumpsLoaded ? 'missing' : 'loading', name: null, id: profile.jump_host_id};
                const session = sessions.find(item => item.connected === true
                    && (item.profileId === profile.id || sameEndpoint(item, profile)));
                const status = ready.get(profile.id) || null;
                const reach = reachability?.[profile.id] || null;
                let state = status ? status.state : 'unknown';
                if (route.kind === 'missing') state = 'broken';
                if (reach && ['unreachable', 'unresolved', 'blocked'].includes(reach.state) && state !== 'broken') state = 'unreachable';
                if (session) state = 'live';
                return {
                    id: profile.id,
                    name: String(profile.name || profile.host || ''),
                    group: String(profile.group || '').trim(),
                    favorite: profile.favorite === true,
                    destination: destination(profile),
                    order: Number(profile.sort_order) || 0,
                    route, state, status, reach,
                    sessionId: session?.id || null,
                    profile,
                };
            })
            .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.group.localeCompare(b.group)
                || a.order - b.order || a.name.localeCompare(b.name));
    }

    function filter(list, query) {
        const search = String(query || '').trim().toLocaleLowerCase();
        if (!search) return list;
        return list.filter(host => [host.name, host.destination, host.group, host.route.name || '']
            .some(value => value.toLocaleLowerCase().includes(search)));
    }

    /** Fourteen daily bins of run outcomes, oldest first, in local time. */
    function automationBins(runs = [], now = Date.now(), days = 14) {
        const today = new Date(now);
        today.setHours(0, 0, 0, 0);
        const bins = Array.from({length: days}, (_, index) => ({
            start: today.getTime() - (days - 1 - index) * DAY, succeeded: 0, failed: 0, other: 0,
        }));
        for (const run of runs) {
            const time = Date.parse(run.created_at);
            if (Number.isNaN(time)) continue;
            const bin = bins.find(item => time >= item.start && time < item.start + DAY);
            if (!bin) continue;
            if (run.outcome === 'succeeded') bin.succeeded += 1;
            else if (run.outcome === 'failed') bin.failed += 1;
            else bin.other += 1;
        }
        return bins;
    }

    function metrics({hostList = [], sessions = [], runs = [], schedules = [], reachability = null, now = Date.now()} = {}) {
        const total = hostList.length;
        // TCP reachability is a separate observation, not configuration readiness.
        const configurationState = host => host.sessionId ? 'ready'
            : host.route?.kind === 'missing' ? 'broken' : host.status?.state || 'unknown';
        const known = hostList.filter(host => configurationState(host) !== 'unknown');
        const readyCount = hostList.filter(host => configurationState(host) === 'ready').length;
        const bins = automationBins(runs, now);
        const finished = bins.reduce((sum, bin) => sum + bin.succeeded + bin.failed + bin.other, 0);
        const succeeded = bins.reduce((sum, bin) => sum + bin.succeeded, 0);
        const failed = bins.reduce((sum, bin) => sum + bin.failed, 0);
        const upcoming = schedules.filter(item => item.enabled && item.next_due)
            .map(item => ({...item, due: Date.parse(item.next_due)}))
            .filter(item => !Number.isNaN(item.due) && item.due >= now)
            .sort((a, b) => a.due - b.due)[0] || null;
        // Hosts the check could not reach in time are unknown, not counted either way.
        const checked = reachability ? Object.values(reachability).filter(item => item.state !== 'unchecked') : [];
        return {
            hosts: {total, ready: readyCount, needsAttention: known.length - readyCount, loaded: known.length === total},
            sessions: {count: sessions.filter(item => item.connected === true).length},
            automation: {runs: finished, succeeded, failed, rate: finished ? Math.round((succeeded / finished) * 100) : null, bins},
            nextRun: upcoming ? {name: upcoming.name, due: upcoming.due} : null,
            reachability: checked.length ? {
                checked: checked.length,
                reachable: checked.filter(item => item.state === 'reachable').length,
            } : null,
        };
    }

    /** Overall headline: the most severe condition wins. */
    function headline({connected = true, hostList = [], attentionItems = []} = {}) {
        if (!connected) return {tone: 'danger', key: 'disconnected'};
        // Acknowledged items no longer drive the headline. A grouped item counts every host it covers.
        const count = attentionItems.reduce((sum, item) => sum + (Number.isInteger(item.count) && item.count > 0 ? item.count : 1), 0);
        if (attentionItems.some(item => item.kind === 'jump-missing' || item.kind === 'run-failed')) return {tone: 'danger', key: 'attention', count};
        if (attentionItems.length) return {tone: 'warning', key: 'attention', count};
        if (!hostList.length) return {tone: 'neutral', key: 'empty'};
        return {tone: 'success', key: 'ready'};
    }

    function attention({hostList = [], runs = [], schedules = [], now = Date.now()} = {}) {
        const items = [];
        const hostKeys = hostList.filter(host => host.status?.host_key === 'unknown' && host.state !== 'live');
        if (hostKeys.length) items.push({kind: 'host-keys', count: hostKeys.length, hostIds: hostKeys.map(host => host.id)});
        hostList.filter(host => host.state === 'broken').slice(0, 3)
            .forEach(host => items.push({kind: 'jump-missing', name: host.name, hostId: host.id}));
        const unreachable = hostList.filter(host => host.state === 'unreachable');
        if (unreachable.length) items.push({kind: 'unreachable', count: unreachable.length, names: unreachable.slice(0, 3).map(host => host.name), hostIds: unreachable.map(host => host.id)});
        const credentials = hostList.filter(host => ['password_changed', 'key_missing'].includes(host.status?.auth));
        if (credentials.length) items.push({kind: 'credentials', count: credentials.length, hostIds: credentials.map(host => host.id)});
        // Read from the host's own package state when it was last connected; see maintenance().
        const restart = hostList.filter(host => maintenance(host.profile, now)?.reboot_required === true);
        if (restart.length) items.push({kind: 'reboot', count: restart.length, hostIds: restart.map(host => host.id)});
        const security = hostList.filter(host => maintenance(host.profile, now)?.security_updates > 0);
        if (security.length) items.push({kind: 'security-updates', count: security.length, hostIds: security.map(host => host.id)});
        runs.filter(run => run.outcome === 'failed' && now - Date.parse(run.created_at) < DAY).slice(0, 2)
            .forEach(run => items.push({kind: 'run-failed', name: run.name, runId: run.id}));
        schedules.filter(item => ['needs_review', 'unknown'].includes(item.last_status)).slice(0, 2)
            .forEach(item => items.push({kind: 'schedule-review', name: item.name, scheduleId: item.id, status: item.last_status}));
        return items.map(item => ({...item, key: attentionKey(item)}));
    }

    /**
     * Pending updates and a required restart, as the host reported them in the
     * last run of the Updates and restart status workflow. Unknown values are
     * null, never guessed.
     */
    function maintenance(profile, now = Date.now()) {
        const facts = profile?.detected_maintenance;
        if (!facts || typeof facts !== 'object') return null;
        const count = value => Number.isInteger(value) && value >= 0 && value <= 100000 ? value : null;
        const checked = Number(facts.checked_at);
        // Facts older than a week, or dated in the future, are not shown as current.
        if (!Number.isFinite(checked) || checked <= 0 || now - checked * 1000 > 7 * DAY || checked * 1000 - now > DAY) return null;
        return {
            reboot_required: typeof facts.reboot_required === 'boolean' ? facts.reboot_required : null,
            updates: count(facts.updates),
            security_updates: count(facts.security_updates),
            checkedAt: checked * 1000,
        };
    }

    /** 32-bit FNV-1a, enough to tell one set of hosts from another. */
    function fingerprint(value) {
        let hash = 0x811c9dc5;
        for (const char of String(value)) {
            hash ^= char.codePointAt(0);
            hash = Math.imul(hash, 0x01000193) >>> 0;
        }
        return hash.toString(36);
    }

    /**
     * Stable identity of an attention item. Acknowledging it hides exactly
     * this situation: a different set of hosts or a new failed run is a new
     * item and shows again.
     */
    function attentionKey(item) {
        const subject = item.hostIds ? [...item.hostIds].sort().join(',')
            : item.runId || item.hostId || `${item.scheduleId || item.name}|${item.status || ''}`;
        const plain = /^[A-Za-z0-9_.-]{1,64}$/.test(subject) ? subject : fingerprint(subject);
        return `${item.kind}:${plain}`;
    }

    /** Recent events across sessions, connections and runs, newest first. */
    function activity({hostList = [], sessions = [], history = [], runs = [], now = Date.now(), limit = 6} = {}) {
        const events = [];
        sessions.filter(item => item.connected === true).forEach(session => {
            const host = hostList.find(item => item.sessionId === session.id);
            events.push({kind: 'session', name: host?.name || session.displayName || session.host || '', at: now, sessionId: session.id});
        });
        history.forEach(entry => {
            const host = hostList.find(item => sameEndpoint(entry, item.profile));
            if (host && !host.sessionId) events.push({kind: 'connection', name: host.name, at: Number(entry.timestamp), hostId: host.id});
        });
        runs.forEach(run => {
            const at = Date.parse(run.created_at);
            if (!Number.isNaN(at)) events.push({kind: `run-${['succeeded', 'failed'].includes(run.outcome) ? run.outcome : 'other'}`, name: run.name, at, runId: run.id});
        });
        return events.sort((a, b) => b.at - a.at).slice(0, limit);
    }

    function platforms(hostList = [], resolve = () => ({id: 'server'})) {
        const counts = new Map();
        hostList.forEach(host => {
            const platform = resolve(host.profile) || {id: 'server'};
            const id = platform.id || 'server';
            counts.set(id, {platform, count: (counts.get(id)?.count || 0) + 1});
        });
        return [...counts.values()].sort((a, b) => b.count - a.count || String(a.platform.id).localeCompare(String(b.platform.id)));
    }

    /**
     * Flow topology in a wide view box: WebSSH in the middle, direct hosts
     * fanned out to the left, jump hosts stacked on the right with their
     * hosts behind them. Hubs with many hosts show the first `perHub` and a
     * "+N" summary. Labels point away from the center, so they never cross.
     * Without an explicit height the view box fits the content, so a small
     * inventory does not leave an empty canvas.
     */
    const ROW = 40;
    function topology(hostList = [], {width = 1200, height = null, perHub = 12} = {}) {
        const groups = new Map();
        hostList.forEach(host => {
            const kind = host.route.kind === 'jump' ? 'jump' : host.route.kind === 'direct' ? 'direct' : 'missing';
            const key = kind === 'jump' ? `jump:${host.route.id}` : kind;
            if (!groups.has(key)) groups.set(key, {key, kind, name: host.route.name, hosts: []});
            groups.get(key).hosts.push(host);
        });
        const direct = groups.get('direct');
        const right = [...groups.values()].filter(hub => hub.kind !== 'direct')
            .sort((a, b) => b.hosts.length - a.hosts.length || String(a.name).localeCompare(String(b.name)));
        if (!height) {
            const left = direct ? Math.min(perHub, direct.hosts.length) : 0;
            const rightRows = right.reduce((sum, hub) => sum + Math.max(1.5, Math.min(perHub, hub.hosts.length)), 0);
            height = Math.round(Math.min(520, Math.max(220, Math.max(left, rightRows) * ROW + 90)));
        }
        // Keep the drawing centred when one side is empty.
        const center = {x: width * (!right.length ? 0.64 : !direct ? 0.3 : 0.42), y: height / 2};
        const nodes = [];
        const hubs = [];
        const place = (hub, point, side, slice) => {
            const shown = hub.hosts.slice(0, perHub);
            const span = Math.min(slice * 0.86, ROW * Math.max(0, shown.length - 1));
            shown.forEach((host, index) => {
                const offset = shown.length === 1 ? 0 : -span / 2 + (span * index) / (shown.length - 1);
                const curve = Math.abs(offset) * 0.35;
                nodes.push({host, hub: hub.key, x: point.x + side * (150 - curve), y: point.y + offset, anchor: side < 0 ? 'end' : 'start'});
            });
            hubs.push({...hub, x: point.x, y: point.y, hidden: Math.max(0, hub.hosts.length - shown.length)});
        };
        if (direct) place(direct, {x: center.x - 190, y: center.y}, -1, height);
        // Jump hosts share the right side in proportion to the hosts they carry.
        const weights = right.map(hub => Math.max(1.5, Math.min(perHub, hub.hosts.length)));
        const totalWeight = weights.reduce((sum, value) => sum + value, 0);
        let top = 0;
        right.forEach((hub, index) => {
            const slice = (height * weights[index]) / totalWeight;
            place(hub, {x: center.x + 200, y: top + slice / 2}, 1, slice);
            top += slice;
        });
        nodes.forEach(node => {
            // Room for a name and destination label beside every node.
            node.x = Math.max(190, Math.min(width - 190, node.x));
            node.y = Math.max(20, Math.min(height - 20, node.y));
        });
        return {center, hubs, nodes, width, height};
    }

    /** Saved-host shortcuts only: stale history can never resurrect a deleted host. */
    function workFirst({hostList = [], history = [], sessions = [], limit = 6} = {}) {
        const used = new Set();
        const take = list => list.filter(host => !used.has(host.id) && used.add(host.id)).slice(0, limit);
        const liveHosts = hostList.filter(host => host.sessionId);
        const adHoc = sessions.filter(session => session.connected === true && !liveHosts.some(host => host.sessionId === session.id))
            .map(session => ({id: `session:${session.id}`, sessionId: session.id,
                name: String(session.displayName || session.host || ''), destination: destination(session)}));
        const resume = take([...liveHosts, ...adHoc]);
        const favorites = take(hostList.filter(host => host.favorite));
        const recent = take([...history].filter(entry => Number.isFinite(Number(entry.timestamp)))
            .sort((a, b) => Number(b.timestamp) - Number(a.timestamp))
            .map(entry => hostList.find(host => sameEndpoint(entry, host.profile))).filter(Boolean));
        const saved = resume.length || favorites.length || recent.length ? [] : hostList.slice(0, limit);
        return {resume, favorites, recent, saved};
    }

    /** These are observations, never acknowledgements or predictions of login success. */
    function setupProgress(host, fileSessions = new Set()) {
        const live = Boolean(host?.sessionId);
        return {host: Boolean(host?.profile?.host && host?.profile?.username), auth: live,
            trust: host?.status?.host_key === 'trusted' || live,
            terminal: live, files: live && fileSessions.has(host.sessionId)};
    }

    function greetingKey(hour) {
        return hour < 11 ? 'greetingMorning' : hour < 18 ? 'greetingDay' : 'greetingEvening';
    }

    return {workFirst, setupProgress, destination, hosts, filter, automationBins, metrics, headline, attention, attentionKey, maintenance, fingerprint, activity, platforms, topology, greetingKey};
}));
