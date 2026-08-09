(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.CommandPaletteUtils = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const MAX_ITEMS = 50;
    const KIND_ORDER = {
        session: 0,
        profile: 1,
        action: 2,
    };

    function clean(value) {
        return value === undefined || value === null ? '' : String(value).trim();
    }

    function matchScore(fields, query) {
        let best = Number.POSITIVE_INFINITY;
        for (const field of fields) {
            const value = clean(field).toLocaleLowerCase();
            if (!value) continue;
            if (value === query) best = Math.min(best, 0);
            else if (value.startsWith(query)) best = Math.min(best, 1);
            else if (value.split(/\s+/).some(part => part.startsWith(query))) {
                best = Math.min(best, 2);
            } else if (value.includes(query)) best = Math.min(best, 3);
        }
        return best;
    }

    function endpoint(item, formatter) {
        if (typeof formatter === 'function') {
            return clean(formatter(item));
        }
        const username = clean(item?.username);
        const host = clean(item?.host);
        const port = clean(item?.port);
        if (!host) return '';
        return `${username ? `${username}@` : ''}${host}${port ? `:${port}` : ''}`;
    }

    function buildItems(options = {}) {
        const actions = Array.isArray(options.actions) ? options.actions : [];
        const profiles = Array.isArray(options.profiles) ? options.profiles : [];
        const sessions = Array.isArray(options.sessions) ? options.sessions : [];
        const labels = options.labels || {};
        const query = clean(options.query).toLocaleLowerCase();
        const requestedLimit = Number(options.limit);
        const limit = Number.isInteger(requestedLimit) && requestedLimit > 0
            ? Math.min(requestedLimit, MAX_ITEMS)
            : MAX_ITEMS;
        const candidates = [];
        let sequence = 0;

        for (const session of sessions) {
            if (!session || session.connected !== true || !clean(session.id)) continue;
            const description = endpoint(session, options.formatEndpoint);
            const label = clean(
                typeof options.sessionLabel === 'function'
                    ? options.sessionLabel(session)
                    : session.displayName,
            ) || description;
            const score = query ? matchScore([
                label,
                description,
                session.displayName,
                session.username,
                session.host,
            ], query) : 0;
            if (!Number.isFinite(score)) continue;
            candidates.push({
                item: {
                    kind: 'session',
                    id: clean(session.id),
                    label,
                    description,
                    hint: clean(labels.activeSession),
                },
                score,
                sequence: sequence++,
            });
        }

        for (const profile of profiles) {
            if (!profile || !clean(profile.id) || (!query && profile.favorite !== true)) {
                continue;
            }
            const description = endpoint(profile, options.formatEndpoint);
            const label = clean(profile.name) || description;
            const score = query ? matchScore([
                label,
                description,
                profile.username,
                profile.host,
                profile.group,
            ], query) : 0;
            if (!Number.isFinite(score)) continue;
            candidates.push({
                item: {
                    kind: 'profile',
                    id: clean(profile.id),
                    label,
                    description,
                    hint: clean(labels.savedHost),
                },
                score,
                sequence: sequence++,
            });
        }

        for (const action of actions) {
            if (!action || !clean(action.id)) continue;
            const label = clean(action.label);
            const description = clean(action.description);
            const score = query ? matchScore([label, description], query) : 0;
            if (!Number.isFinite(score)) continue;
            candidates.push({
                item: {
                    kind: 'action',
                    id: clean(action.id),
                    label,
                    description,
                    hint: clean(action.hint),
                },
                score,
                sequence: sequence++,
            });
        }

        candidates.sort((left, right) => (
            left.score - right.score
            || KIND_ORDER[left.item.kind] - KIND_ORDER[right.item.kind]
            || left.sequence - right.sequence
        ));

        const seen = new Set();
        const result = [];
        for (const candidate of candidates) {
            const key = `${candidate.item.kind}:${candidate.item.id}`;
            if (seen.has(key)) continue;
            seen.add(key);
            result.push(candidate.item);
            if (result.length >= limit) break;
        }
        return result;
    }

    return {
        buildItems,
    };
}));
