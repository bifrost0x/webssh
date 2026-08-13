(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.ConnectionHistoryFactory = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const DEFAULT_MAX_ITEMS = 10;
    const DEFAULT_MAX_AGE = 30 * 24 * 60 * 60 * 1000;
    const LEGACY_STORAGE_KEY = 'recentConnections';

    function normalizeEntry(entry) {
        if (!entry || typeof entry !== 'object') return null;

        const host = typeof entry.host === 'string' ? entry.host.trim() : '';
        const username = typeof entry.username === 'string' ? entry.username.trim() : '';
        const port = Number(entry.port);
        const timestamp = Number(entry.timestamp);
        if (!host || !username || !Number.isInteger(port) || port < 1 || port > 65535) {
            return null;
        }
        if (!Number.isFinite(timestamp) || timestamp <= 0) return null;
        return { host, port, username, timestamp };
    }

    function createConnectionHistory(options = {}) {
        const storage = options.storage;
        const scope = String(options.scope || '').trim();
        const now = typeof options.now === 'function' ? options.now : Date.now;
        const maxItems = Number.isInteger(options.maxItems) && options.maxItems > 0
            ? options.maxItems
            : DEFAULT_MAX_ITEMS;
        const maxAge = Number.isFinite(options.maxAge) && options.maxAge > 0
            ? options.maxAge
            : DEFAULT_MAX_AGE;
        const storageKey = scope ? `${LEGACY_STORAGE_KEY}:${scope}` : null;

        try {
            storage?.removeItem(LEGACY_STORAGE_KEY);
        } catch {
            // History is optional. Restricted browser storage must not block SSH.
        }

        function cleanupInactiveHistories() {
            if (!storage || typeof storage.key !== 'function') return;

            let keys;
            try {
                keys = Array.from({ length: storage.length }, (_, index) => storage.key(index))
                    .filter(key => key?.startsWith(`${LEGACY_STORAGE_KEY}:`) && key !== storageKey);
            } catch {
                return;
            }

            const currentTime = now();
            keys.forEach(key => {
                try {
                    const parsed = JSON.parse(storage.getItem(key) || '[]');
                    const history = Array.isArray(parsed)
                        ? parsed
                            .map(normalizeEntry)
                            .filter(entry => entry && currentTime - entry.timestamp < maxAge)
                            .slice(0, maxItems)
                        : [];
                    if (history.length === 0) {
                        storage.removeItem(key);
                    } else if (JSON.stringify(history) !== JSON.stringify(parsed)) {
                        storage.setItem(key, JSON.stringify(history));
                    }
                } catch {
                    try {
                        storage.removeItem(key);
                    } catch {
                        // History cleanup is best effort only.
                    }
                }
            });
        }

        cleanupInactiveHistories();

        function persist(history) {
            if (!storageKey || !storage) return;
            try {
                storage.setItem(storageKey, JSON.stringify(history));
            } catch {
                // History is convenience data; connecting must remain available.
            }
        }

        function getHistory() {
            if (!storageKey || !storage) return [];

            try {
                const raw = storage.getItem(storageKey);
                const parsed = raw ? JSON.parse(raw) : [];
                if (!Array.isArray(parsed)) {
                    persist([]);
                    return [];
                }

                const currentTime = now();
                const history = parsed
                    .map(normalizeEntry)
                    .filter(entry => entry && currentTime - entry.timestamp < maxAge)
                    .slice(0, maxItems);
                if (JSON.stringify(history) !== JSON.stringify(parsed)) persist(history);
                return history;
            } catch {
                return [];
            }
        }

        function addConnection(host, port, username) {
            if (!storageKey) return;

            const entry = normalizeEntry({ host, port, username, timestamp: now() });
            if (!entry) return;
            const history = getHistory().filter(item => !(
                item.host === entry.host
                && item.port === entry.port
                && item.username === entry.username
            ));
            history.unshift(entry);
            persist(history.slice(0, maxItems));
        }

        return {
            addConnection,
            getHistory,
            storageKey,
        };
    }

    return { createConnectionHistory };
}));
