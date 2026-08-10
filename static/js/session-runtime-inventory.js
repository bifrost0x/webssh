(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionRuntimeInventoryModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const RESPONSE_TIMEOUT_MS = 3500;
    const SYSTEMD_ACTIONS = new Set(['start', 'stop', 'restart']);
    const UNIT_NAME = /^[A-Za-z0-9@_.:-]{1,200}$/;
    const PERMISSION_SCOPES = new Set(['systemd', 'docker']);

    function filterServices(services, filter) {
        const rows = Array.isArray(services) ? services : [];
        const query = String(filter || 'all').trim().toLowerCase();
        if (query === 'all' || query === '') return rows.slice();
        return rows.filter(service => {
            const state = String(service?.active || service?.state || '').toLowerCase();
            if (query === 'active' || query === 'failed' || query === 'inactive') {
                return state === query;
            }
            return [service?.unit, service?.description]
                .some(value => String(value || '').toLowerCase().includes(query));
        });
    }

    function filterContainers(containers, query) {
        const rows = Array.isArray(containers) ? containers : [];
        const needle = String(query || '').trim().toLowerCase();
        if (!needle) return rows.slice();
        return rows.filter(container => [container?.name, container?.status]
            .some(value => String(value || '').toLowerCase().includes(needle)));
    }

    function buildSystemdCommand(action, unit) {
        if (!SYSTEMD_ACTIONS.has(action) || typeof unit !== 'string' || !UNIT_NAME.test(unit)) {
            return null;
        }
        return `sudo systemctl ${action} -- ${unit}`;
    }

    async function copySystemdCommand(action, unit, writeText) {
        const command = buildSystemdCommand(action, unit);
        if (!command || typeof writeText !== 'function') return null;
        await writeText(command);
        return command;
    }

    function permissionDenied(payload) {
        if (!Array.isArray(payload?.permission_denied)) return [];
        const scopes = [];
        payload.permission_denied.forEach(scope => {
            if (PERMISSION_SCOPES.has(scope) && !scopes.includes(scope)) scopes.push(scope);
        });
        return scopes;
    }

    function responseInventory(payload, denied) {
        const inventory = {};
        if (payload?.systemd && typeof payload.systemd === 'object' && !denied.includes('systemd')) {
            inventory.systemd = payload.systemd;
        }
        if (payload?.docker && typeof payload.docker === 'object' && !denied.includes('docker')) {
            inventory.docker = payload.docker;
        }
        return Object.keys(inventory).length ? inventory : null;
    }

    function createController(options) {
        const socket = options.socket;
        const render = options.render || (() => {});
        const setTimeoutFn = options.setTimeoutFn || setTimeout;
        const clearTimeoutFn = options.clearTimeoutFn || clearTimeout;
        const cacheBySession = new Map();
        let sessionId = null;
        let connected = false;
        let open = false;
        let status = 'disconnected';
        let requestCounter = 0;
        let pendingRequest = null;
        let responseTimeoutId = null;

        function cachedState(id) {
            return id ? cacheBySession.get(id) || null : null;
        }

        function stateFor(status) {
            const cached = cachedState(sessionId);
            return {
                sessionId,
                status,
                inventory: cached?.inventory || null,
                sampledAt: cached?.sampledAt || null,
                permissionDenied: cached?.permissionDenied ? cached.permissionDenied.slice() : [],
            };
        }

        function renderCurrent(nextStatus) {
            status = nextStatus || 'disconnected';
            const current = stateFor(status);
            render({
                ...current,
                inventory: current.inventory ? { ...current.inventory } : null,
            });
        }

        function clearResponseTimeout() {
            if (responseTimeoutId !== null) {
                clearTimeoutFn(responseTimeoutId);
                responseTimeoutId = null;
            }
        }

        function clearPending() {
            clearResponseTimeout();
            pendingRequest = null;
        }

        function renderFailure() {
            renderCurrent(cachedState(sessionId)?.inventory ? 'stale' : 'unavailable');
        }

        function requestInventory() {
            if (!open || !connected || !sessionId || pendingRequest) return;
            requestCounter += 1;
            const requestId = `runtime-inventory-${requestCounter}`;
            const requestedSessionId = sessionId;
            pendingRequest = { sessionId: requestedSessionId, requestId };
            socket.emit('request_session_runtime_inventory', {
                session_id: requestedSessionId,
                request_id: requestId,
            });
            responseTimeoutId = setTimeoutFn(() => {
                if (!pendingRequest || pendingRequest.requestId !== requestId) return;
                pendingRequest = null;
                responseTimeoutId = null;
                renderFailure();
            }, RESPONSE_TIMEOUT_MS);
        }

        function handleResponse(payload) {
            if (!pendingRequest || !payload) return;
            if (
                payload.session_id !== pendingRequest.sessionId
                || payload.request_id !== pendingRequest.requestId
                || payload.session_id !== sessionId
            ) return;

            clearPending();
            if (!payload.success) {
                renderFailure();
                return;
            }

            const denied = permissionDenied(payload);
            const inventory = responseInventory(payload, denied);
            const sampledAt = Number(payload.sampled_at);
            cacheBySession.set(sessionId, {
                inventory,
                sampledAt: Number.isFinite(sampledAt) ? sampledAt : null,
                permissionDenied: denied,
            });
            renderCurrent('ready');
        }

        socket.on('session_runtime_inventory', handleResponse);

        return {
            setSession(nextSessionId, isConnected) {
                clearPending();
                sessionId = typeof nextSessionId === 'string' && nextSessionId ? nextSessionId : null;
                connected = Boolean(isConnected && sessionId);
                renderCurrent(connected ? (cachedState(sessionId)?.inventory ? 'ready' : 'loading') : 'disconnected');
                requestInventory();
            },

            setOpen(nextOpen) {
                open = Boolean(nextOpen);
                if (!open) {
                    clearPending();
                    return;
                }
                renderCurrent(connected ? (cachedState(sessionId)?.inventory ? 'ready' : 'loading') : 'disconnected');
                requestInventory();
            },

            refresh() {
                requestInventory();
            },

            removeSession(removedSessionId) {
                if (typeof removedSessionId !== 'string' || !removedSessionId) return;
                cacheBySession.delete(removedSessionId);
                if (sessionId !== removedSessionId) return;
                clearPending();
                sessionId = null;
                connected = false;
                renderCurrent('disconnected');
            },

            getState() {
                const cached = cachedState(sessionId);
                return {
                    sessionId,
                    status,
                    inventory: cached?.inventory ? { ...cached.inventory } : null,
                    sampledAt: cached?.sampledAt || null,
                    permissionDenied: cached?.permissionDenied ? cached.permissionDenied.slice() : [],
                };
            },

            destroy() {
                clearPending();
                socket.off?.('session_runtime_inventory', handleResponse);
            },
        };
    }

    return {
        RESPONSE_TIMEOUT_MS,
        filterServices,
        filterContainers,
        buildSystemdCommand,
        copySystemdCommand,
        createController,
    };
}));
