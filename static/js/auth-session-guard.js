(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.AuthSessionGuard = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    const FIVE_MINUTES = 5 * 60 * 1000;
    const ONE_MINUTE = 60 * 1000;
    const RESTORE_TTL = 30 * 60 * 1000;
    const LEGACY_STORAGE_KEY = 'webssh:auth-session-return';
    const STORAGE_KEY_PREFIX = `${LEGACY_STORAGE_KEY}:`;
    let started = false;
    let dismissWarning = null;

    function getSessionManager(browserWindow) {
        // Classic scripts expose this const as a global lexical binding, not
        // a window property. Alternate windows/tests can supply their own manager.
        return browserWindow.SessionManager
            || (browserWindow === root && typeof SessionManager !== 'undefined' ? SessionManager : null);
    }

    function accountScope(browserDocument) {
        return String(browserDocument?.body?.dataset?.connectionHistoryScope || '').trim();
    }

    function storageKey(scope) {
        return scope ? `${STORAGE_KEY_PREFIX}${scope}` : null;
    }

    function pruneRestoreStorage(storage, keepKey) {
        try {
            storage?.removeItem(LEGACY_STORAGE_KEY);
            for (let index = Number(storage?.length) - 1; index >= 0; index -= 1) {
                const key = storage.key(index);
                if (key !== keepKey && key?.startsWith(STORAGE_KEY_PREFIX)) {
                    storage.removeItem(key);
                }
            }
        } catch {
            // Storage cleanup must not affect authentication expiry.
        }
    }

    function readRestore(storage, now = Date.now(), scope = '') {
        const key = storageKey(scope);
        pruneRestoreStorage(storage, key);
        if (!key) return null;
        try {
            const value = JSON.parse(storage?.getItem(key) || 'null');
            if (!value || value.accountScope !== scope || !Number.isFinite(value.savedAt)
                    || value.savedAt > now + ONE_MINUTE
                    || now - value.savedAt > RESTORE_TTL) return null;
            return value;
        } catch {
            return null;
        }
    }

    function saveRestore(
        browserWindow,
        browserDocument,
        storage,
        now = Date.now(),
        scope = accountScope(browserDocument),
    ) {
        const key = storageKey(scope);
        pruneRestoreStorage(storage, key);
        const note = browserDocument.getElementById('sessionNotepad');
        const sessionManager = getSessionManager(browserWindow);
        const layout = sessionManager?.layout;
        const windowMode = layout === 'windows';
        const sessionId = sessionManager?.getActiveSession?.() || null;
        const assignments = sessionManager?.paneAssignments;
        const state = {
            accountScope: scope,
            savedAt: now,
            path: `${browserWindow.location.pathname}${browserWindow.location.search}${browserWindow.location.hash}`,
            sessionId,
            primaryView: browserDocument.body?.dataset?.primaryWorkspace || 'workspaces',
            activeContext: browserWindow.workspaceLayoutController?.getState?.().activeContext || null,
            noteDraft: browserWindow.notepadController?.hasUnsaved?.() ? note?.value : null,
            // Older clients read these fields on rollback. Keep a usable split
            // fallback; window geometry is already stored separately per session.
            layout: windowMode ? 1 : layout || null,
            ...(windowMode ? {windowMode: true} : {}),
            paneAssignments: Array.isArray(assignments)
                ? windowMode ? [sessionId || assignments.find(Boolean) || null] : assignments.slice(0, 4)
                : [],
            commandDrafts: Array.from(
                browserWindow.SessionCommandLauncher?.parameterDrafts?.entries?.() || [],
            ).filter(([key, value]) => (
                typeof key === 'string' && typeof value === 'string' && value.length <= 4096
            )).slice(0, 100),
        };
        try {
            if (key) storage?.setItem(key, JSON.stringify(state));
        } catch {
            // Session storage is optional; expiry still proceeds safely.
        }
        return state;
    }

    function restore(browserWindow, browserDocument, storage, scope = accountScope(browserDocument)) {
        const key = storageKey(scope);
        const state = readRestore(storage, Date.now(), scope);
        if (!state) return false;
        const sessionManager = getSessionManager(browserWindow);
        try { storage?.removeItem(key); } catch { /* optional storage */ }
        if (typeof state.noteDraft === 'string') {
            const note = browserDocument.getElementById('sessionNotepad');
            if (note) {
                note.value = state.noteDraft;
                note.dispatchEvent(new browserWindow.Event('input', { bubbles: true }));
            }
        }
        if (Array.isArray(state.commandDrafts) && browserWindow.SessionCommandLauncher) {
            browserWindow.SessionCommandLauncher.parameterDrafts = new Map(
                state.commandDrafts.filter(entry => Array.isArray(entry) && entry.length === 2),
            );
        }
        if (typeof state.path === 'string' && state.path.startsWith('/')
                && !state.path.startsWith('//')) {
            browserWindow.history?.replaceState?.(null, '', state.path);
        }
        let attempts = 0;
        let uiRestored = false;
        let applying = false;
        // Also accept records written before the split-compatible format.
        const windowMode = state.windowMode === true || state.layout === 'windows';
        const layout = windowMode ? 'windows' : state.layout;
        const apply = () => {
            if (applying) return false;
            applying = true;
            try {
                attempts += 1;
                if ([1, 2, 4, 'windows'].includes(layout) && sessionManager?.setSplitLayout) {
                    sessionManager.setSplitLayout(layout);
                }
                if (!windowMode && Array.isArray(state.paneAssignments)) {
                    state.paneAssignments.forEach((sessionId, paneIndex) => {
                        if (sessionId && sessionManager?.getSession?.(sessionId)) {
                            sessionManager.assignSessionToPane?.(sessionId, paneIndex);
                        }
                    });
                }
                if (state.sessionId && sessionManager?.getSession?.(state.sessionId)) {
                    sessionManager.switchSession(state.sessionId);
                }
                if (!uiRestored) {
                    if (state.primaryView === 'overview') browserDocument.getElementById('overviewNavBtn')?.click();
                    else if (state.primaryView === 'files') browserDocument.getElementById('fileTransferBtn')?.click();
                    else if (state.primaryView === 'hosts') browserDocument.getElementById('manageProfilesBtn')?.click();
                    else if (state.primaryView === 'commands') browserDocument.getElementById('commandLibraryBtn')?.click();
                    else browserWindow.primaryWorkspaceController?.showWorkspaces?.();
                    if (state.activeContext) {
                        browserWindow.workspaceLayoutController?.openContext?.(state.activeContext, 'restore');
                    }
                    uiRestored = true;
                }
                return !state.sessionId || Boolean(sessionManager?.getSession?.(state.sessionId));
            } finally {
                applying = false;
            }
        };
        const restored = apply();
        const socket = browserWindow.socket;
        if (socket?.on && socket.connected !== true) {
            // The server emits connected/success after all restoration events.
            // Select the saved session after the batch, so later arrivals cannot
            // replace its focus or split assignment. No SSH protocol change.
            const onConnected = data => {
                if (data?.status !== 'success') return;
                socket.off?.('connected', onConnected);
                apply();
            };
            socket.on('connected', onConnected);
        } else if (!restored) {
            const listener = () => {
                if (apply() || attempts >= 20) {
                    browserWindow.removeEventListener('session-workspace-change', listener);
                }
            };
            browserWindow.addEventListener('session-workspace-change', listener);
        }
        return true;
    }

    function create(options = {}) {
        const browserWindow = options.window || root;
        const browserDocument = options.document || browserWindow.document;
        let storage = options.storage || null;
        if (!storage) {
            try { storage = browserWindow.sessionStorage; } catch { storage = null; }
        }
        const now = options.now || Date.now;
        const scope = String(options.accountScope
            ?? accountScope(browserDocument)).trim();
        const setTimer = options.setTimeout || browserWindow.setTimeout.bind(browserWindow);
        const expiresAt = Number(options.expiresAt
            ?? browserDocument.body?.dataset?.authSessionExpiresAt);
        const initialNow = now();
        const suppliedServerNow = Number(options.serverNow
            ?? browserDocument.body?.dataset?.authServerNow);
        const serverNow = Number.isFinite(suppliedServerNow)
            ? suppliedServerNow
            : initialNow;
        const deadline = initialNow + Math.max(0, expiresAt - serverNow);
        let warningLevel = 0;
        let timer = null;

        function message(level) {
            const key = level === 2 ? 'authSession.expiringOne' : 'authSession.expiringFive';
            const fallback = level === 2
                ? 'Your WebSSH sign-in expires in less than one minute. This is separate from the SSH idle timeout. You will return to this workspace after signing in again.'
                : 'Your WebSSH sign-in expires in five minutes. This is separate from the SSH idle timeout; current workspace context will be restored after sign-in.';
            const translated = browserWindow.i18n?.t?.(key);
            return translated && translated !== key ? translated : fallback;
        }

        function showWarning(level) {
            if (warningLevel >= level) return;
            warningLevel = level;
            dismissWarning?.();
            const closeLabel = browserWindow.i18n?.t?.('common.close');
            dismissWarning = browserWindow.showNotification?.({
                message: message(level),
                type: level === 2 ? 'warning' : 'info',
                persistent: true,
                action: {
                    label: closeLabel && closeLabel !== 'common.close' ? closeLabel : 'Close',
                    onClick() {
                        // The notification dismisses itself; the expiry timer keeps running.
                    },
                },
            }) || null;
        }

        function expire() {
            saveRestore(browserWindow, browserDocument, storage, now(), scope);
            browserWindow.authSessionRedirectPending = true;
            const appRoot = String(browserWindow.APP_ROOT || '');
            const next = `${browserWindow.location.pathname}${browserWindow.location.search}`;
            browserWindow.location.assign(`${appRoot}/login?next=${encodeURIComponent(next)}`);
        }

        function schedule() {
            if (!Number.isFinite(deadline)) return false;
            const remaining = deadline - now();
            if (remaining <= 0) return expire();
            if (remaining <= ONE_MINUTE) showWarning(2);
            else if (remaining <= FIVE_MINUTES) showWarning(1);
            const nextDelay = remaining > FIVE_MINUTES
                ? remaining - FIVE_MINUTES
                : remaining > ONE_MINUTE ? remaining - ONE_MINUTE : remaining;
            timer = setTimer(schedule, Math.max(50, Math.min(nextDelay, 2147483647)));
            return timer;
        }

        return {
            schedule,
            expire,
            restore: () => restore(browserWindow, browserDocument, storage, scope),
        };
    }

    function start() {
        if (started || !root?.document) return null;
        started = true;
        const guard = create();
        guard.restore();
        guard.schedule();
        return guard;
    }

    return { create, start, readRestore, saveRestore, restore };
}));
