(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WorkspaceLayoutController = api;
    }
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const CONTEXTS = Object.freeze(['files', 'commands', 'diagnostics', 'notes']);
    const CONTEXT_STORAGE_KEY = 'webssh.workspace.lastContext';
    const CONTEXT_WIDTH_STORAGE_KEY = 'webssh.workspace.contextWidth';
    const CONTEXT_WIDTH_MODE_STORAGE_KEY = 'webssh.workspace.contextWidthMode';
    const DEFAULT_CONTEXT_WIDTH = 420;
    const MIN_CONTEXT_WIDTH = 320;
    const MAX_CONTEXT_WIDTH = 720;
    const MIN_TERMINAL_WIDTH = 480;
    const AUTO_CONTEXT_WIDTH_RATIO = 0.32;
    const LAYOUT_CLASSES = ['layout-desktop', 'layout-tablet', 'layout-mobile'];

    function breakpointForWidth(width) {
        const viewportWidth = Number(width);
        if (viewportWidth >= 1024) return 'desktop';
        if (viewportWidth >= 768) return 'tablet';
        return 'mobile';
    }

    function contextWidthBounds(viewportWidth) {
        const usableWidth = Number.isFinite(Number(viewportWidth))
            ? Number(viewportWidth)
            : 1280;
        return {
            min: MIN_CONTEXT_WIDTH,
            max: Math.max(
                MIN_CONTEXT_WIDTH,
                Math.min(MAX_CONTEXT_WIDTH, usableWidth - MIN_TERMINAL_WIDTH),
            ),
        };
    }

    function clampContextWidth(width, viewportWidth) {
        const bounds = contextWidthBounds(viewportWidth);
        const hasStoredWidth = width !== null && width !== undefined && width !== '';
        const numericWidth = hasStoredWidth ? Number(width) : Number.NaN;
        const candidate = Number.isFinite(numericWidth)
            ? numericWidth
            : DEFAULT_CONTEXT_WIDTH;
        return Math.round(Math.min(bounds.max, Math.max(bounds.min, candidate)));
    }

    function defaultContextWidth(viewportWidth) {
        const numericViewport = Number(viewportWidth);
        const usableWidth = Number.isFinite(numericViewport) ? numericViewport : 1280;
        return clampContextWidth(
            Math.max(DEFAULT_CONTEXT_WIDTH, usableWidth * AUTO_CONTEXT_WIDTH_RATIO),
            usableWidth,
        );
    }

    function createController(options = {}) {
        const windowRef = options.window || root;
        const documentRef = options.document || windowRef?.document;
        const storage = options.storage || windowRef?.localStorage;
        const terminalManager = options.terminalManager || windowRef?.TerminalManager;
        const sessionManager = options.sessionManager || windowRef?.SessionManager;
        const socket = options.socket || windowRef?.socket;
        if (!windowRef || !documentRef) return null;

        const byId = id => documentRef.getElementById(id);
        const elements = {
            workspace: byId('workspace'),
            panel: byId('contextWorkspace'),
            resizer: byId('contextWorkspaceResizer'),
            launcher: byId('contextWorkspaceLauncher'),
            close: byId('contextWorkspaceClose'),
            backdrop: byId('contextWorkspaceBackdrop'),
            tablist: byId('contextWorkspaceTabs'),
            mobileMenu: documentRef.querySelector?.('.header-buttons')
                || byId('headerButtons'),
            mobileMenuToggle: byId('mobileMenuBtn'),
            tabs: {},
            panels: {},
        };
        CONTEXTS.forEach(name => {
            const title = name.charAt(0).toUpperCase() + name.slice(1);
            elements.tabs[name] = byId(`context${title}Tab`);
            elements.panels[name] = byId(`context${title}Panel`);
        });
        if (
            !elements.workspace
            || !elements.panel
            || !elements.resizer
            || !elements.launcher
            || !elements.close
            || !elements.tablist
            || CONTEXTS.some(name => !elements.tabs[name] || !elements.panels[name])
        ) {
            return null;
        }

        const mediaQueries = [
            windowRef.matchMedia?.('(min-width: 1024px)'),
            windowRef.matchMedia?.('(min-width: 768px)'),
        ].filter(Boolean);
        const availability = new Map([
            ['files', false],
            ['commands', true],
            ['diagnostics', false],
            ['notes', true],
        ]);
        const cleanup = [];
        let initialized = false;
        let mode = null;
        let activeContext = null;
        let lastContext = 'files';
        let syncTimer = null;
        let contextWidth = DEFAULT_CONTEXT_WIDTH;
        let contextWidthMode = 'auto';
        let resizePointerId = null;
        let userInteractionRevision = 0;
        const sessionDefaults = new Map();

        function listen(target, name, listener) {
            target?.addEventListener?.(name, listener);
            cleanup.push(() => target?.removeEventListener?.(name, listener));
        }

        function scheduleTerminalSync(force = false) {
            if (syncTimer !== null) {
                windowRef.clearTimeout?.(syncTimer);
            }
            syncTimer = windowRef.setTimeout?.(() => {
                syncTimer = null;
                terminalManager?.fitAndSyncVisibleTerminals?.({
                    socket,
                    isConnected: sessionId => Boolean(
                        sessionManager?.getSession?.(sessionId)?.connected
                    ),
                    force,
                });
            }, 120) ?? null;
        }

        function contextEvent(previousContext) {
            const EventConstructor = windowRef.CustomEvent
                || globalThis.CustomEvent;
            if (!EventConstructor) return;
            documentRef.dispatchEvent?.(new EventConstructor('workspace-context-change', {
                detail: { activeContext, previousContext, mode },
            }));
        }

        function contextAvailabilityEvent(name) {
            const EventConstructor = windowRef.CustomEvent
                || globalThis.CustomEvent;
            if (!EventConstructor) return;
            documentRef.dispatchEvent?.(new EventConstructor(
                'workspace-context-availability-change',
                { detail: { name, available: Boolean(availability.get(name)) } },
            ));
        }

        function availableContexts() {
            return CONTEXTS.filter(name => availability.get(name));
        }

        function applyContextWidth() {
            contextWidth = contextWidthMode === 'auto'
                ? defaultContextWidth(windowRef.innerWidth)
                : clampContextWidth(contextWidth, windowRef.innerWidth);
            const bounds = contextWidthBounds(windowRef.innerWidth);
            elements.workspace.style?.setProperty?.(
                '--context-workspace-width',
                `${contextWidth}px`,
            );
            elements.resizer.setAttribute('aria-valuemin', String(bounds.min));
            elements.resizer.setAttribute('aria-valuemax', String(bounds.max));
            elements.resizer.setAttribute('aria-valuenow', String(contextWidth));
        }

        function persistContextWidth() {
            try {
                storage?.setItem?.(CONTEXT_WIDTH_STORAGE_KEY, String(contextWidth));
                storage?.setItem?.(CONTEXT_WIDTH_MODE_STORAGE_KEY, contextWidthMode);
            } catch {
                // Resizing remains available when browser storage is unavailable.
            }
        }

        function setContextWidth(
            nextWidth,
            { persist = false, widthMode = contextWidthMode } = {},
        ) {
            const previousWidth = contextWidth;
            contextWidthMode = widthMode === 'manual' ? 'manual' : 'auto';
            contextWidth = contextWidthMode === 'auto'
                ? defaultContextWidth(windowRef.innerWidth)
                : clampContextWidth(nextWidth, windowRef.innerWidth);
            applyContextWidth();
            if (persist) persistContextWidth();
            if (contextWidth !== previousWidth) scheduleTerminalSync(true);
            return contextWidth;
        }

        function fallbackContext() {
            if (availability.get(lastContext)) return lastContext;
            return ['notes', 'commands', 'files', 'diagnostics']
                .find(name => availability.get(name)) || null;
        }

        function render() {
            LAYOUT_CLASSES.forEach(name => elements.workspace.classList.remove(name));
            elements.workspace.classList.add(`layout-${mode}`);
            const panelOpen = Boolean(activeContext);
            elements.workspace.classList.toggle('context-open', panelOpen);
            elements.panel.hidden = !panelOpen;
            elements.panel.setAttribute('aria-hidden', String(!panelOpen));
            elements.resizer.hidden = !panelOpen || mode !== 'desktop';
            elements.launcher.hidden = panelOpen;
            elements.launcher.setAttribute('aria-expanded', String(panelOpen));
            elements.backdrop?.classList.toggle(
                'visible',
                panelOpen && mode !== 'desktop',
            );
            elements.backdrop?.setAttribute(
                'aria-hidden',
                String(!panelOpen || mode === 'desktop'),
            );

            const focusableContext = panelOpen ? activeContext : fallbackContext();
            CONTEXTS.forEach(name => {
                const selected = activeContext === name;
                const enabled = Boolean(availability.get(name));
                const tab = elements.tabs[name];
                const panel = elements.panels[name];
                tab.disabled = !enabled;
                tab.setAttribute('aria-disabled', String(!enabled));
                tab.setAttribute('aria-selected', String(selected));
                tab.setAttribute('tabindex', name === focusableContext ? '0' : '-1');
                panel.hidden = !selected;
                panel.setAttribute('aria-hidden', String(!selected));
            });
        }

        function openContext(name, reason = 'programmatic') {
            if (!CONTEXTS.includes(name) || !availability.get(name)) return false;
            if (reason === 'user') userInteractionRevision += 1;
            const previousContext = activeContext;
            activeContext = name;
            lastContext = name;
            if (reason === 'user') {
                try {
                    storage?.setItem?.(CONTEXT_STORAGE_KEY, name);
                } catch {
                    // The workspace remains usable when browser storage is unavailable.
                }
            }
            render();
            if (previousContext !== activeContext) contextEvent(previousContext);
            scheduleTerminalSync(true);
            return true;
        }

        function closeContext(reason = 'programmatic') {
            if (!activeContext) return false;
            if (reason === 'user') userInteractionRevision += 1;
            const previousContext = activeContext;
            activeContext = null;
            render();
            contextEvent(previousContext);
            scheduleTerminalSync(true);
            if (reason === 'user') elements.launcher.focus?.();
            return true;
        }

        function setContextAvailability(name, enabled) {
            if (!CONTEXTS.includes(name)) return;
            const normalized = Boolean(enabled);
            if (availability.get(name) === normalized) return;
            availability.set(name, normalized);
            if (
                normalized
                && mode === 'desktop'
                && lastContext === name
                && activeContext !== name
            ) {
                openContext(name);
                contextAvailabilityEvent(name);
                return;
            }
            if (!normalized && activeContext === name) {
                const previousContext = activeContext;
                activeContext = null;
                const fallback = fallbackContext();
                if (fallback) {
                    openContext(fallback);
                } else {
                    render();
                    contextEvent(previousContext);
                    scheduleTerminalSync(true);
                }
                contextAvailabilityEvent(name);
                return;
            }
            render();
            contextAvailabilityEvent(name);
        }

        function reconcile() {
            const nextMode = breakpointForWidth(windowRef.innerWidth);
            const changed = mode !== null && nextMode !== mode;
            const previousMode = mode;
            mode = nextMode;
            applyContextWidth();
            if (changed && previousMode === 'desktop' && mode !== 'desktop' && activeContext) {
                closeContext('responsive');
            }
            if (mode === 'desktop') {
                elements.mobileMenu?.classList.remove('is-open');
                elements.mobileMenuToggle?.setAttribute('aria-expanded', 'false');
            }
            render();
            scheduleTerminalSync(changed);
            return { mode, activeContext, lastContext };
        }

        function selectSessionDefault({ sessionId, sftpAvailable } = {}) {
            if (typeof sessionId !== 'string' || !sessionId) return false;
            let state = sessionDefaults.get(sessionId);
            if (!state) {
                state = { revision: userInteractionRevision, applied: false };
                sessionDefaults.set(sessionId, state);
            }
            if (state.applied || sftpAvailable === null || sftpAvailable === undefined) {
                return false;
            }
            if (state.revision !== userInteractionRevision || mode !== 'desktop') {
                state.applied = true;
                return false;
            }
            const target = sftpAvailable === true ? 'files' : 'diagnostics';
            if (!availability.get(target)) return false;
            const opened = openContext(target, 'session-default');
            if (opened) state.applied = true;
            return opened;
        }

        function handleResizePointerDown(event) {
            if (mode !== 'desktop' || !activeContext) return;
            if (event.button !== undefined && event.button !== 0) return;
            resizePointerId = event.pointerId ?? 'mouse';
            elements.resizer.setPointerCapture?.(event.pointerId);
            elements.workspace.classList.add('context-resizing');
            event.preventDefault?.();
        }

        function handleResizePointerMove(event) {
            if (resizePointerId === null || !Number.isFinite(Number(event.clientX))) return;
            setContextWidth(windowRef.innerWidth - Number(event.clientX), {
                widthMode: 'manual',
            });
            event.preventDefault?.();
        }

        function finishResize(event) {
            if (resizePointerId === null) return;
            elements.resizer.releasePointerCapture?.(event?.pointerId);
            resizePointerId = null;
            elements.workspace.classList.remove('context-resizing');
            persistContextWidth();
            scheduleTerminalSync(true);
        }

        function handleResizeKeydown(event) {
            if (mode !== 'desktop' || !activeContext) return;
            const bounds = contextWidthBounds(windowRef.innerWidth);
            const widths = {
                ArrowLeft: contextWidth + 24,
                ArrowRight: contextWidth - 24,
                Home: bounds.min,
                End: bounds.max,
            };
            if (!Object.hasOwn(widths, event.key)) return;
            event.preventDefault?.();
            setContextWidth(widths[event.key], {
                persist: true,
                widthMode: 'manual',
            });
        }

        function moveTabFocus(event) {
            const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
            if (!keys.includes(event.key)) return;
            const tabs = availableContexts().map(name => elements.tabs[name]);
            if (!tabs.length) return;
            const currentIndex = Math.max(0, tabs.indexOf(event.target));
            let nextIndex = currentIndex;
            if (event.key === 'Home') nextIndex = 0;
            if (event.key === 'End') nextIndex = tabs.length - 1;
            if (event.key === 'ArrowLeft') {
                nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
            }
            if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
            event.preventDefault?.();
            const nextTab = tabs[nextIndex];
            const name = nextTab.getAttribute('data-workspace-context');
            openContext(name, 'user');
            nextTab.focus?.();
        }

        function init() {
            if (initialized) return reconcile();
            initialized = true;
            mode = breakpointForWidth(windowRef.innerWidth);
            try {
                const stored = storage?.getItem?.(CONTEXT_STORAGE_KEY);
                if (CONTEXTS.includes(stored)) lastContext = stored;
                const storedWidth = storage?.getItem?.(CONTEXT_WIDTH_STORAGE_KEY);
                const numericStoredWidth = Number(storedWidth);
                const storedWidthMode = storage?.getItem?.(
                    CONTEXT_WIDTH_MODE_STORAGE_KEY,
                );
                if (storedWidthMode === 'manual' && Number.isFinite(numericStoredWidth)) {
                    contextWidthMode = 'manual';
                    contextWidth = clampContextWidth(storedWidth, windowRef.innerWidth);
                } else if (storedWidthMode === 'auto') {
                    contextWidthMode = 'auto';
                    contextWidth = defaultContextWidth(windowRef.innerWidth);
                } else if (
                    storedWidth !== null
                    && storedWidth !== ''
                    && Number.isFinite(numericStoredWidth)
                    && numericStoredWidth !== DEFAULT_CONTEXT_WIDTH
                ) {
                    contextWidthMode = 'manual';
                    contextWidth = clampContextWidth(storedWidth, windowRef.innerWidth);
                } else {
                    contextWidthMode = 'auto';
                    contextWidth = defaultContextWidth(windowRef.innerWidth);
                }
            } catch {
                lastContext = 'files';
                contextWidthMode = 'auto';
                contextWidth = defaultContextWidth(windowRef.innerWidth);
            }
            if (mode === 'desktop') {
                activeContext = fallbackContext();
            }
            applyContextWidth();
            render();

            CONTEXTS.forEach(name => {
                listen(elements.tabs[name], 'click', () => {
                    if (openContext(name, 'user')) elements.tabs[name].focus?.();
                });
            });
            listen(elements.tablist, 'keydown', moveTabFocus);
            listen(elements.launcher, 'click', () => {
                const context = fallbackContext();
                if (context && openContext(context, 'user')) {
                    elements.tabs[context].focus?.();
                }
            });
            listen(elements.close, 'click', () => closeContext('user'));
            listen(elements.resizer, 'pointerdown', handleResizePointerDown);
            listen(elements.resizer, 'keydown', handleResizeKeydown);
            listen(elements.resizer, 'dblclick', () => {
                setContextWidth(defaultContextWidth(windowRef.innerWidth), {
                    persist: true,
                    widthMode: 'auto',
                });
            });
            listen(documentRef, 'pointermove', handleResizePointerMove);
            listen(documentRef, 'pointerup', finishResize);
            listen(documentRef, 'pointercancel', finishResize);
            listen(elements.backdrop, 'click', () => closeContext('user'));
            listen(documentRef, 'keydown', event => {
                if (event.key === 'Escape' && activeContext && mode !== 'desktop') {
                    event.preventDefault?.();
                    closeContext('user');
                }
            });
            listen(windowRef, 'resize', reconcile);
            listen(windowRef, 'orientationchange', reconcile);
            listen(windowRef.visualViewport, 'resize', () => scheduleTerminalSync());
            mediaQueries.forEach(query => listen(query, 'change', reconcile));
            scheduleTerminalSync(true);
            return { mode, activeContext, lastContext };
        }

        function setNotesOpen(open, reason = 'programmatic') {
            if (open) return openContext('notes', reason);
            return activeContext === 'notes' ? closeContext(reason) : false;
        }

        function setCommandsOpen(open, reason = 'programmatic') {
            if (open) return openContext('commands', reason);
            return activeContext === 'commands' ? closeContext(reason) : false;
        }

        function destroy() {
            cleanup.splice(0).forEach(remove => remove());
            if (syncTimer !== null) windowRef.clearTimeout?.(syncTimer);
            syncTimer = null;
            initialized = false;
        }

        return Object.freeze({
            init,
            reconcile,
            openContext,
            closeContext,
            setContextAvailability,
            selectSessionDefault,
            setNotesOpen,
            setCommandsOpen,
            getContextWidth: () => contextWidth,
            getContextWidthMode: () => contextWidthMode,
            getState: () => ({ mode, activeContext, lastContext }),
            destroy,
        });
    }

    return Object.freeze({
        CONTEXTS,
        breakpointForWidth,
        clampContextWidth,
        defaultContextWidth,
        createController,
    });
}));
