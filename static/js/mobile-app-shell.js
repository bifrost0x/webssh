/* Mobile-first application shell for the existing WebSSH workspaces. */
(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.MobileAppShell = api;
}(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';

    const VIEW_TARGETS = Object.freeze({
        workspaces: 'workspaceNavBtn',
        hosts: 'manageProfilesBtn',
        files: 'fileTransferBtn',
        commands: 'commandLibraryBtn',
    });

    function createController(options = {}) {
        const windowRef = options.window || window;
        const documentRef = options.document || document;
        const sessionManager = options.sessionManager || windowRef.SessionManager;
        const terminalManager = options.terminalManager || windowRef.TerminalManager;
        const byId = id => documentRef.getElementById(id);
        const elements = {
            body: documentRef.body,
            headerButtons: byId('headerButtons'),
            menuButton: byId('mobileMenuBtn'),
            menuBackdrop: byId('mobileMenuBackdrop'),
            moreButton: byId('mobileMoreBtn'),
            commandToggle: byId('mobileCommandToggle'),
            commandClose: byId('mobileInputCloseBtn'),
            mobileInput: byId('mobileInput'),
            sessionSummary: byId('mobileSessionSummary'),
            sessionSummaryLabel: byId('mobileSessionSummaryLabel'),
            sessionStatus: documentRef.querySelector?.('.mobile-session-status'),
            dockItems: Array.from(documentRef.querySelectorAll?.('[data-mobile-view]') || []),
            modalBackground: [
                documentRef.querySelector?.('.header-title-row'),
                documentRef.querySelector?.('.session-tabs-row'),
                byId('primaryWorkspaceSurface'),
                documentRef.querySelector?.('.main-content'),
                byId('workspaceStatusBar'),
                byId('mobileCommandToggle'),
                byId('mobileAppDock'),
            ].filter(Boolean),
        };
        const listeners = [];
        const backgroundState = new Map();
        let initialized = false;
        let commandOpen = false;
        let moreOpen = false;
        let moreReturnFocus = null;

        function listen(target, name, listener) {
            target?.addEventListener?.(name, listener);
            listeners.push(() => target?.removeEventListener?.(name, listener));
        }

        function isPhone() {
            return windowRef.matchMedia?.(
                '(max-width: 767px), (max-height: 520px) and (pointer: coarse)'
            ).matches
                ?? windowRef.innerWidth < 768;
        }

        function translate(key, fallback) {
            const value = windowRef.i18n?.t?.(key);
            return value && value !== key ? value : fallback;
        }

        function scheduleTerminalFit() {
            windowRef.requestAnimationFrame?.(() => {
                terminalManager?.fitAndSyncVisibleTerminals?.({
                    socket: windowRef.socket,
                    isConnected: sessionId => Boolean(
                        sessionManager?.getSession?.(sessionId)?.connected
                    ),
                    force: true,
                });
            });
        }

        function updateSessionSummary() {
            const sessionId = sessionManager?.getActiveSession?.();
            const session = sessionId ? sessionManager?.getSession?.(sessionId) : null;
            const connected = Boolean(session?.connected);
            const label = session
                ? sessionManager?.getDisplayLabel?.(
                    sessionId,
                    session.username,
                    session.host,
                ) || session.displayName || session.host || sessionId
                : translate('workspace.noActiveSession', 'No active session');

            if (elements.sessionSummaryLabel) elements.sessionSummaryLabel.textContent = label;
            if (elements.sessionSummary) {
                elements.sessionSummary.disabled = !session;
                elements.sessionSummary.setAttribute(
                    'aria-label',
                    session
                        ? `${translate('workspaceContext.activeSession', 'Active session')}: ${label}`
                        : translate('workspace.noActiveSession', 'No active session'),
                );
            }
            elements.sessionStatus?.classList.toggle('connected', connected);
            elements.sessionStatus?.classList.toggle(
                'disconnected',
                Boolean(session && !connected),
            );
            if (elements.commandToggle) elements.commandToggle.disabled = !session;
            if (!session) setCommandOpen(false);
        }

        function setActiveView(view = 'workspaces') {
            elements.dockItems.forEach(button => {
                if (button.dataset.mobileView === 'more') return;
                const selected = button.dataset.mobileView === view;
                button.classList.toggle('active', selected);
                if (selected) button.setAttribute('aria-current', 'page');
                else button.removeAttribute('aria-current');
            });
        }

        function setCommandOpen(open) {
            commandOpen = Boolean(open && isPhone() && !elements.commandToggle?.disabled);
            elements.body?.classList.toggle('mobile-command-open', commandOpen);
            elements.commandToggle?.setAttribute('aria-expanded', String(commandOpen));
            if (elements.commandToggle) {
                const key = commandOpen ? 'terminal.hideInput' : 'terminal.showInput';
                const fallback = commandOpen ? 'Hide command input' : 'Show command input';
                elements.commandToggle.setAttribute('aria-label', translate(key, fallback));
                elements.commandToggle.dataset.i18nAriaLabel = key;
            }
            if (commandOpen) {
                windowRef.requestAnimationFrame?.(() => elements.mobileInput?.focus?.());
            }
            scheduleTerminalFit();
            return commandOpen;
        }

        function setBackgroundInert(inert) {
            if (inert) {
                elements.modalBackground.forEach(element => {
                    if (!backgroundState.has(element)) {
                        backgroundState.set(element, {
                            inert: Boolean(element.inert),
                            ariaHidden: element.getAttribute?.('aria-hidden'),
                        });
                    }
                    element.inert = true;
                    element.setAttribute?.('aria-hidden', 'true');
                });
                return;
            }

            backgroundState.forEach((state, element) => {
                element.inert = state.inert;
                if (state.ariaHidden === null || state.ariaHidden === undefined) {
                    element.removeAttribute?.('aria-hidden');
                } else {
                    element.setAttribute?.('aria-hidden', state.ariaHidden);
                }
            });
            backgroundState.clear();
        }

        function moreFocusableItems() {
            return Array.from(elements.headerButtons?.querySelectorAll?.(
                'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
            ) || []).filter(element => (
                !element.hidden
                && element.getAttribute?.('aria-hidden') !== 'true'
                && (
                    typeof element.getClientRects !== 'function'
                    || element.getClientRects().length > 0
                )
            ));
        }

        function focusFirstMoreAction() {
            const target = moreFocusableItems()[0] || elements.headerButtons;
            target?.focus?.();
        }

        function trapMoreFocus(event) {
            const items = moreFocusableItems();
            if (!items.length) {
                event.preventDefault?.();
                elements.headerButtons?.focus?.();
                return;
            }
            const first = items[0];
            const last = items[items.length - 1];
            const active = documentRef.activeElement;
            const inside = elements.headerButtons?.contains?.(active);
            if (event.shiftKey && (!inside || active === first)) {
                event.preventDefault?.();
                last.focus?.();
            } else if (!event.shiftKey && (!inside || active === last)) {
                event.preventDefault?.();
                first.focus?.();
            }
        }

        function setMoreOpen(open, {focus = false, restoreFocus = true} = {}) {
            const wasOpen = moreOpen;
            moreOpen = Boolean(open && isPhone());
            if (moreOpen && !wasOpen) {
                const active = documentRef.activeElement;
                moreReturnFocus = active && active.isConnected !== false
                    ? active
                    : elements.moreButton;
                setCommandOpen(false);
                setBackgroundInert(true);
                elements.headerButtons?.setAttribute?.('role', 'dialog');
                elements.headerButtons?.setAttribute?.('aria-modal', 'true');
                elements.headerButtons?.setAttribute?.(
                    'aria-label',
                    translate('navigation.more', 'More'),
                );
            } else if (!moreOpen && wasOpen) {
                setBackgroundInert(false);
                elements.headerButtons?.removeAttribute?.('role');
                elements.headerButtons?.removeAttribute?.('aria-modal');
                elements.headerButtons?.removeAttribute?.('aria-label');
            }
            elements.headerButtons?.classList.toggle('is-open', moreOpen);
            elements.body?.classList.toggle('mobile-more-open', moreOpen);
            elements.menuButton?.setAttribute('aria-expanded', String(moreOpen));
            elements.moreButton?.setAttribute('aria-expanded', String(moreOpen));
            elements.moreButton?.classList.toggle('active', moreOpen);
            if (elements.menuBackdrop) elements.menuBackdrop.hidden = !moreOpen;
            if (!moreOpen) windowRef.closeAccountDropdownHeader?.();
            if (moreOpen && focus) {
                windowRef.requestAnimationFrame?.(focusFirstMoreAction);
            } else if (!moreOpen && wasOpen) {
                const target = moreReturnFocus;
                moreReturnFocus = null;
                if (restoreFocus && target?.isConnected !== false) {
                    windowRef.requestAnimationFrame?.(() => target?.focus?.());
                }
            }
            return moreOpen;
        }

        function handleDockClick(event) {
            const view = event.currentTarget?.dataset?.mobileView;
            if (view === 'more') {
                setMoreOpen(!moreOpen, {focus: true});
                return;
            }
            const targetId = VIEW_TARGETS[view];
            if (!targetId) return;
            setMoreOpen(false);
            byId(targetId)?.click?.();
        }

        function handleSessionSummary() {
            const sessionId = sessionManager?.getActiveSession?.();
            const tab = sessionId ? byId(`tab-${sessionId}`) : null;
            tab?.scrollIntoView?.({behavior: 'smooth', block: 'nearest', inline: 'center'});
            tab?.focus?.();
        }

        function init() {
            if (initialized || !elements.body) return controller;
            initialized = true;
            elements.dockItems.forEach(button => listen(button, 'click', handleDockClick));
            listen(elements.commandToggle, 'click', () => setCommandOpen(!commandOpen));
            listen(elements.commandClose, 'click', () => setCommandOpen(false));
            listen(elements.menuBackdrop, 'click', () => setMoreOpen(false));
            listen(elements.sessionSummary, 'click', handleSessionSummary);
            listen(windowRef, 'session-workspace-change', updateSessionSummary);
            listen(windowRef, 'session-removed', updateSessionSummary);
            listen(windowRef, 'languageChanged', updateSessionSummary);
            listen(windowRef, 'primary-workspace-change', event => {
                const view = event.detail?.view || 'workspaces';
                setMoreOpen(false, {restoreFocus: false});
                setActiveView(view);
                if (view !== 'workspaces') setCommandOpen(false);
            });
            listen(windowRef, 'resize', () => {
                if (!isPhone()) {
                    setMoreOpen(false, {restoreFocus: false});
                    setCommandOpen(false);
                }
            });
            listen(documentRef, 'keydown', event => {
                if (event.key === 'Tab' && moreOpen) {
                    trapMoreFocus(event);
                    return;
                }
                if (event.key !== 'Escape') return;
                if (moreOpen) {
                    event.preventDefault?.();
                    setMoreOpen(false);
                } else if (commandOpen) {
                    event.preventDefault?.();
                    setCommandOpen(false);
                }
            });
            setActiveView(elements.body.dataset.primaryWorkspace || 'workspaces');
            updateSessionSummary();
            return controller;
        }

        function destroy() {
            listeners.splice(0).forEach(dispose => dispose());
            initialized = false;
            setMoreOpen(false, {restoreFocus: false});
            setCommandOpen(false);
        }

        const controller = {
            init,
            destroy,
            isPhone,
            setActiveView,
            setCommandOpen,
            toggleMoreMenu: () => setMoreOpen(!moreOpen, {focus: true}),
            closeMoreMenu: () => setMoreOpen(false),
            getState: () => ({commandOpen, moreOpen}),
        };
        return controller;
    }

    return {createController, VIEW_TARGETS};
}));
