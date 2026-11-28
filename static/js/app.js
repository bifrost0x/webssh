(function() {
    'use strict';

    window.addEventListener('unhandledrejection', () => {
        console.error('[WebSSH] Unhandled promise rejection');
    });

    window.addEventListener('error', () => {
        console.error('[WebSSH] Uncaught browser error');
    });

    const APP_ROOT = document.querySelector('meta[name="app-root"]')?.content || '';
    window.APP_ROOT = APP_ROOT;
    const socketProtocol = window.WebSSHSocketProtocol;
    if (!socketProtocol) {
        throw new Error('Socket protocol module is unavailable');
    }
    window.socket = io({
        path: APP_ROOT + '/socket.io',
        autoConnect: false,
        auth: { wire_revision: socketProtocol.WIRE_REVISION },
    });
    const outputFlowReconnect = window.WebSSHSocketReconnect.create(
        window.socket
    );


    let socketProtocolReloadPending = false;
    let settingsNavigationPending = false;

    document.addEventListener('click', (event) => {
        const link = event.target.closest?.('#accountSettingsBtn');
        if (!link || event.defaultPrevented || event.button !== 0
            || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey
            || (link.target && link.target !== '_self')) return;
        event.preventDefault();
        settingsNavigationPending = true;
        // Consume the exception in beforeunload, even when the browser defers it.
        try {
            window.location.assign(link.href);
        } catch (error) {
            settingsNavigationPending = false;
            throw error;
        }
    });

    function reloadForSocketProtocolMismatch() {
        socketProtocolReloadPending = true;
        showSocketProtocolReloadNotice();
        window.location.reload();
    }

    window.addEventListener('beforeunload', (event) => {
        const unsavedNotes = window.notepadController?.hasUnsaved() || window.HostContext?.hasUnsaved();
        const unsavedCommands = window.CommandLibrary?.hasUnsavedChanges()
            || window.CommandSetManager?.hasUnsavedChanges();
        const unsavedChanges = unsavedNotes || unsavedCommands;
        if (window.authSessionRedirectPending) {
            window.authSessionRedirectPending = false;
            return;
        }
        if (socketProtocolReloadPending || settingsNavigationPending) {
            socketProtocolReloadPending = false;
            settingsNavigationPending = false;
            if (!unsavedChanges) return;
        }
        const activeSessions = Object.values(SessionManager.sessions).filter(
            session => session.connected
        );
        if (activeSessions.length > 0 || unsavedChanges) {
            const message = unsavedCommands
                ? window.i18n?.t('commandSets.discardHint') || 'Your unsaved changes will be lost.'
                : unsavedNotes
                ? window.i18n?.t('notes.unsaved') || 'Your notes have not been saved.'
                : window.i18n
                ? window.i18n.t(
                    'session.closeWarning',
                    'You have active SSH sessions. They will be closed.',
                )
                : 'You have active SSH sessions. They will be closed.';
            event.preventDefault();
            event.returnValue = message;
            return message;
        }
    });

    // The one HTML escaper of the workspace. Quotes are escaped too, so the
    // result is also safe inside quoted attribute values.
    window.escapeHtml = function(text) {
        return String(text ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll('\'', '&#39;');
    };

    const MAX_TIMED_NOTIFICATIONS = 4;
    const MAX_TIMED_NOTIFICATIONS_NARROW = 2;
    // Success and info toasts that arrive while errors fill the stack wait
    // here and appear once a slot frees, so a prompt is never lost unseen.
    const MAX_QUEUED_NOTIFICATIONS = 8;
    const queuedNotifications = [];
    let placingTimedNotification = false;
    const timedNotificationDismissers = new WeakMap();
    // Where keyboard focus was before it entered the toast stack.
    const notificationReturnFocus = new WeakMap();

    function timedNotificationLimit() {
        try {
            return window.matchMedia?.('(max-width: 599px)').matches
                ? MAX_TIMED_NOTIFICATIONS_NARROW
                : MAX_TIMED_NOTIFICATIONS;
        } catch {
            return MAX_TIMED_NOTIFICATIONS;
        }
    }

    // Oldest success and info toasts give way first; errors and warnings are
    // only evicted when nothing less important is left. The newest toast is a
    // candidate as well, so a success never pushes out an unread error.
    function selectTimedEvictions(entries, limit) {
        const evicted = new Set();
        const excess = Math.max(0, entries.length - limit);
        const byPriority = [
            ...entries.filter(entry => !entry.urgent),
            ...entries.filter(entry => entry.urgent),
        ];
        byPriority.slice(0, excess).forEach(entry => evicted.add(entry));
        return evicted;
    }
    window.WebSSHNotificationPolicy = { selectTimedEvictions };

    function visibleTimedNotificationCount(container) {
        return Array.from(container.children).filter(item => (
            item.dataset.timedNotification === 'true' && !item.classList.contains('fade-out')
        )).length;
    }

    function showQueuedNotification(container) {
        if (placingTimedNotification) return;
        while (queuedNotifications.length > 0
            && visibleTimedNotificationCount(container) < timedNotificationLimit()) {
            queuedNotifications.shift().show();
        }
    }

    window.showNotification = function(message, type = 'info', duration) {
        const presentation = typeof message === 'object' && message !== null
            ? message
            : { message, type, duration };
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        const notificationType = presentation.type || type;
        notification.className = `notification notification-${notificationType}`;
        notification.setAttribute('role', notificationType === 'error' ? 'alert' : 'status');
        const copy = document.createElement('span');
        copy.className = 'notification-copy';
        copy.textContent = String(presentation.message || '');
        notification.appendChild(copy);
        let dismissed = false;
        let queued = null;
        let fadeTimer = null;
        let removeTimer = null;
        notification.addEventListener('focusin', event => {
            const from = event.relatedTarget;
            if (from && !container.contains(from)) notificationReturnFocus.set(container, from);
        });
        // Keyboard users keep their place: focus moves to the neighbouring
        // toast's close button, otherwise back to where it came from.
        const restoreFocus = () => {
            const toasts = Array.from(container.querySelectorAll('.notification'))
                .filter(item => item !== notification && !item.classList.contains('fade-out'));
            const index = Array.from(container.children).indexOf(notification);
            const next = toasts.find(item => Array.from(container.children).indexOf(item) > index)
                || toasts[toasts.length - 1];
            const target = next?.querySelector('.notification-close, .notification-action');
            if (target) {
                target.focus();
            } else {
                const returnFocus = notificationReturnFocus.get(container);
                if (returnFocus?.isConnected && typeof returnFocus.focus === 'function') returnFocus.focus();
            }
        };
        const dismiss = () => {
            if (dismissed) return;
            dismissed = true;
            if (queued) {
                const index = queuedNotifications.indexOf(queued);
                if (index !== -1) queuedNotifications.splice(index, 1);
                queued = null;
                presentation.onDismiss?.();
                return;
            }
            clearTimeout(fadeTimer);
            clearTimeout(removeTimer);
            const hadFocus = notification.contains(document.activeElement);
            notification.classList.add('fade-out');
            if (hadFocus) restoreFocus();
            try {
                presentation.onDismiss?.();
            } finally {
                removeTimer = setTimeout(() => notification.remove(), 300);
                if (notification.dataset.timedNotification === 'true') showQueuedNotification(container);
            }
        };
        if (
            presentation.action?.label
            && (presentation.action?.url || presentation.action?.onClick)
        ) {
            const action = document.createElement(
                presentation.action.onClick ? 'button' : 'a'
            );
            action.className = 'notification-action';
            if (presentation.action.onClick) {
                action.type = 'button';
                action.addEventListener('click', () => {
                    try {
                        presentation.action.onClick();
                    } finally {
                        if (presentation.action.dismissOnClick !== false) {
                            dismiss();
                        }
                    }
                });
            } else {
                // Only same-site or http(s) targets; a notification never runs a script URL.
                let target = '#';
                try {
                    const url = new URL(String(presentation.action.url || ''), window.location.href);
                    if (url.protocol === 'http:' || url.protocol === 'https:') target = url.href;
                } catch {
                    target = '#';
                }
                action.href = target;
            }
            action.textContent = presentation.action.label;
            notification.appendChild(action);
        }
        const urgent = notificationType === 'error' || notificationType === 'warning';
        if (urgent || presentation.persistent === true) {
            const close = document.createElement('button');
            close.type = 'button';
            close.className = 'notification-close';
            close.setAttribute(
                'aria-label',
                (() => {
                    const label = window.i18n?.t('common.dismissNotification');
                    return label && label !== 'common.dismissNotification' ? label : 'Dismiss notification';
                })(),
            );
            const icon = document.createElement('span');
            icon.className = 'material-icons';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = 'close';
            close.appendChild(icon);
            close.addEventListener('click', dismiss);
            notification.classList.add('notification-dismissible');
            notification.appendChild(close);
        }
        // Errors now stay longer; repeated failures (reconnects, polling) must
        // not pile up without bound. The oldest timed toasts give way first.
        notification.addEventListener('keydown', event => {
            if (event.key !== 'Escape' || !notification.classList.contains('notification-dismissible')) return;
            event.preventDefault();
            event.stopPropagation();
            dismiss();
        });
        const show = () => {
            queued = null;
            if (presentation.persistent !== true) {
                notification.dataset.timedNotification = 'true';
                const entries = Array.from(container.children)
                    .filter(item => (
                        item.dataset.timedNotification === 'true' && !item.classList.contains('fade-out')
                    ))
                    .map(item => ({ item, urgent: item.dataset.urgent === 'true' }));
                const incoming = { item: notification, urgent };
                entries.push(incoming);
                const evicted = selectTimedEvictions(entries, timedNotificationLimit());
                if (evicted.has(incoming)) {
                    // Less important than everything on screen; wait for a free slot.
                    queued = { show, dismiss };
                    queuedNotifications.push(queued);
                    if (queuedNotifications.length > MAX_QUEUED_NOTIFICATIONS) {
                        queuedNotifications[0].dismiss();
                    }
                    return;
                }
                placingTimedNotification = true;
                try {
                    evicted.forEach(entry => timedNotificationDismissers.get(entry.item)?.());
                } finally {
                    placingTimedNotification = false;
                }
                notification.dataset.urgent = String(urgent);
                timedNotificationDismissers.set(notification, dismiss);
            }
            container.appendChild(notification);
            if (presentation.persistent !== true) startTimer();
        };

        const startTimer = () => {
            // Errors and warnings stay long enough to be read. Every timed
            // toast waits while the pointer or keyboard focus is on it.
            let remaining = presentation.duration || (urgent ? 8000 : 2000);
            let startedAt = 0;
            let hovered = false;
            let focused = false;
            const start = () => {
                if (dismissed || hovered || focused || fadeTimer !== null) return;
                startedAt = Date.now();
                fadeTimer = setTimeout(dismiss, remaining);
            };
            const pause = () => {
                if (dismissed || fadeTimer === null) return;
                clearTimeout(fadeTimer);
                fadeTimer = null;
                remaining = Math.max(1000, remaining - (Date.now() - startedAt));
            };
            notification.addEventListener('mouseenter', () => {
                hovered = true;
                pause();
            });
            notification.addEventListener('mouseleave', () => {
                hovered = false;
                start();
            });
            notification.addEventListener('focusin', () => {
                focused = true;
                pause();
            });
            notification.addEventListener('focusout', event => {
                if (notification.contains(event.relatedTarget)) return;
                focused = false;
                start();
            });
            start();
        };

        show();
        return dismiss;
    };

    let socketProtocolReloadNoticeVisible = false;

    function showSocketProtocolReloadNotice() {
        if (socketProtocolReloadNoticeVisible) return;
        socketProtocolReloadNoticeVisible = true;
        showNotification({
            message: window.i18n
                ? i18n.t('connection.reloadRequired')
                : 'WebSSH was updated. Reload this page to continue.',
            type: 'error',
            persistent: true,
            onDismiss: () => {
                socketProtocolReloadNoticeVisible = false;
            },
            action: {
                label: window.i18n
                    ? i18n.t('connection.reloadPage')
                    : 'Reload page',
                onClick: reloadForSocketProtocolMismatch,
                dismissOnClick: false,
            },
        });
    }

    let socketProtocolStorage = null;
    try {
        socketProtocolStorage = window.sessionStorage;
    } catch {
        // Some privacy modes intentionally deny access to sessionStorage.
    }
    const socketProtocolMismatch = socketProtocol.createMismatchController({
        storage: socketProtocolStorage,
        disconnect: () => window.socket?.disconnect(),
        reload: reloadForSocketProtocolMismatch,
        showManualReload: showSocketProtocolReloadNotice,
    });
    socket.on(socketProtocol.MISMATCH_EVENT, data => {
        socketProtocolMismatch.handleMismatch(data);
    });
    let connectionErrorNotice = null;
    let connectionErrorReported = false;
    socket.on('connect_error', error => {
        if (error?.data?.code === 'socket_protocol_mismatch') {
            socketProtocolMismatch.handleMismatch(error.data);
            return;
        }
        if (connectionErrorReported) return;
        connectionErrorReported = true;
        // The new realtime server closes with 1013 and a readable reason when
        // a connection limit is reached; Python never sends it.
        const limit = error?.data?.code === 'connection_limit' ? String(error.data.message || '').trim() : '';
        connectionErrorNotice = showNotification({
            message: limit
                ? `Cannot connect to WebSSH: ${limit}`
                : 'Cannot connect to WebSSH. Check your network and sign-in session. '
                    + 'If this continues, check the proxy path, public origin and WebSocket settings.',
            type: 'error',
            persistent: true,
        });
    });
    socket.on('connect', () => {
        connectionErrorNotice?.();
        connectionErrorNotice = null;
        connectionErrorReported = false;
    });

    window.ModalManager = {
        activeModal: null,
        // Modals opened on top of another one; closing the top one hands the
        // focus trap back to the dialog underneath.
        openStack: [],
        previouslyFocused: new WeakMap(),
        focusableSelector: 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',

        focusableElements(modal) {
            // Only hiding inside the dialog counts: some dialogs are shown again
            // without open(), so the root can keep a stale aria-hidden.
            const hiddenWithin = element => {
                const hidden = element.closest('[hidden], [inert], [aria-hidden="true"]');
                return Boolean(hidden && hidden !== modal && modal.contains(hidden));
            };
            return Array.from(modal.querySelectorAll(this.focusableSelector)).filter(element => (
                !element.matches(':disabled')
                && element.getAttribute('tabindex') !== '-1'
                && !hiddenWithin(element)
                && element.getClientRects().length > 0
                && getComputedStyle(element).visibility !== 'hidden'
            ));
        },

        isTrappable(modal) {
            return Boolean(
                modal?.isConnected
                && modal.classList.contains('show')
                && !modal.classList.contains('primary-workspace-view')
            );
        },

        open(modal) {
            if (!modal) return;
            if (document.activeElement && document.activeElement !== document.body) {
                this.previouslyFocused.set(modal, document.activeElement);
            }
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
            if (this.activeModal && this.activeModal !== modal && !this.openStack.includes(this.activeModal)) {
                this.openStack.push(this.activeModal);
            }
            this.openStack = this.openStack.filter(entry => entry !== modal);
            this.openStack.push(modal);
            this.activeModal = modal;

            const focusable = this.focusableElements(modal);
            if (focusable.length > 0) {
                focusable[0].focus();
            }
        },

        close(modal) {
            if (!modal) return;
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
            this.openStack = this.openStack.filter(entry => entry !== modal && this.isTrappable(entry));
            if (this.activeModal === modal) {
                this.activeModal = this.openStack[this.openStack.length - 1] || null;
            }
            const previouslyFocused = this.previouslyFocused.get(modal);
            if (previouslyFocused?.isConnected) {
                previouslyFocused.focus();
            }
            this.previouslyFocused.delete(modal);
        },

        trapFocus(event) {
            if (
                !this.activeModal
                || event.key !== 'Tab'
                || event.defaultPrevented
                || event.ctrlKey
                || event.altKey
                || event.metaKey
                || !this.isTrappable(this.activeModal)
            ) {
                return;
            }
            const modal = this.activeModal;
            const focusable = this.focusableElements(modal);
            if (focusable.length === 0) {
                event.preventDefault();
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            const active = document.activeElement;
            // Focus left on the page body re-enters the dialog. Terminals and
            // native dialogs outside it handle their own keyboard focus.
            const outside = !modal.contains(active) && !active?.closest?.('dialog[open], .xterm');
            if (event.shiftKey && (active === first || outside)) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && (active === last || outside)) {
                event.preventDefault();
                first.focus();
            }
        }
    };

    function openConnectionAssetManager(asset) {
        // Resource views open behind the connection dialog, so leave it first.
        if (document.getElementById('connectionModal')?.classList.contains('show')) {
            dismissConnectionModal();
        }
        if (asset === 'passwords') {
            window.primaryWorkspaceController?.open('hosts', document.getElementById('credentialManagementView'));
            window.NativeCredentials?.mount();
            return;
        }
        const modalByAsset = {
            hosts: 'profileManagementModal',
            'jump-hosts': 'jumpHostManagementModal',
            'socks-proxies': 'socksProxyManagementModal',
            keys: 'keyManagementModal',
        };
        if (asset === 'socks-proxies') { window.SocksProxyManager?.load(); window.SocksProxyManager?.renderList(); }
        const modalId = modalByAsset[asset];
        if (!modalId) return;

        const primaryWorkspace = window.primaryWorkspaceController;
        if (primaryWorkspace) {
            if (asset === 'hosts') {
                ProfileManager.openManagement();
                return;
            }
            ProfileManager.loadKeys();
            if (asset === 'jump-hosts') {
                window.JumpHostManager?.load();
                window.SocksProxyManager?.load();
                window.JumpHostManager?.renderList();
            }
            const view = document.getElementById(modalId);
            primaryWorkspace.open('hosts', view);
            view?.querySelector('[aria-current="page"]')?.focus();
            return;
        }

        const currentModal = document.querySelector(
            '#profileManagementModal.show, #jumpHostManagementModal.show, #socksProxyManagementModal.show, #keyManagementModal.show',
        );
        const switchingFromHosts = currentModal?.id === 'profileManagementModal';
        if (currentModal) {
            window.ModalManager.close(currentModal);
        }

        if (asset === 'hosts') {
            ProfileManager.openManagement();
            return;
        }

        if (asset !== 'keys' || !switchingFromHosts) {
            ProfileManager.loadKeys();
        }
        if (asset === 'jump-hosts') {
            window.JumpHostManager?.load();
            window.SocksProxyManager?.load();
            window.JumpHostManager?.renderList();
        }
        window.ModalManager.open(document.getElementById(modalId));
    }
    window.openConnectionAssetManager = openConnectionAssetManager;
    document.getElementById?.('automationNavBtn')?.addEventListener('click', event => {
            event.preventDefault();
            window.primaryWorkspaceController?.open('automation', document.getElementById('automationNativeView'));
            window.WebSSHAutomation?.activate();
    });
    window.addEventListener('webssh:credentials', () => openConnectionAssetManager('passwords'));
    window.addEventListener('webssh:credential-resource', async event => {
        const id = String(event.detail.resource_id || event.detail.id || '');
        if (id.startsWith('smb:')) {
            let share=window.sftpFileManager?.smbSourceDialog?.savedShares?.find(item=>item.id===id.slice(4));
            if(!share){const state=await window.NativeCredentials.load();const resource=state.profiles.find(item=>item.id===id);if(resource)share={...resource,id:id.slice(4)};}
            if(share)window.sftpFileManager.openSMBSourceDialog(share);
            return;
        }
        if (id.startsWith('socks:')) { openConnectionAssetManager('socks-proxies'); window.SocksProxyManager?.edit(id.slice(6)); return; }
        openConnectionAssetManager(id.startsWith('jump:') ? 'jump-hosts' : 'hosts');
        if (id.startsWith('jump:')) window.JumpHostManager?.edit(id.slice(5));
        else if (!id.startsWith('smb:')) window.ProfileManager?.openEditor(id);
    });

    window.setConnectionAdvancedExpanded = expanded => {
        const advanced = document.getElementById('connectionAdvancedSettings');
        if (advanced) advanced.open = expanded === true;
    };

    let selectedConnectionProfileState = null;
    const pendingReconnectSessionMap = new Map();
    const herdrFallbackNotified = new Set();

    function hasUsableConnectionKey(keyId) {
        return Boolean(keyId) && ProfileManager.keys.some(
            key => key.id === keyId && key.usable === true
        );
    }

    function refreshConnectionProfileKeyResolution() {
        const keyId = document.getElementById('keySelect')?.value;
        const needsKey = selectedConnectionProfileState?.requiresKey === true
            && ProfileManager.keysLoaded === true
            && document.getElementById('authTypeSelect')?.value === 'key'
            && !hasUsableConnectionKey(keyId);
        document.getElementById('connectionProfileKeyResolution')
            ?.classList.toggle('hidden', !needsKey);
    }

    function refreshConnectionProfileJumpResolution() {
        const resolution = document.getElementById('connectionProfileJumpResolution');
        const directConfirm = document.getElementById('connectionProfileDirectConfirm');
        const selectedJumpHostId = document.getElementById('jumpHostSelect')?.value || '';
        const needsDecision = selectedConnectionProfileState?.missingJumpHost === true
            && !selectedJumpHostId;
        resolution?.classList.toggle('hidden', !needsDecision);
        if (!needsDecision && directConfirm) directConfirm.checked = false;
        return needsDecision && directConfirm?.checked !== true;
    }

    window.clearConnectionProfileState = () => {
        selectedConnectionProfileState = null;
        ProfileManager.selectedProfileId = null;
        SessionManager.pendingReconnectProfileId = null;
        SessionManager.pendingReconnectSessionId = null;
        SessionManager.pendingReconnectTmux = null;
        SessionManager.pendingReconnectHerdr = false;
        const jumpSelect = document.getElementById('jumpHostSelect');
        if (jumpSelect) jumpSelect.value = '';
        const jumpPassword = document.getElementById('jumpHostPasswordInput');
        if (jumpPassword) jumpPassword.value = '';
        const socksSelect = document.getElementById('socksProxySelect');
        if (socksSelect) socksSelect.value = '';
        const socksPassword = document.getElementById('socksProxyPasswordInput');
        if (socksPassword) socksPassword.value = '';
        window.SocksProxyManager?.updatePasswordVisibility();
        window.SocksProxyManager?.updateRouteControls();
        window.JumpHostManager?.updatePasswordVisibility();
        window.ConnectionCommandManager?.clear();
        ProfileManager.clearLegacyCommands();
        window.setConnectionAdvancedExpanded(false);

        const useTmuxCheck = document.getElementById('useTmuxCheck');
        if (useTmuxCheck) useTmuxCheck.checked = useTmuxCheck.defaultChecked;

        const profileContext = document.getElementById('connectionProfileContext');
        profileContext?.classList.add('hidden');
        const profileContextName = document.getElementById('connectionProfileContextName');
        if (profileContextName) profileContextName.textContent = '';
        const directConfirm = document.getElementById('connectionProfileDirectConfirm');
        if (directConfirm) directConfirm.checked = false;
        document.getElementById('connectionProfileJumpResolution')?.classList.add('hidden');
        document.getElementById('connectionProfileKeyResolution')?.classList.add('hidden');
    };

    window.prepareSessionReconnectJump = (session, {applyToForm = false} = {}) => {
        if (session.socksProxyId || session.viaSocks) {
            const manager = window.SocksProxyManager;
            const proxy = manager?.loaded === true ? manager.getById(session.socksProxyId) : null;
            const unresolved = !proxy || Boolean(session.jumpHostId || session.viaJump) || session.reconnectRouteKnown === false;
            if (applyToForm) {
                selectedConnectionProfileState = {requiredSocksProxyId: session.socksProxyId || '', missingSocksProxy: unresolved};
                const jumpSelect = document.getElementById('jumpHostSelect');
                if (jumpSelect) jumpSelect.value = '';
                const jumpPassword = document.getElementById('jumpHostPasswordInput');
                if (jumpPassword) jumpPassword.value = '';
                window.JumpHostManager?.updatePasswordVisibility();
                manager?.selectReference(document.getElementById('socksProxySelect'), session.socksProxyId);
                const password = document.getElementById('socksProxyPasswordInput');
                if (password) password.value = '';
                manager?.updatePasswordVisibility();
                manager?.updateRouteControls();
                window.CredentialPicker?.restore?.('socksProxyPasswordInput');
                window.setConnectionAdvancedExpanded(true);
                if (unresolved) window.showNotification?.(window.i18n?.t('connection.socksProxyMissing') || 'SOCKS5 proxy missing', 'error');
            }
            return {requiresForm: unresolved || proxy?.auth_type === 'password', socksProxy: proxy && !unresolved ? {socks_proxy_id: proxy.id} : null};
        }
        const requiredId = session.jumpHostId || '';
        const manager = window.JumpHostManager;
        const jump = manager?.loaded === true && requiredId ? manager.getById(requiredId) : null;
        const unresolved = Boolean((requiredId && !jump) || (session.viaJump && !requiredId)
            || session.reconnectRouteKnown === false);
        if (applyToForm) {
            selectedConnectionProfileState = {missingJumpHost: unresolved};
            const socksSelect = document.getElementById('socksProxySelect');
            if (socksSelect) socksSelect.value = '';
            const socksPassword = document.getElementById('socksProxyPasswordInput');
            if (socksPassword) socksPassword.value = '';
            const select = document.getElementById('jumpHostSelect');
            if (select) select.value = jump ? requiredId : '';
            // Setting the value in code fires no change event; apply the jump host's
            // assigned saved password here, as choosing it by hand does.
            if (jump?.auth_type === 'password') {
                const jumpPassword = document.getElementById('jumpHostPasswordInput');
                if (jumpPassword) jumpPassword.value = '';
                window.CredentialPicker?.restore?.('jumpHostPasswordInput');
            }
            manager?.updatePasswordVisibility();
            window.SocksProxyManager?.updatePasswordVisibility();
            window.SocksProxyManager?.updateRouteControls();
            window.setConnectionAdvancedExpanded(Boolean(jump || unresolved));
            refreshConnectionProfileJumpResolution();
            if (jump?.auth_type === 'password') {
                document.getElementById('jumpHostPasswordInput')?.focus();
            }
        }
        return {
            requiresForm: unresolved || jump?.auth_type === 'password',
            proxyJump: jump ? {jump_host_id: requiredId} : null,
        };
    };

    let connectionHistoryStorage = null;
    try {
        connectionHistoryStorage = window.localStorage;
    } catch {
        // Some privacy modes deny storage access entirely.
    }
    const connectionHistoryStore = window.ConnectionHistoryFactory?.createConnectionHistory({
        storage: connectionHistoryStorage,
        scope: document.body.dataset.connectionHistoryScope,
    }) || { getHistory: () => [], addConnection: () => {} };

    const ConnectionHistory = {
        ...connectionHistoryStore,

        renderHistoryDropdown() {
            const container = document.getElementById('recentConnectionsList');
            if (!container) return;

            const history = this.getHistory();
            document.getElementById('recentConnectionsCard')
                ?.classList.toggle('hidden', history.length === 0);
            container.replaceChildren();
            container.classList.toggle('hidden', history.length === 0);
            document.getElementById('recentConnectionsEmpty')
                ?.classList.toggle('hidden', history.length > 0);

            history.forEach(conn => {
                const option = document.createElement('button');
                option.type = 'button';
                option.className = 'recent-connection-item';
                option.setAttribute('aria-label', `${conn.username}@${conn.host}:${conn.port}`);

                const label = document.createElement('span');
                label.className = 'recent-conn-label';
                label.textContent = `${conn.username}@${conn.host}:${conn.port}`;
                if (conn.socks_proxy_id) {
                    const proxy = window.SocksProxyManager?.getById(conn.socks_proxy_id);
                    const route = proxy
                        ? (window.i18n?.t('connection.socksProxyVia') || 'via SOCKS5 {name}').replace('{name}', proxy.name)
                        : window.i18n?.t('connection.socksProxyMissing') || 'SOCKS5 proxy missing';
                    label.textContent += ` · ${route}`;
                } else if (conn.jump_host_id) {
                    const jump = window.JumpHostManager?.getById(conn.jump_host_id);
                    label.textContent += ` · ${window.i18n?.t('connection.jumpHost') || 'Jump Host'}${jump ? ': ' + jump.name : ''}`;
                }
                option.setAttribute('aria-label', label.textContent);
                const time = document.createElement('span');
                time.className = 'recent-conn-time';
                time.textContent = this.formatTime(conn.timestamp);
                option.append(label, time);
                option.addEventListener('click', () => {
                    window.clearConnectionProfileState();
                    document.getElementById('hostInput').value = conn.host;
                    document.getElementById('portInput').value = conn.port;
                    document.getElementById('usernameInput').value = conn.username;
                    if (conn.socks_proxy_id || conn.jump_host_id) {
                        window.prepareSessionReconnectJump({
                            socksProxyId: conn.socks_proxy_id, viaSocks: Boolean(conn.socks_proxy_id),
                            jumpHostId: conn.jump_host_id, reconnectRouteKnown: true,
                        }, {applyToForm: true});
                    }
                    document.getElementById('passwordInput').focus();
                });
                container.appendChild(option);
            });
        },

        formatTime(timestamp) {
            const diff = Date.now() - timestamp;
            const minutes = Math.floor(diff / 60000);
            const hours = Math.floor(diff / 3600000);
            const days = Math.floor(diff / 86400000);

            if (minutes < 1) return window.i18n?.t('time.justNow', 'just now') || 'just now';
            if (minutes < 60) return `${minutes}m`;
            if (hours < 24) return `${hours}h`;
            return `${days}d`;
        }
    };

    window.ConnectionHistory = ConnectionHistory;

    const TerminalSearch = window.TerminalSearch;
    const FilePreview = window.FilePreview;

    socket.on('connect', () => {
        outputFlowReconnect.clear();
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar && reconnectBar.style.display !== 'none') {
            reconnectBar.style.display = 'none';
            showNotification(
                window.i18n
                    ? i18n.t('connection.reconnected')
                    : 'Reconnected!',
                'success',
                2000
            );
        }
        if (!keepAliveInterval) {
            keepAliveInterval = setInterval(() => {
                if (socket.connected) {
                    socket.emit('keep_alive');
                }
            }, 60000);
        }
    });

    let keepAliveInterval = setInterval(() => {
        if (socket.connected) {
            socket.emit('keep_alive');
        }
    }, 60000);

    window.SSHHostTrust?.init(socket, requestId => Boolean(requestId)
        && !cancelledConnectRequestIds.has(requestId)
        && (requestId === currentConnectRequestId || requestId.startsWith('reconnect_')
            || window.SSHGatewayDialog?.has(requestId)));

    let pendingAuthBannerPrompt = null;

    function closeAuthBannerPrompt(requestId = null) {
        if (
            requestId
            && pendingAuthBannerPrompt
            && pendingAuthBannerPrompt.requestId !== requestId
        ) {
            return false;
        }
        const hadPrompt = pendingAuthBannerPrompt !== null;
        pendingAuthBannerPrompt = null;
        window.ModalManager.close(document.getElementById('sshAuthBannerModal'));
        const connectionModal = document.getElementById('connectionModal');
        if (hadPrompt && connectionModal?.classList.contains('show')) {
            window.ModalManager.activeModal = connectionModal;
        }
        return hadPrompt;
    }

    function answerAuthBannerPrompt(accepted) {
        if (!pendingAuthBannerPrompt) return;
        const promptId = pendingAuthBannerPrompt.promptId;
        closeAuthBannerPrompt();
        socket.emit('ssh_auth_banner_decision', {
            prompt_id: promptId,
            accepted: accepted === true,
        });
    }

    socket.on('ssh_auth_banner', data => {
        if (
            !data
            || typeof data.prompt_id !== 'string'
            || typeof data.banner !== 'string'
        ) {
            return;
        }
        const requestId = typeof data.client_request_id === 'string'
            ? data.client_request_id
            : null;
        const isExpectedRequest = requestId && (
            requestId === currentConnectRequestId
            || requestId.startsWith('reconnect_')
        );
        if (
            !isExpectedRequest
            || cancelledConnectRequestIds.has(requestId)
        ) {
            socket.emit('ssh_auth_banner_decision', {
                prompt_id: data.prompt_id,
                accepted: false,
            });
            return;
        }
        pendingAuthBannerPrompt = { promptId: data.prompt_id, requestId };
        const contextKey = data.context === 'jump_host'
            ? 'connection.authBannerJumpHost'
            : 'connection.authBannerTarget';
        const contextLabel = window.i18n
            ? i18n.t(contextKey)
            : (data.context === 'jump_host' ? 'Jump host' : 'Target host');
        const target = [data.host, data.port].filter(value => value !== undefined).join(':');
        document.getElementById('sshAuthBannerTarget').textContent = `${contextLabel}: ${target}`;
        document.getElementById('sshAuthBannerText').textContent = data.banner;
        window.ModalManager.open(document.getElementById('sshAuthBannerModal'));
    });

    socket.io.on('reconnect_attempt', (attempt) => {
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar) {
            const textEl = reconnectBar.querySelector('.reconnect-text');
            if (textEl) {
                textEl.textContent = window.i18n
                    ? i18n.t('connection.lostReconnectingAttempt')
                        .replace('{attempt}', attempt)
                    : `Connection lost. Reconnecting... (attempt ${attempt})`;
            }
        }
    });

    socket.on('connected', (data) => {
        if (data && data.status === 'success' && window.socket) {
            if (!socketProtocol.isCompatibleServer(data)) {
                socketProtocolMismatch.handleMismatch({
                    status: 'reload_required',
                    code: socketProtocol.MISMATCH_EVENT,
                    required_revision: data.wire_revision,
                });
                return;
            }
            socketProtocolMismatch.markCompatible();
            window.socket.emit('get_notepad');
            window.notepadController?.reconnect();
            window.CommandLibrary?.loadCommands();
            window.CommandSetManager?.load();
        }
    });

    socket.on('ssh_output_resync_required', () => {
        outputFlowReconnect.expectOutputResync();
    });

    socket.on('disconnect', (reason) => {
        FilePreview.interruptSave();
        closeAuthBannerPrompt();
        showNotification(
            window.i18n
                ? i18n.t('connection.disconnectedFromServer')
                : 'Disconnected from server',
            'error'
        );
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar) {
            reconnectBar.style.display = 'flex';
        }
        if (keepAliveInterval) {
            clearInterval(keepAliveInterval);
            keepAliveInterval = null;
        }
        pendingRequestPaneMap.forEach((_pane, requestId) => {
            SessionManager.clearPendingConnection(requestId);
        });
        pendingRequestPaneMap.clear();
        pendingReconnectSessionMap.clear();
        cancelledConnectRequestIds.clear();
        cancellingConnectRequestIds.clear();
        completedWhileCancellingRequestIds.clear();
        cancelledSessionIds.clear();
        currentConnectRequestId = null;
        connectionModalRequestId = null;
        setConnectLoading(false);
        stopConnectTimer();
        outputFlowReconnect.handleDisconnect(reason);
    });

    function discardLateConnection(data, requestId) {
        if (!data?.session_id) return;
        rememberTransientId(cancelledSessionIds, data.session_id);
        if (requestId) {
            socket.emit('ssh_discard_late_connection', {
                session_id: data.session_id,
                client_request_id: requestId,
            });
        } else {
            socket.emit('ssh_disconnect', { session_id: data.session_id });
        }
    }

    socket.on('host_platform', data => {
        const platform = data && Object.hasOwn(window.HostPlatform?.labels || {}, data.platform);
        const profileId = typeof data?.profile_id === 'string' && data.profile_id;
        if (!platform && !Array.isArray(data?.services)) {
            // A greeting without a POSIX shell, or a probe that found nothing,
            // changed only the saved host.
            if (profileId) ProfileManager.loadProfiles();
            return;
        }
        const session = SessionManager.sessions[data.session_id];
        if (session && platform) session.detectedPlatform = data.platform;
        window.HostPlatform?.refreshSessionIcons(SessionManager, ProfileManager.profiles);
        if (profileId) ProfileManager.loadProfiles();
    });

    // The login recheck found the restart marker gone; reload the saved facts.
    socket.on('host_maintenance', data => {
        if (typeof data?.profile_id === 'string' && data.profile_id) ProfileManager.loadProfiles();
    });


    socket.on('ssh_connected', (data) => {
        const requestId = typeof data?.client_request_id === 'string'
            ? data.client_request_id
            : null;
        if (requestId && cancellingConnectRequestIds.has(requestId)) {
            // A completed connection and its cancellation ACK share one
            // ordered socket stream, but the success event can arrive first.
            // Retain that correlation after the success handler clears the
            // pending UI so the ACK can explain that cancellation was too late.
            rememberTransientId(completedWhileCancellingRequestIds, requestId);
        }
        if (requestId && cancelledConnectRequestIds.delete(requestId)) {
            closeAuthBannerPrompt(requestId);
            pendingRequestPaneMap.delete(requestId);
            SessionManager.clearPendingConnection(requestId);
            discardLateConnection(data, requestId);
            return;
        }

        const isCurrentRequest = Boolean(
            requestId && requestId === currentConnectRequestId
        );
        const isReconnectRequest = Boolean(
            requestId && requestId.startsWith('reconnect_')
        );
        if (!isCurrentRequest && !isReconnectRequest) {
            discardLateConnection(data, requestId);
            return;
        }

        closeAuthBannerPrompt(requestId);
        if (requestId) {
            SessionManager.clearPendingConnection(requestId);
        }

        if (isCurrentRequest) {
            stopConnectTimer();
            setConnectLoading(false);
            SessionManager.pendingReconnectTmux = null;
            SessionManager.pendingReconnectHerdr = false;
            SessionManager.pendingReconnectProfileId = null;
            SessionManager.pendingDisplayName = null;
            currentConnectRequestId = null;
            if (connectionModalRequestId === requestId) {
                connectionModalRequestId = null;
            }
            clearPendingPane();
        }

        const sessionId = SessionManager.createSession(data);
        // Tell once per host and page load; reconnects of the same host stay quiet.
        if (!herdrFallbackNotified.has(data.profile_id)
                && window.ProfileLauncherUtils?.herdrFellBack(window.ProfileManager?.getProfile?.(data.profile_id), data)) {
            herdrFallbackNotified.add(data.profile_id);
            showNotification(
                (window.i18n?.t('herdr.sessionFallback') || 'Herdr was not found on {host}. A standard shell was started instead.')
                    .replace('{host}', data.host || ''),
                'info',
            );
        }
        const replacedSessionId = pendingReconnectSessionMap.get(requestId);
        pendingReconnectSessionMap.delete(requestId);
        if (SessionManager.pendingReconnectSessionId === replacedSessionId) {
            SessionManager.pendingReconnectSessionId = null;
        }
        if (replacedSessionId && replacedSessionId !== sessionId
                && SessionManager.sessions[replacedSessionId]) {
            // A newly attached tmux client must survive closing the old transport.
            socket.emit('ssh_disconnect', {
                session_id: replacedSessionId, preserve_tmux: true,
                replacement_session_id: sessionId,
            });
            // The replacement takes over the old session's window in place.
            SessionManager.removeSessionUI(replacedSessionId, {keepWindow: true});
        }

        let targetPane = null;
        if (requestId && pendingRequestPaneMap.has(requestId)) {
            targetPane = pendingRequestPaneMap.get(requestId);
            pendingRequestPaneMap.delete(requestId);
        }
        SessionManager.assignSessionToPane(
            sessionId,
            SessionManager.resolvePaneForNewSession(targetPane),
        );

        if (isCurrentRequest) {
            window.ModalManager.close(document.getElementById('connectionModal'));
        }
        const connMsg = data.via_jump
            ? `Connected to ${data.username}@${data.host} via ${data.via_jump}`
            : `Connected to ${data.username}@${data.host}`;
        showNotification(connMsg, 'success');

        ConnectionHistory.addConnection(data.host, data.port, data.username, {
            socks_proxy_id: data.socks_proxy_id, via_socks: data.via_socks,
            jump_host_id: data.jump_host_id, via_jump: data.via_jump,
        });

    });

    socket.on('ssh_output', (data, acknowledge) => {
        TerminalManager.handleSocketOutput(data, acknowledge);
    });

    socket.on('ssh_error', (data) => {
        const requestId = typeof data?.client_request_id === 'string'
            ? data.client_request_id
            : null;
        pendingReconnectSessionMap.delete(requestId);
        if (requestId && cancelledConnectRequestIds.delete(requestId)) {
            closeAuthBannerPrompt(requestId);
            pendingRequestPaneMap.delete(requestId);
            SessionManager.clearPendingConnection(requestId);
            if (requestId === currentConnectRequestId) {
                currentConnectRequestId = null;
                setConnectLoading(false);
                stopConnectTimer();
            }
            return;
        }

        const isCurrentRequest = Boolean(
            requestId && requestId === currentConnectRequestId
        );
        const isReconnectRequest = Boolean(
            requestId && requestId.startsWith('reconnect_')
        );
        if (requestId && !isCurrentRequest && !isReconnectRequest) {
            return;
        }

        const presentation = window.SSHErrorUI?.describeSSHError?.(
            data,
            key => window.i18n?.t?.(key),
            APP_ROOT,
        ) || { message: `SSH Error: ${data.error}`, type: 'error' };
        if (presentation.action?.asset === 'socks-proxies') presentation.action.onClick = () => openConnectionAssetManager('socks-proxies');
        showNotification(presentation);

        if (!isCurrentRequest) {
            if (isReconnectRequest) closeAuthBannerPrompt(requestId);
            return;
        }

        closeAuthBannerPrompt(requestId);
        stopConnectTimer();
        setConnectLoading(false);
        SessionManager.clearPendingConnection(requestId);
        currentConnectRequestId = null;
        if (connectionModalRequestId === requestId) {
            connectionModalRequestId = null;
        }
        pendingRequestPaneMap.delete(requestId);
    });

    socket.on('ssh_disconnected', (data) => {
        if (cancelledSessionIds.delete(data.session_id)) {
            return;
        }
        const session = SessionManager.getSession(data.session_id);
        if (session?.connected) {
            showNotification(`Session disconnected: ${data.reason}`, 'warning');
        }
        SessionManager.updateSessionStatus(data.session_id, 'disconnected');

        if (window.sftpFileManager) {
            window.sftpFileManager.handleSessionDisconnected(data.session_id);
        }
    });

    socket.on('session_timeout_warning', (data) => {
        const session = `${String(data?.session_id || '').substr(0, 8)}…`;
        const text = window.i18n?.t('session.timeoutWarning');
        showNotification(text && text !== 'session.timeoutWarning'
            ? text.replace('{session}', session)
            : `Session "${session}" will time out in 2 minutes due to inactivity. Type anything to keep it alive.`, 'warning', 10000);
    });

    socket.on('profiles_list', (data) => {
        ProfileManager.setProfiles(data.profiles);
    });

    socket.on('profile_saved', (data) => {
        const created = !ProfileManager.profiles.some(profile => profile.id === data?.profile?.id);
        ProfileManager.upsertProfile(data?.profile);
        const key = created ? 'profiles.savedCreated' : 'profiles.savedUpdated';
        const text = window.i18n?.t(key);
        showNotification(text && text !== key ? text : (created ? 'Host saved' : 'Host updated'), 'success');
    });

    socket.on('profile_deleted', (data) => {
        ProfileManager.removeProfile(data?.profile_id);
        showNotification((window.i18n ? window.i18n.t('toast.hostDeleted') : 'Saved connection deleted successfully'), 'success');
    });

    socket.on('keys_list', (data) => {
        ProfileManager.setKeys(data.keys);
        const pendingKeyId = selectedConnectionProfileState?.pendingKeyId;
        const keySelect = document.getElementById('keySelect');
        if (pendingKeyId && ProfileManager.keys.some(key => key.id === pendingKeyId)) {
            keySelect.value = pendingKeyId;
            selectedConnectionProfileState.pendingKeyId = null;
        }
        refreshConnectionProfileKeyResolution();
    });

    socket.on('key_uploaded', (data) => {
        ProfileManager.upsertKeySummary(data.key);
        showNotification((window.i18n ? window.i18n.t('toast.keyUploaded') : 'SSH key uploaded successfully'), 'success');
        document.getElementById('keyUploadForm')?.reset();
    });

    socket.on('key_renamed', (data) => {
        ProfileManager.upsertKeySummary(data.key);
    });

    socket.on('key_replaced', (data) => {
        ProfileManager.upsertKeySummary(data.key);
        showNotification(
            window.i18n
                ? i18n.t('keys.replacedSuccess')
                : 'SSH key replaced successfully',
            'success',
        );
    });

    socket.on('key_deleted', () => {
        showNotification((window.i18n ? window.i18n.t('toast.keyDeleted') : 'SSH key deleted successfully'), 'success');
    });

    socket.on('socks_proxies_list', data => window.SocksProxyManager?.setSocksProxies(data.socks_proxies));
    socket.on('socks_proxy_saved', data => {
        window.SocksProxyManager?.upsertSocksProxy(data?.socks_proxy);
        showNotification(window.i18n?.t('socksproxies.savedOk') || 'SOCKS5 proxy saved', 'success');
    });
    socket.on('socks_proxy_deleted', data => {
        window.SocksProxyManager?.removeSocksProxy(data?.socks_proxy_id);
        showNotification(window.i18n?.t('socksproxies.deleted') || 'SOCKS5 proxy deleted', 'success');
    });

    socket.on('jump_hosts_list', (data) => {
        if (window.JumpHostManager) window.JumpHostManager.setJumpHosts(data.jump_hosts);
    });

    socket.on('jump_host_saved', (data) => {
        window.JumpHostManager?.upsertJumpHost(data?.jump_host);
        showNotification(window.i18n ? i18n.t('jumphosts.savedOk') : 'Jump host saved', 'success');
    });

    socket.on('jump_host_deleted', (data) => {
        window.JumpHostManager?.removeJumpHost(data?.jump_host_id);
        showNotification(window.i18n ? i18n.t('jumphosts.deleted') : 'Jump host deleted', 'success');
    });

    socket.on('error', (data) => {
        if (window.SocksProxyManager?.handleUsageError(data)) return;
        if (FilePreview.handleSocketError(data)) return;
        if (window.sftpFileManager?.handlesSocketError?.(data)) return;
        showNotification(`Error: ${data.error}`, 'error');
    });

    socket.on('notepad_data', (data) => {
        const notepad = document.getElementById('sessionNotepad');
        if (!notepad) {
            return;
        }
        if (window.notepadController) {
            window.notepadController.receive(data?.notepad || '');
        } else {
            notepad.value = data?.notepad || '';
        }
    });

    let currentConnectRequestId = null;
    let connectionModalRequestId = null;
    let pendingPaneIndex = null;
    const pendingRequestPaneMap = new Map();
    const cancelledConnectRequestIds = new Set();
    const cancellingConnectRequestIds = new Set();
    const completedWhileCancellingRequestIds = new Set();
    const cancelledSessionIds = new Set();
    let connectTimer = null;
    let connectSeconds = 0;
    const CONNECT_CANCEL_ACK_TIMEOUT_MS = 5000;
    const TRANSIENT_ID_TTL_MS = 120000;
    const MAX_TRANSIENT_IDS = 128;
    window.SSHGatewayDialog?.init(socket, (id, done) => cancelConnectionAttempt(id, done));

    function rememberTransientId(collection, value) {
        if (!value) return;
        collection.add(value);
        while (collection.size > MAX_TRANSIENT_IDS) {
            collection.delete(collection.values().next().value);
        }
        window.setTimeout(() => collection.delete(value), TRANSIENT_ID_TTL_MS);
    }

    function closeProfileManagementModal() {
        if (
            window.primaryWorkspaceController
            && ['hosts', 'overview'].includes(window.primaryWorkspaceController.getActiveView())
        ) {
            window.primaryWorkspaceController.showWorkspaces();
            return;
        }
        window.ModalManager?.close(
            document.getElementById('profileManagementModal'),
        );
    }

    function startConnection(connectionData, paneIndex, replacedSessionId = null) {
        if (currentConnectRequestId) return false;

        closeProfileManagementModal();
        const randomSuffix = window.crypto.getRandomValues(new Uint32Array(1))[0]
            .toString(36)
            .slice(0, 4)
            .padStart(4, '0');
        const requestId = (
            `req_${Date.now().toString(36)}_`
            + randomSuffix
        );
        const payload = {
            ...connectionData,
            client_request_id: requestId,
        };
        currentConnectRequestId = requestId;
        if (replacedSessionId) pendingReconnectSessionMap.set(requestId, replacedSessionId);
        pendingPaneIndex = paneIndex;
        SessionManager.createPendingConnection(
            requestId,
            payload.host,
            payload.username,
            payload.port,
        );
        if (paneIndex !== null && paneIndex !== undefined) {
            pendingRequestPaneMap.set(requestId, paneIndex);
            const modalOpen = document.getElementById('connectionModal')
                ?.classList.contains('show');
            SessionManager.restoreConnectionLauncher?.(
                paneIndex,
                { activate: !modalOpen },
            );
        }

        Object.keys(SessionManager.sessions).forEach(sessionId => {
            const session = SessionManager.sessions[sessionId];
            if (session?.isPersistentCandidate
                    && session.host === payload.host
                    && session.port === Number(payload.port)
                    && session.username === payload.username) {
                SessionManager.removeSessionUI(sessionId);
            }
        });

        window.SSHGatewayDialog?.prepare(payload);
        socket.emit('ssh_connect', payload);
        return true;
    }

    function openConnectionModalForPane(paneIndex) {
        if (currentConnectRequestId) {
            showNotification(
                window.i18n
                    ? i18n.t('connection.connectBusy')
                    : 'A connection attempt is already in progress.',
                'info',
            );
            return false;
        }
        window.clearConnectionProfileState();
        connectionModalRequestId = null;
        pendingPaneIndex = paneIndex;

        // Reset the jump host selection so a previous jump never carries into a
        // new connection by accident.
        const jumpHostSelect = document.getElementById('jumpHostSelect');
        if (jumpHostSelect) {
            jumpHostSelect.value = '';
            document.getElementById('jumpHostPasswordGroup')?.classList.add('hidden');
        }

        ConnectionHistory.renderHistoryDropdown();

        const modal = document.getElementById('connectionModal');
        if (window.ModalManager) {
            window.ModalManager.open(modal);
        } else {
            modal.classList.add('show');
        }
        setConnectLoading(false);
        return true;
    }

    function selectConnectionProfile(profileId) {
        if (!profileId) {
            window.clearConnectionProfileState();
            return null;
        }

        const profile = ProfileManager.getProfile(profileId);
        if (!profile) {
            window.clearConnectionProfileState();
            return null;
        }
        const requiredSocksProxyId = profile.socks_proxy_id || '';
        const requiredJumpHostId = profile.jump_host_id || '';
        selectedConnectionProfileState = {
            profileId,
            requiredSocksProxyId,
            missingSocksProxy: Boolean(requiredSocksProxyId && !window.SocksProxyManager?.getById(requiredSocksProxyId)),
            requiresKey: profile.auth_type === 'key',
            pendingKeyId: profile.auth_type === 'key' ? profile.key_id || null : null,
            missingJumpHost: Boolean(
                requiredJumpHostId
                && !window.JumpHostManager?.getById(requiredJumpHostId)
            ),
        };
        ProfileManager.selectProfile(profileId);
        if (document.getElementById('keySelect')?.value === selectedConnectionProfileState.pendingKeyId) {
            selectedConnectionProfileState.pendingKeyId = null;
        }
        const profileContext = document.getElementById('connectionProfileContext');
        profileContext?.classList.remove('hidden');
        const profileContextName = document.getElementById('connectionProfileContextName');
        if (profileContextName) profileContextName.textContent = profile.name || profile.host;
        refreshConnectionProfileKeyResolution();
        refreshConnectionProfileJumpResolution();
        return profile;
    }

    window.selectConnectionProfile = selectConnectionProfile;

    function openProfileForReview(profileId, paneIndex, mode) {
        closeProfileManagementModal();
        if (!openConnectionModalForPane(paneIndex)) return;
        const selected = selectConnectionProfile(profileId);
        if (!selected) return;

        let focusTarget = document.getElementById('connectBtn');
        if (mode === 'password') {
            focusTarget = document.getElementById('passwordInput');
        } else if (mode === 'socks-proxy-password') {
            focusTarget = document.getElementById('socksProxyPasswordInput');
        } else if (mode === 'jump-host-password') {
            focusTarget = document.getElementById('jumpHostPasswordInput');
        }
        window.requestAnimationFrame(() => focusTarget?.focus());
        if (['password', 'jump-host-password', 'socks-proxy-password'].includes(mode)) connectWithAssignedPasswords(profileId);
    }

    /**
     * A saved host whose every password (target and jump host) has an assigned
     * saved password connects without waiting for a click in the form. It goes
     * through the normal form submission, so all checks there still apply.
     */
    async function connectWithAssignedPasswords(profileId) {
        const picker = window.CredentialPicker;
        const profile = ProfileManager.profiles.find(item => item.id === profileId);
        if (!picker?.restore || !profile) return;
        const jump = profile.jump_host_id ? window.JumpHostManager?.getById(profile.jump_host_id) : null;
        const needsTarget = profile.auth_type === 'password';
        const needsJump = jump?.auth_type === 'password';
        const needsSocks = window.SocksProxyManager?.getById(profile.socks_proxy_id)?.auth_type === 'password';
        if (!needsTarget && !needsJump && !needsSocks) return;
        try {
            await Promise.all([
                needsTarget ? picker.restore('passwordInput') : null,
                needsJump ? picker.restore('jumpHostPasswordInput') : null,
                needsSocks ? picker.restore('socksProxyPasswordInput') : null,
            ]);
        } catch {
            return;
        }
        const modal = document.getElementById('connectionModal');
        if (!modal?.classList.contains('show') || ProfileManager.selectedProfileId !== profileId) return;
        const targetReady = !needsTarget || (document.getElementById('authTypeSelect')?.value === 'saved-password'
            && Boolean(document.getElementById('savedPasswordSelect')?.value));
        const jumpReady = !needsJump || Boolean(picker.get('jumpHostPasswordInput'));
        const socksReady = !needsSocks || Boolean(picker.get('socksProxyPasswordInput'));
        if (targetReady && jumpReady && socksReady) document.getElementById('connectionForm')?.requestSubmit();
    }

    function clearPendingPane() {
        pendingPaneIndex = null;
    }

    function stopConnectTimer() {
        if (connectTimer) {
            clearInterval(connectTimer);
            connectTimer = null;
        }
        const connectLabel = document.querySelector('#connectBtn .btn-label');
        if (connectLabel) {
            connectLabel.textContent = window.i18n
                ? i18n.t('connection.connect')
                : 'Connect';
        }
    }

    function finishConnectionCancellation(requestId) {
        window.SSHGatewayDialog?.close(requestId);
        pendingReconnectSessionMap.delete(requestId);
        rememberTransientId(cancelledConnectRequestIds, requestId);
        closeAuthBannerPrompt(requestId);
        pendingRequestPaneMap.delete(requestId);
        SessionManager.clearPendingConnection(requestId);
        if (requestId === currentConnectRequestId) {
            currentConnectRequestId = null;
            setConnectLoading(false);
            stopConnectTimer();
        }
    }

    function setPendingCancellationBusy(requestId, busy) {
        const button = document.getElementById(`pending-${requestId}`)
            ?.querySelector('.tab-close');
        if (!button) return;
        button.setAttribute('aria-disabled', String(Boolean(busy)));
        button.setAttribute('aria-busy', String(Boolean(busy)));
    }

    function cancelConnectionAttempt(
        requestId = currentConnectRequestId,
        onSettled = null,
    ) {
        if (
            !requestId
            || cancellingConnectRequestIds.has(requestId)
            || (
                requestId !== currentConnectRequestId
                && !pendingRequestPaneMap.has(requestId)
                && !window.SSHGatewayDialog?.has(requestId)
            )
        ) {
            return false;
        }
        cancellingConnectRequestIds.add(requestId);
        setPendingCancellationBusy(requestId, true);
        let settled = false;
        const settleCancellation = acknowledgement => {
            if (settled) return;
            settled = true;
            window.clearTimeout(acknowledgementTimer);
            cancellingConnectRequestIds.delete(requestId);
            setPendingCancellationBusy(requestId, false);
            const requestStillPending = (
                requestId === currentConnectRequestId
                || pendingRequestPaneMap.has(requestId)
                || window.SSHGatewayDialog?.has(requestId)
            );
            const completedWhileCancelling = (
                completedWhileCancellingRequestIds.delete(requestId)
            );
            let cancelled = acknowledgement?.cancelled === true || (
                acknowledgement?.success === true
                && acknowledgement?.cancelled !== false
            );
            if (cancelled) {
                finishConnectionCancellation(requestId);
            } else if (completedWhileCancelling) {
                // The commit won and the success event was already handled.
                // Keep the usable connection and make the rejected
                // cancellation explicit instead of silently ignoring it.
                showNotification(
                    window.i18n
                        ? i18n.t('connection.cancelCompleted')
                        : 'Cancellation was too late. The connection had already opened and remains active.',
                    'info',
                );
            } else if (
                acknowledgement?.reason === 'not_found'
                && requestStillPending
            ) {
                // The server no longer owns this request. Honour the user's
                // cancellation locally and discard any success that was
                // already in flight for the same correlated request.
                cancelled = true;
                finishConnectionCancellation(requestId);
                showNotification(
                    window.i18n
                        ? i18n.t('connection.cancelAlreadyStopped')
                        : 'The connection attempt is no longer active.',
                    'info',
                );
            } else if (
                acknowledgement?.reason === 'already_committed'
                && requestStillPending
            ) {
                showNotification(
                    window.i18n
                        ? i18n.t('connection.cancelTooLate')
                        : 'The connection is already finishing and can no longer be cancelled safely.',
                    'info',
                );
            } else if (requestStillPending) {
                showNotification(
                    window.i18n
                        ? i18n.t('connection.cancelUnconfirmed')
                        : 'Cancellation was not confirmed. The attempt is still pending; try cancelling again.',
                    'warning',
                    7000,
                );
            }
            if (typeof onSettled === 'function') {
                onSettled(cancelled, acknowledgement);
            }
        };
        const acknowledgementTimer = window.setTimeout(() => {
            settleCancellation({
                success: false,
                cancelled: false,
                reason: 'ack_timeout',
            });
        }, CONNECT_CANCEL_ACK_TIMEOUT_MS);
        socket.emit(
            'ssh_connect_cancel',
            { client_request_id: requestId },
            settleCancellation,
        );
        return true;
    }

    function dismissConnectionModal() {
        SessionManager.pendingReconnectSessionId = null;
        SessionManager.pendingReconnectTmux = null;
        SessionManager.pendingReconnectHerdr = false;
        SessionManager.pendingDisplayName = null;
        const modalRequestId = connectionModalRequestId;
        const targetPane = pendingPaneIndex;
        const shouldReactivatePane = Number.isInteger(targetPane)
            && Boolean(SessionManager.getWorkspaceSession?.())
            && !SessionManager.getActiveSession();
        const reactivatePreservedPane = () => {
            if (!shouldReactivatePane) return;
            SessionManager.setActivePane(targetPane);
            window.requestAnimationFrame(() => SessionManager.focusActivePane());
        };
        cancelConnectionAttempt(modalRequestId);
        connectionModalRequestId = null;
        window.ModalManager.close(document.getElementById('connectionModal'));
        clearPendingPane();
        if (!modalRequestId) {
            setConnectLoading(false);
            stopConnectTimer();
        }
        // The replacement remains staged until ssh_connected, so returning to
        // the preserved session is safe even while cancellation is pending or
        // the server has already crossed its commit boundary.
        reactivatePreservedPane();
    }

    function getDefaultPaneIndex() {
        if (SessionManager.windowMode) {
            // Without an empty window to fill, the connection opens a new one.
            return SessionManager.getLauncherPaneIndex();
        }
        const activeIndex = SessionManager.getActivePaneIndex();
        const activeSession = SessionManager.getActiveSession();
        if (!activeSession && activeIndex !== null && activeIndex !== undefined) {
            return activeIndex;
        }
        const emptyIndex = SessionManager.getFirstEmptyPaneIndex();
        if (emptyIndex !== -1) {
            return emptyIndex;
        }
        return activeIndex !== null && activeIndex !== undefined ? activeIndex : 0;
    }

    function openDefaultConnectionModal() {
        return openConnectionModalForPane(getDefaultPaneIndex());
    }
    window.openDefaultConnectionModal = openDefaultConnectionModal;

    const savedConnectionLauncher = (
        ConnectionLauncher.createConnectionLauncher({
            getProfile: profileId => ProfileManager.getProfile(profileId),
            getContext: () => ({
                keys: ProfileManager.keys,
                jumpHosts: window.JumpHostManager?.jumpHosts || [],
                socksProxies: window.SocksProxyManager?.socksProxies || [],
            }),
            getDefaultPaneIndex,
            isBusy: () => Boolean(currentConnectRequestId),
            startConnection,
            openReview: openProfileForReview,
            notify: (key, fallback, type) => {
                const translated = window.i18n ? i18n.t(key) : key;
                showNotification(
                    translated && translated !== key ? translated : fallback,
                    type,
                );
            },
            refreshProfiles: () => ProfileManager.loadProfiles(),
        })
    );
    window.launchProfileForPane = (profileId, paneIndex = null) => (
        savedConnectionLauncher.launch(profileId, paneIndex)
    );

    window.openConnectionModalForPane = openConnectionModalForPane;

    function setConnectLoading(isLoading) {
        const connectBtn = document.getElementById('connectBtn');
        const spinner = document.getElementById('connectSpinner');
        if (!connectBtn) return;
        connectBtn.disabled = isLoading;
        spinner?.classList.toggle('hidden', !isLoading);
    }

    function setFieldState(input, hintEl, message, isValid) {
        if (!input || !hintEl) {
            return;
        }
        input.classList.toggle('is-valid', Boolean(isValid));
        input.classList.toggle('is-invalid', isValid === false);
        if (isValid === false) input.setAttribute('aria-invalid', 'true');
        else input.removeAttribute('aria-invalid');
        hintEl.textContent = message || '';
        hintEl.classList.toggle('hint-error', isValid === false);
        hintEl.classList.toggle('hint-success', isValid === true);
    }

    function setupConnectionValidation() {
        const hostInput = document.getElementById('hostInput');
        const portInput = document.getElementById('portInput');
        const userInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const keySelect = document.getElementById('keySelect');
        const profileNameInput = document.getElementById('profileNameInput');
        const authTypeSelect = document.getElementById('authTypeSelect');

        if (!hostInput || !portInput || !userInput) {
            return;
        }

        const hostHint = document.getElementById('hostHint');
        const portHint = document.getElementById('portHint');
        const userHint = document.getElementById('usernameHint');
        const passHint = document.getElementById('passwordHint');
        const keyHint = document.getElementById('keyHint');
        const profileHint = document.getElementById('profileHint');

        const validation = window.ConnectionValidation;
        const hint = (input, element, valid, key) => {
            setFieldState(input, element, valid ? '' : i18n.t(key), valid);
        };
        const validateHost = () => hint(hostInput, hostHint,
            validation.isValidHost(hostInput.value), 'validation.host');
        const validatePort = () => hint(portInput, portHint,
            validation.isValidPort(portInput.value), 'validation.port');
        const validatePassword = () => {
            if (!passwordInput) return;
            const passwordAuth = authTypeSelect?.value === 'password';
            const gateway = passwordAuth && validation.isGateway(userInput.value);
            const valid = !passwordAuth || gateway || Boolean(window.CredentialPicker?.get('passwordInput')) || passwordInput.value.length > 0;
            setFieldState(passwordInput, passHint,
                valid ? '' : i18n.t('connection.passwordRequired'), passwordAuth ? valid : null);
            if (passHint && gateway && !passwordInput.value) {
                passHint.textContent = i18n.t('gateway.passwordHint', 'Leave the password empty for interactive gateway authentication.');
            }
        };
        let gatewayPasswordMode = false;
        const validateUser = () => {
            hint(userInput, userHint,
                validation.isValidUsername(userInput.value, authTypeSelect?.value !== 'tailscale'), 'validation.username');
            const gateway = validation.isGateway(userInput.value);
            if (gateway || gatewayPasswordMode) {
                if (passwordInput) passwordInput.required = authTypeSelect?.value === 'password' && !gateway && !window.CredentialPicker?.get('passwordInput');
                validatePassword();
            }
            gatewayPasswordMode = gateway;
        };
        hostInput.addEventListener('input', validateHost);
        portInput.addEventListener('input', validatePort);
        userInput.addEventListener('input', validateUser);
        window.addEventListener('languageChanged', () => {
            if (hostHint.textContent) validateHost();
            if (portHint.textContent) validatePort();
            if (userHint.textContent) validateUser();
            if (passHint?.textContent) validatePassword();
        });

        if (passwordInput) {
            passwordInput.addEventListener('input', validatePassword);
        }

        if (keySelect) {
            keySelect.addEventListener('change', () => {
                const value = keySelect.value;
                setFieldState(keySelect, keyHint, value ? '' : i18n.t('connection.selectSSHKey'), Boolean(value));
                refreshConnectionProfileKeyResolution();
            });
        }

        if (profileNameInput) {
            profileNameInput.addEventListener('input', () => {
                const value = profileNameInput.value.trim();
                setFieldState(profileNameInput, profileHint, '', value ? true : null);
            });
        }

        if (authTypeSelect) {
            authTypeSelect.addEventListener('change', () => {
                if (validation.isGateway(userInput.value)) validateUser();
                if (authTypeSelect.value === 'password' && passwordInput) validatePassword();
                if (authTypeSelect.value === 'key' && keySelect) {
                    setFieldState(keySelect, keyHint, keySelect.value ? '' : i18n.t('connection.selectSSHKey'), Boolean(keySelect.value));
                }
                refreshConnectionProfileKeyResolution();
            });
        }
    }

    function setupPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach(button => {
            button.addEventListener('click', () => {
                const targetId = button.dataset.target;
                const input = document.getElementById(targetId);
                if (!input) {
                    return;
                }
                const isHidden = input.getAttribute('type') === 'password';
                input.setAttribute('type', isHidden ? 'text' : 'password');
                button.classList.toggle('active', isHidden);
            });
        });
    }

    function copyActiveTerminalSelection() {
        const active = SessionManager.getActiveSession();
        const terminal = SessionManager.getActiveTerminal();
        if (!active || !terminal) {
            showNotification((window.i18n ? window.i18n.t('toast.noActiveSession') : 'No active session'), 'warning');
            return;
        }
        if (!terminal.hasSelection()) {
            showNotification((window.i18n ? window.i18n.t('toast.nothingSelected') : 'Nothing selected to copy'), 'info');
            return;
        }
        TerminalManager.copySelectionToClipboard(terminal)
            .then(copied => {
                showNotification(
                    copied ? 'Selection copied' : 'Nothing selected to copy',
                    copied ? 'success' : 'info',
                );
            })
            .catch(() => showNotification((window.i18n ? window.i18n.t('toast.clipboardDenied') : 'Clipboard access denied'), 'error'));
    }

    function pasteClipboardIntoActiveTerminal() {
        const active = SessionManager.getActiveSession();
        if (!active) {
            showNotification((window.i18n ? window.i18n.t('toast.noActiveSession') : 'No active session'), 'warning');
            return;
        }
        if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
            showNotification((window.i18n ? window.i18n.t('toast.clipboardDenied') : 'Clipboard access denied'), 'error');
            return;
        }
        const binding = window.TerminalPasteGuard?.capture(active, TerminalManager.terminals[active]);
        let clipboardText;
        try {
            clipboardText = navigator.clipboard.readText();
        } catch {
            showNotification((window.i18n ? window.i18n.t('toast.clipboardDenied') : 'Clipboard access denied'), 'error');
            return;
        }
        Promise.resolve(clipboardText)
            .then(text => {
                if (text) return window.TerminalPasteGuard?.paste(binding, text);
            })
            .catch(() => showNotification((window.i18n ? window.i18n.t('toast.clipboardDenied') : 'Clipboard access denied'), 'error'));
    }

    function setupClipboardActions() {
        const saveBtn = document.getElementById('saveTranscriptBtn');

        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                const active = SessionManager.getActiveSession();
                if (!active) {
                    showNotification((window.i18n ? window.i18n.t('toast.noActiveSession') : 'No active session'), 'warning');
                    return;
                }
                const transcript = TerminalManager.getCleanTranscript(active);
                if (!transcript) {
                    showNotification((window.i18n ? window.i18n.t('toast.transcriptEmpty') : 'Transcript is empty'), 'info');
                    return;
                }
                const blob = new Blob([transcript], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `session-${active}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification((window.i18n ? window.i18n.t('toast.transcriptSaved') : 'Transcript saved'), 'success');
            });
        }

        const mobileInput = document.getElementById('mobileInput');
        const mobileSendBtn = document.getElementById('mobileSendBtn');

        let mobileSendPending = false;
        const sendMobileInput = async () => {
            const active = SessionManager.getActiveSession();
            if (mobileSendPending || !active || !mobileInput.value) return;
            const submitted = mobileInput.value;
            mobileSendPending = true;
            try {
                let sent = false;
                if (window.socket?.connected === true) {
                    const binding = window.TerminalPasteGuard?.capture(active);
                    sent = await window.TerminalPasteGuard?.review(binding, submitted,
                        value => window.SSHInput?.sendText(active, value + '\r'));
                }
                if (sent && mobileInput.value === submitted) mobileInput.value = '';
            } finally {
                mobileSendPending = false;
            }
        };

        if (mobileInput) {
            // Input[type=text] strips line breaks. Review the original clipboard
            // before the browser can silently turn several commands into one.
            mobileInput.addEventListener('paste', event => {
                const text = event.clipboardData?.getData('text/plain') || '';
                if (!window.TerminalPasteGuard?.needsReview(text)) return;
                event.preventDefault();
                const active = SessionManager.getActiveSession();
                const binding = window.TerminalPasteGuard.capture(active, TerminalManager.terminals[active]);
                window.TerminalPasteGuard.paste(binding, text);
            });
            mobileInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    sendMobileInput();
                }
            });
        }

        if (mobileSendBtn) {
            mobileSendBtn.addEventListener('click', sendMobileInput);
        }

    }

    function setupSplitControls() {
        const picker = document.getElementById('workspaceLayoutPicker');
        const closePicker = () => { if (picker) picker.open = false; };
        document.addEventListener('click', event => {
            if (picker?.open && !picker.contains(event.target)) closePicker();
        });
        picker?.addEventListener('keydown', event => {
            if (event.key === 'Escape') {
                closePicker();
                picker.querySelector('summary')?.focus();
                event.stopPropagation();
            }
        });
        document.querySelectorAll('.split-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                closePicker();
                if (btn.dataset.layout === 'windows') {
                    SessionManager.setWindowMode(true);
                    return;
                }
                const layout = parseInt(btn.dataset.layout, 10);
                const currentLayout = SessionManager.layout;
                // A user's split choice overrides a remembered window mode,
                // including while compact-screen fallback is active.
                SessionManager.setWindowModePreference(false);

                // Leaving windows keeps the front-most sessions in the panes.
                if (!SessionManager.windowMode
                        && layout !== currentLayout && SessionManager.hasAnySessions()) {
                    SessionManager.showPaneAssignmentModal(layout);
                } else {
                    SessionManager.setSplitLayout(layout);
                }
            });
        });
        document.querySelectorAll('[data-window-arrange]').forEach(btn => {
            btn.addEventListener('click', () => {
                SessionManager.arrangeWindows(btn.dataset.windowArrange);
                closePicker();
            });
        });
    }

    function setupNotepad() {
        const notepad = document.getElementById('sessionNotepad');
        const status = document.getElementById('notepadSaveStatus');
        const retry = document.getElementById('notepadRetryBtn');
        if (!notepad || !window.NotepadController) return;
        window.notepadController = window.NotepadController.create({
            socket: window.socket,
            read: () => notepad.value,
            write: value => { notepad.value = value; },
            status: state => {
                if (retry) retry.hidden = state !== 'failed';
                if (!status) return;
                status.textContent = window.i18n.t(`notes.${state}`);
                status.className = `notepad-save-status ${state}`;
                status.setAttribute('role', state === 'failed' ? 'alert' : 'status');
            },
        });
        retry?.addEventListener('click', () => {
            window.notepadController.retry();
            notepad.focus({preventScroll: true});
        });
        notepad.addEventListener('input', () => window.notepadController.changed());
        notepad.addEventListener('focus', () => {
            if (document.body.classList.contains('keyboard-open')) {
                document.body.classList.add('notepad-focused');
            }
        });
        notepad.addEventListener('blur', () => document.body.classList.remove('notepad-focused'));
        window.addEventListener('languageChanged', () => window.notepadController.render());
    }

    function setupShortcutsModal() {
        const modal = document.getElementById('shortcutsModal');
        const list = document.getElementById('shortcutsList');
        const shortcuts = [
            { keys: 'F1', labelKey: 'shortcuts.openCommandLibrary' },
            { keys: 'Ctrl+K', labelKey: 'shortcuts.openCommandPalette' },
            { keys: 'Ctrl+?', labelKey: 'shortcuts.showShortcuts' },
            { keys: 'Ctrl+Shift+N', labelKey: 'shortcuts.newConnection' },
            { keys: 'Ctrl+F', labelKey: 'shortcuts.searchTerminal' },
            { keys: 'Ctrl/Cmd+C', labelKey: 'shortcuts.copyTerminal' },
            { keys: 'Ctrl/Cmd+V', labelKey: 'shortcuts.pasteTerminal' },
            { keys: 'Ctrl+1-9', labelKey: 'shortcuts.switchTab' },
            { keys: 'Ctrl+Tab', labelKey: 'shortcuts.nextTab' },
            { keys: 'Ctrl+Shift+Tab', labelKey: 'shortcuts.previousTab' },
            { keys: 'F2', labelKey: 'shortcuts.renameFile' },
            { keys: 'F5', labelKey: 'shortcuts.transferFile' },
            { keys: 'F7', labelKey: 'shortcuts.newFolder' },
            { keys: 'Delete', labelKey: 'shortcuts.deleteSelected' },
            { keys: 'Tab', labelKey: 'shortcuts.switchPane' },
            { keys: 'Ctrl+A', labelKey: 'shortcuts.selectAll' },
            { keys: 'Esc', labelKey: 'shortcuts.closeModals' }
        ];
        if (!list) {
            return;
        }

        const renderShortcuts = () => {
            list.innerHTML = '';
            shortcuts.forEach(shortcut => {
                const row = document.createElement('div');
                row.className = 'shortcut-row';
                const label = window.i18n ? i18n.t(shortcut.labelKey) : shortcut.labelKey;
                row.innerHTML = `<strong>${window.escapeHtml(shortcut.keys)}</strong>`
                    + `<span>${window.escapeHtml(label)}</span>`;
                list.appendChild(row);
            });
        };
        renderShortcuts();
        window.addEventListener('languageChanged', renderShortcuts);

        const closeBtn = document.getElementById('closeShortcutsModal');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                window.ModalManager.close(modal);
            });
        }

        return modal;
    }

    function setupCommandPalette() {
        const modal = document.getElementById('commandPaletteModal');
        const input = document.getElementById('commandPaletteInput');
        const list = document.getElementById('commandPaletteList');
        if (!modal || !input || !list) {
            return null;
        }

        // Views first: the palette also works as a way to move between the main areas.
        const navButton = id => {
            const button = document.getElementById(id);
            return button && !button.hidden && !button.disabled && button.getClientRects().length ? button : null;
        };
        const actions = [
            { id: 'view-overview', labelKey: 'overview.title', hint: '', available: () => navButton('overviewNavBtn'), action: () => navButton('overviewNavBtn')?.click() },
            { id: 'view-workspaces', labelKey: 'navigation.workspaces', hint: '', available: () => navButton('workspaceNavBtn'), action: () => navButton('workspaceNavBtn')?.click() },
            { id: 'view-hosts', labelKey: 'connectionAssets.hosts', hint: '', available: () => document.getElementById('manageProfilesBtn'), action: () => document.getElementById('manageProfilesBtn')?.click() },
            { id: 'view-automation', labelKey: 'automation.title', hint: '', available: () => navButton('automationNavBtn'), action: () => navButton('automationNavBtn')?.click() },
            { id: 'view-settings', labelKey: 'settings.title', hint: '', action: () => { window.location.href = APP_ROOT + '/settings'; } },
            { id: 'quick-connect', labelKey: 'connection.newConnection', hint: 'Ctrl+Shift+N', action: openDefaultConnectionModal },
            { id: 'command-library', labelKey: 'commands.library', hint: 'F1', action: () => CommandLibrary.openLibrary() },
            { id: 'file-transfer', labelKey: 'files.fileTransfer', hint: '', action: () => document.getElementById('fileTransferBtn').click() },
            { id: 'manage-keys', labelKey: 'keys.manageKeys', hint: '', action: () => openConnectionAssetManager('keys') },
            { id: 'change-password', labelKey: 'auth.changePassword', hint: '', action: () => { window.location.href = APP_ROOT + '/security#password'; } },
            { id: 'save-transcript', labelKey: 'terminal.saveTranscript', hint: '', action: () => document.getElementById('saveTranscriptBtn').click() },
            { id: 'copy-selection', labelKey: 'terminal.copySelection', hint: '', action: copyActiveTerminalSelection },
            { id: 'paste-clipboard', labelKey: 'terminal.pasteClipboard', hint: '', action: pasteClipboardIntoActiveTerminal },
            { id: 'keyboard-shortcuts', labelKey: 'shortcuts.title', hint: 'Ctrl+?', action: () => openShortcuts() },
            // Herdr actions appear only while the active session runs Herdr.
            {
                id: 'herdr-toggle-bar',
                labelKey: 'herdr.barToggle',
                fallback: 'Show or hide the Herdr controls',
                descriptionKey: 'herdr.barLabel',
                hint: '',
                available: () => window.herdrControlBar?.available() === true,
                action: () => window.herdrControlBar?.toggle(),
            },
            ...(window.HerdrControlBar?.ACTIONS || []).map(herdrAction => ({
                id: `herdr-${herdrAction.id}`,
                labelKey: herdrAction.labelKey,
                fallback: herdrAction.title,
                descriptionKey: 'herdr.barLabel',
                hint: herdrAction.id === 'prefix' ? herdrAction.hint : `Ctrl+B ${herdrAction.hint}`,
                available: () => window.herdrControlBar?.available() === true,
                action: () => window.herdrControlBar?.run(herdrAction.id),
            }))
        ];
        const actionMap = new Map(actions.map(action => [action.id, action.action]));

        let filtered = [];
        let activeIndex = 0;

        function translate(key, fallback) {
            return window.i18n ? i18n.t(key) : fallback;
        }

        function buildItems() {
            const translatedActions = actions.filter(action => !action.available || action.available()).map(action => ({
                id: action.id,
                label: translate(action.labelKey, action.fallback || action.labelKey),
                description: action.descriptionKey ? translate(action.descriptionKey, 'Herdr') : '',
                hint: action.hint,
            }));
            return CommandPaletteUtils.buildItems({
                actions: translatedActions,
                profiles: Array.isArray(ProfileManager.profiles)
                    ? ProfileManager.profiles
                    : [],
                sessions: SessionManager.getAllSessions(),
                query: input.value,
                formatEndpoint: item => ProfileLauncherUtils.formatEndpoint(item),
                sessionLabel: session => SessionManager.getDisplayLabel(
                    session.id,
                    session.username,
                    session.host,
                ),
                labels: {
                    activeSession: translate('palette.activeSession', 'Active session'),
                    savedHost: translate('palette.savedHost', 'Saved host'),
                },
                limit: 50,
            });
        }

        function closePalette() {
            window.ModalManager.close(modal);
        }

        function activateItem(item) {
            if (!item) return;
            if (item.kind === 'action') {
                const action = actionMap.get(item.id);
                if (!action) return;
                closePalette();
                action();
                return;
            }
            if (
                item.kind === 'profile'
                && ProfileManager.profiles.some(profile => profile.id === item.id)
                && typeof window.launchProfileForPane === 'function'
            ) {
                closePalette();
                window.launchProfileForPane(item.id);
                return;
            }
            if (
                item.kind === 'session'
                && Object.prototype.hasOwnProperty.call(SessionManager.sessions, item.id)
                && SessionManager.sessions[item.id]
                && typeof SessionManager.switchSession === 'function'
            ) {
                closePalette();
                window.primaryWorkspaceController?.showWorkspaces();
                SessionManager.switchSession(item.id);
            }
        }

        function updateSelection(reveal = false) {
            const options = list.querySelectorAll('.palette-item');
            options.forEach((option, index) => {
                option.classList.toggle('active', index === activeIndex);
                option.setAttribute('aria-selected', String(index === activeIndex));
            });
            const active = options[activeIndex];
            if (active) {
                input.setAttribute('aria-activedescendant', active.id);
                if (reveal) active.scrollIntoView({block: 'nearest', inline: 'nearest'});
            } else input.removeAttribute('aria-activedescendant');
        }

        function render({resetSelection = false} = {}) {
            const selected = resetSelection ? null : filtered[activeIndex];
            const hadResultFocus = list.contains(document.activeElement);
            filtered = buildItems();
            const retainedIndex = selected ? filtered.findIndex(item => item.kind === selected.kind && item.id === selected.id) : -1;
            activeIndex = resetSelection ? 0 : selected ? retainedIndex : activeIndex < 0 ? -1 : 0;
            list.replaceChildren();
            input.removeAttribute('aria-activedescendant');
            if (filtered.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'palette-empty';
                empty.textContent = translate('palette.noMatches', 'No matches');
                empty.setAttribute('role', 'status');
                list.appendChild(empty);
                if (hadResultFocus) input.focus();
                return;
            }
            let previousKind = null;
            const showSections = input.value.trim() === '';
            filtered.forEach((item, index) => {
                if (showSections && item.kind !== previousKind) {
                    const section = document.createElement('div');
                    section.className = 'palette-section-title';
                    section.textContent = translate(
                        `palette.${item.kind === 'profile' ? 'hosts' : `${item.kind}s`}`,
                        item.kind,
                    );
                    list.appendChild(section);
                    previousKind = item.kind;
                }
                const el = document.createElement('button');
                el.type = 'button';
                el.id = `command-palette-option-${index}`;
                el.className = 'palette-item' + (index === activeIndex ? ' active' : '');
                el.dataset.paletteKind = item.kind;
                el.dataset.paletteId = item.id;
                el.setAttribute('role', 'option');
                el.setAttribute('aria-selected', index === activeIndex ? 'true' : 'false');

                const copy = document.createElement('span');
                copy.className = 'palette-item-copy';
                const label = document.createElement('span');
                label.className = 'palette-item-label';
                label.textContent = item.label;
                const description = document.createElement('span');
                description.className = 'palette-item-description';
                description.textContent = item.description;
                copy.append(label, description);

                const hint = document.createElement('span');
                hint.className = 'palette-item-hint';
                hint.textContent = item.hint;
                el.append(copy, hint);
                el.addEventListener('click', () => activateItem(item));
                el.addEventListener('focus', () => {
                    activeIndex = index;
                    updateSelection();
                });
                list.appendChild(el);
            });
            updateSelection(modal.classList.contains('show'));
            if (hadResultFocus) (list.querySelector('.palette-item.active') || input).focus({preventScroll: true});
        }

        function openPalette() {
            input.value = '';
            activeIndex = 0;
            render({resetSelection: true});
            window.ModalManager.open(modal);
            list.scrollTop = 0;
            setTimeout(() => input.focus(), 50);
        }

        input.addEventListener('input', () => {
            activeIndex = 0;
            render({resetSelection: true});
        });

        window.addEventListener('languageChanged', render);
        window.addEventListener('profile-list-change', () => {
            if (modal.classList.contains('show')) render();
        });
        window.addEventListener('session-workspace-change', () => {
            if (modal.classList.contains('show')) render();
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                activeIndex = filtered.length > 0
                    ? Math.min(activeIndex + 1, filtered.length - 1)
                    : 0;
                updateSelection(true);
                e.preventDefault();
            } else if (e.key === 'ArrowUp') {
                activeIndex = Math.max(activeIndex - 1, 0);
                updateSelection(true);
                e.preventDefault();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                activateItem(filtered[activeIndex]);
            } else if (e.key === 'Escape') {
                e.preventDefault();
                closePalette();
            }
        });

        document.getElementById('closeCommandPaletteModal').addEventListener('click', () => closePalette());
        return openPalette;
    }

    let openShortcuts = null;
    let shortcutsModal = null;
    let openPalette = null;

    document.addEventListener('DOMContentLoaded', () => {
        const reconnectBar = document.createElement('div');
        reconnectBar.id = 'reconnectBar';
        reconnectBar.className = 'reconnect-bar';
        reconnectBar.style.display = 'none';
        const reconnectText = document.createElement('span');
        reconnectText.className = 'reconnect-text';
        reconnectText.textContent = window.i18n
            ? i18n.t('connection.lostReconnecting')
            : 'Connection lost. Reconnecting...';
        reconnectBar.appendChild(reconnectText);
        const header = document.querySelector('.header');
        if (header) {
            header.after(reconnectBar);
        }

        window.primaryWorkspaceController = window.PrimaryWorkspaceController
            ?.createController({window, document});
        window.primaryWorkspaceController?.init();
        const restoreNativeRoute = () => {
            if (location.hash === '#passwords') openConnectionAssetManager('passwords');
            if (location.hash === '#automation') { window.primaryWorkspaceController?.open('automation', document.getElementById('automationNativeView')); window.WebSSHAutomation?.activate(); }
        };
        window.addEventListener('hashchange', restoreNativeRoute);
        restoreNativeRoute();

        SessionManager.init();
        window.mobileAppShell = window.MobileAppShell?.createController({
            window,
            document,
            sessionManager: SessionManager,
            terminalManager: TerminalManager,
        });
        window.mobileAppShell?.init();
        window.workspaceLayoutController = window.WorkspaceLayoutController?.createController({
            window,
            document,
            socket: window.socket,
            terminalManager: TerminalManager,
            sessionManager: SessionManager,
        });
        window.workspaceLayoutController?.init();

        CommandWorkspace.init();
        CommandLibrary.init();
        window.CommandSetManager?.init();
        window.ConnectionCommandManager?.init();
        window.SessionCommandLauncher?.init();
        window.HostContext?.init();
        ProfileManager.init();

        // The dashboard owns the Overview page when its markup is present; the
        // established controller keeps the host rail and navigation labels.
        window.overviewWorkspace = window.OverviewWorkspace?.createController({
            window, document, sessionManager: SessionManager,
        }) || null;
        window.connectionOverview = window.ConnectionOverview?.createController({
            window, document, sessionManager: SessionManager, overviewPage: !window.overviewWorkspace,
        });
        window.connectionOverview?.init();
        window.overviewWorkspace?.init();
        window.hostDiscovery = window.HostDiscovery?.create({
            win: window, doc: document,
            t: (key, fallback, values = {}) => {
                let text = window.i18n?.t(key);
                if (!text || text === key) text = fallback;
                return Object.entries(values).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)), text);
            },
            request: async (path, options = {}) => {
                const appRoot = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
                const response = await fetch(appRoot + path, {credentials: 'same-origin', cache: 'no-store', ...options,
                    headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''}});
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.error || 'The request failed.');
                return data;
            },
            openEditor: (values, {saved, closed} = {}) => {
                if (!window.primaryWorkspaceController?.open('hosts', document.getElementById('profileManagementModal'))) return;
                ProfileManager.openEditor(null, {prefill: values, returnAfterSave: saved, returnAfterClose: closed});
            },
        }) || null;
        document.querySelectorAll('[data-host-discovery]').forEach(button => {
            button.hidden = !window.hostDiscovery;
            button.addEventListener('click', () => window.hostDiscovery?.open());
        });

        // The page carries the saved hosts, so the overview draws without waiting
        // for the socket; the socket lists are only needed when it could not.
        let inventory = null;
        try {
            inventory = JSON.parse(document.getElementById('initialInventory')?.textContent || 'null');
        } catch {
            inventory = null;
        }
        if (inventory) {
            window.JumpHostManager?.setJumpHosts(inventory.jump_hosts);
            window.SocksProxyManager?.setSocksProxies(inventory.socks_proxies);
            ProfileManager.setProfiles(inventory.profiles);
        } else {
            ProfileManager.loadProfiles();
            window.JumpHostManager?.load();
        }
        ProfileManager.loadKeys();

        const newTabBtn = document.getElementById('newTabBtn');
        if (newTabBtn) {
            newTabBtn.addEventListener('click', () => {
                const launcher = document.querySelector(
                    `.terminal-pane.active[data-pane-index="${SessionManager.getActivePaneIndex()}"] .profile-launcher-new`,
                );
                if (!SessionManager.windowMode && launcher) {
                    launcher.click();
                    return;
                }
                SessionManager.showConnectionLauncher(
                    SessionManager.getActivePaneIndex()
                );
            });
        }

        document.getElementById('closeConnectionModal').addEventListener('click', () => {
            dismissConnectionModal();
        });

        document.getElementById('cancelConnectionBtn').addEventListener('click', () => {
            dismissConnectionModal();
        });

        window.addEventListener('ssh-connection-cancel-requested', event => {
            cancelConnectionAttempt(event.detail?.requestId);
        });

        document.getElementById('connectionForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const host = document.getElementById('hostInput').value;
            const port = document.getElementById('portInput').value;
            const username = document.getElementById('usernameInput').value;
            const authMode = document.getElementById('authTypeSelect').value;
            const authType = authMode === 'saved-password' ? 'password' : authMode;
            const password = document.getElementById('passwordInput').value;
            let credentialId = window.CredentialPicker?.get('passwordInput');
            const keyId = document.getElementById('keySelect').value;
            const targetPane = pendingPaneIndex;

            if (!host || !username) {
                showNotification((window.i18n ? window.i18n.t('toast.hostUserRequired') : 'Host and username are required'), 'error');
                return;
            }

            if (authMode === 'saved-password') {
                if (e.currentTarget.dataset.credentialPending) return;
                const form = e.currentTarget; form.dataset.credentialPending = 'true';
                try { credentialId = await window.CredentialPicker.resolve('passwordInput'); }
                catch (error) { if (error.name !== 'AbortError') showNotification(error.message, 'error'); return; }
                finally { delete form.dataset.credentialPending; }
            }

            if (authType === 'password' && !password && !credentialId && !window.ConnectionValidation.isGateway(username)) {
                showNotification((window.i18n ? window.i18n.t('toast.passwordRequired') : 'Password is required'), 'error');
                document.getElementById('passwordInput').focus();
                return;
            }

            if (authType === 'key' && !keyId) {
                showNotification((window.i18n ? window.i18n.t('toast.keyRequired') : 'SSH key is required'), 'error');
                return;
            }

            if (authType === 'key' && ProfileManager.keysLoaded
                && !hasUsableConnectionKey(keyId)) {
                showNotification(
                    window.i18n?.t('connection.readinessKey', 'Key missing or unavailable')
                        || 'Key missing or unavailable',
                    'error',
                );
                document.getElementById('keySelect').focus();
                return;
            }

            if (refreshConnectionProfileJumpResolution()) {
                showNotification(
                    window.i18n?.t(
                        'connection.resolveJumpHost',
                        'Choose a jump host or confirm a direct connection.',
                    ) || 'Choose a jump host or confirm a direct connection.',
                    'error',
                );
                document.getElementById('connectionProfileDirectConfirm')?.focus();
                return;
            }

            const socksProxyId = document.getElementById('socksProxySelect')?.value || '';
            const requiredSocksProxyId = selectedConnectionProfileState?.requiredSocksProxyId;
            if ((requiredSocksProxyId && socksProxyId !== requiredSocksProxyId)
                || (selectedConnectionProfileState?.missingSocksProxy && !socksProxyId)) {
                showNotification(window.i18n?.t('connection.socksProxyMissing') || 'SOCKS5 proxy missing', 'error');
                return;
            }
            if ((socksProxyId && document.getElementById('jumpHostSelect').value)
                || (authType === 'tailscale' && (socksProxyId || document.getElementById('jumpHostSelect').value))) {
                showNotification(window.i18n?.t('connection.routeConflict') || 'Choose one compatible route.', 'error');
                return;
            }
            let socksProxy = null;
            if (socksProxyId) {
                const proxy = window.SocksProxyManager?.getById(socksProxyId);
                if (!proxy) { showNotification(window.i18n?.t('connection.socksProxyMissing') || 'SOCKS5 proxy missing', 'error'); return; }
                socksProxy = {socks_proxy_id: socksProxyId};
                if (proxy.auth_type === 'password') {
                    const password = document.getElementById('socksProxyPasswordInput').value;
                    const credential = window.CredentialPicker?.get('socksProxyPasswordInput');
                    if (!password && !credential) {
                        showNotification(window.i18n?.t('connection.socksProxyPasswordRequired') || 'SOCKS5 proxy password is required', 'error');
                        document.getElementById('socksProxyPasswordInput').focus();
                        return;
                    }
                    if (credential) {
                        socksProxy.credential_id = credential;
                        const token = window.CredentialPicker?.token?.('socksProxyPasswordInput');
                        if (token) socksProxy.credential_target_token = token;
                    } else socksProxy.password = password;
                }
            }

            // Optional jump host (bastion) — chosen from the saved list
            const jumpHostId = document.getElementById('jumpHostSelect').value;
            let proxyJump = null;
            if (jumpHostId) {
                const jh = window.JumpHostManager ? window.JumpHostManager.getById(jumpHostId) : null;
                if (!jh) {
                    showNotification((window.i18n ? window.i18n.t('toast.jumpNotFound') : 'Selected jump host not found'), 'error');
                    return;
                }
                proxyJump = {
                    jump_host_id: jumpHostId,
                    host: jh.host,
                    port: jh.port,
                    username: jh.username,
                    auth_type: jh.auth_type
                };
                if (jh.auth_type === 'password') {
                    const jhPass = document.getElementById('jumpHostPasswordInput').value;
                    const jumpCredentialId = window.CredentialPicker?.get('jumpHostPasswordInput');
                    if (!jhPass && !jumpCredentialId) {
                        showNotification((window.i18n ? window.i18n.t('toast.jumpPasswordRequired') : 'Jump host password is required'), 'error');
                        document.getElementById('jumpHostPasswordInput').focus();
                        return;
                    }
                    if (jumpCredentialId) proxyJump.credential_id = jumpCredentialId;
                    else proxyJump.password = jhPass;
                } else {
                    proxyJump.key_id = jh.key_id;
                }
            }

            const connectionData = {
                host: host,
                port: parseInt(port),
                username: username,
                auth_type: authType
            };
            Object.assign(connectionData, ConnectionCommandManager.getPayload());

            if (authType === 'password') {
                if (credentialId) { connectionData.credential_id = credentialId;
                    const targetToken = window.CredentialPicker?.token?.('passwordInput');
                    if (targetToken) connectionData.credential_target_token = targetToken;
                }
                else connectionData.password = password;
            } else if (authType === 'key') {
                connectionData.key_id = keyId;
            }

            if (proxyJump) {
                connectionData.proxy_jump = proxyJump;
            }
            if (socksProxy) connectionData.socks_proxy = socksProxy;
            const contextProfileId = SessionManager.pendingReconnectProfileId
                || window.ProfileManager?.connectionProfileId?.(connectionData);
            if (contextProfileId) connectionData.profile_id = contextProfileId;
            if (SessionManager.pendingReconnectProfileId) connectionData.profile_context_optional = true;

            const useTmuxCheck = document.getElementById('useTmuxCheck');
            if (useTmuxCheck && useTmuxCheck.checked) {
                connectionData.use_tmux = true;
                // Include tmux session name for reconnection to persistent sessions
                if (SessionManager.pendingReconnectTmux) {
                    connectionData.reconnect_tmux_name = SessionManager.pendingReconnectTmux;
                }
                // Include display name for reconnecting persistent sessions
                if (SessionManager.pendingDisplayName) {
                    connectionData.display_name = SessionManager.pendingDisplayName;
                }
            }
            if (window.ProfileLauncherUtils?.requestsHerdrSession({
                profile: window.ProfileManager?.getProfile?.(contextProfileId),
                reconnect: SessionManager.pendingReconnectHerdr === true,
                connectionData,
            })) connectionData.use_herdr = true;

            const started = startConnection(connectionData, targetPane, SessionManager.pendingReconnectSessionId);
            if (!started) return;
            connectionModalRequestId = currentConnectRequestId;

            const connectLabel = document.querySelector('#connectBtn .btn-label');
            const connectingText = seconds => (
                window.i18n
                    ? i18n.t('connection.connectingElapsed')
                        .replace('{seconds}', String(seconds))
                    : `Connecting... ${seconds}s`
            );
            connectSeconds = 0;
            if (connectLabel) connectLabel.textContent = connectingText(connectSeconds);
            connectTimer = setInterval(() => {
                connectSeconds++;
                if (connectLabel) {
                    connectLabel.textContent = connectingText(connectSeconds);
                }
            }, 1000);

            setConnectLoading(true);

            document.getElementById('passwordInput').value = '';
            document.getElementById('jumpHostPasswordInput').value = '';
            document.getElementById('socksProxyPasswordInput').value = '';
        });

        document.getElementById('authTypeSelect').addEventListener('change', (e) => {
            ProfileManager.handleAuthTypeChange(e.target.value);
        });

        document.getElementById('socksProxySelect')?.addEventListener('change', () => {
            document.getElementById('socksProxyPasswordInput').value = '';
            window.CredentialPicker?.restore?.('socksProxyPasswordInput');
            window.SocksProxyManager?.updatePasswordVisibility();
        });
        document.getElementById('jumpHostSelect').addEventListener('change', () => {
            document.getElementById('jumpHostPasswordInput').value = '';
            window.CredentialPicker?.restore?.('jumpHostPasswordInput');
            if (window.JumpHostManager) {
                window.JumpHostManager.updatePasswordVisibility();
            }
            refreshConnectionProfileJumpResolution();
        });

        document.querySelectorAll('[data-connection-asset]').forEach(button => {
            button.addEventListener('click', () => {
                openConnectionAssetManager(button.dataset.connectionAsset);
            });
        });

        document.getElementById('closeKeyModal').addEventListener('click', () => {
            const view = document.getElementById('keyManagementModal');
            if (!window.primaryWorkspaceController?.close(view)) {
                window.ModalManager.close(view);
            }
        });

        // One upload at a time: a second click while the first is on its
        // way would store the key twice.
        let keyUploadPending = false;
        document.getElementById('keyUploadForm').addEventListener('submit', (e) => {
            e.preventDefault();
            if (keyUploadPending) return;

            const name = document.getElementById('keyNameInput').value;
            const keyContent = document.getElementById('keyContentInput').value;

            if (!name || !keyContent) {
                showNotification((window.i18n ? window.i18n.t('toast.keyNameContentRequired') : 'Key name and content are required'), 'error');
                return;
            }

            const submit = e.currentTarget.querySelector('button[type="submit"]');
            keyUploadPending = true;
            if (submit) submit.disabled = true;
            ProfileManager.uploadKey(name, keyContent, acknowledgement => {
                keyUploadPending = false;
                if (submit) submit.disabled = false;
                ProfileManager.reportKeyChangeFailure(acknowledgement);
            });
        });

        document.getElementById('closeJumpHostModal')?.addEventListener('click', () => {
            const view = document.getElementById('jumpHostManagementModal');
            if (!window.primaryWorkspaceController?.close(view)) {
                window.ModalManager.close(view);
            }
        });

        document.querySelectorAll('input[name="jhAuthType"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                document.getElementById('jhKeyGroup').classList.toggle('hidden', e.target.value !== 'key');
            });
        });

        document.getElementById('jumpHostForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            const name = document.getElementById('jhNameInput').value.trim();
            const host = document.getElementById('jhHostInput').value.trim();
            const port = document.getElementById('jhPortInput').value;
            const username = document.getElementById('jhUsernameInput').value.trim();
            const authType = document.querySelector('input[name="jhAuthType"]:checked').value;
            const keyId = document.getElementById('jhKeySelect').value;
            if (!name || !host || !username) {
                showNotification((window.i18n ? window.i18n.t('toast.nameHostUserRequired') : 'Name, host and username are required'), 'error');
                return;
            }
            if (authType === 'key' && !keyId) {
                showNotification((window.i18n ? window.i18n.t('toast.keyRequired') : 'SSH key is required'), 'error');
                return;
            }
            if (window.JumpHostManager) {
                window.JumpHostManager.save(name, host, port, username, authType, keyId);
            }
        });

        // Scrollback lines setting
        const scrollbackInput = document.getElementById('scrollbackInput');
        if (scrollbackInput) {
            scrollbackInput.value = String(TerminalManager.getScrollbackLines());
            scrollbackInput.addEventListener('change', () => {
                let val = parseInt(scrollbackInput.value, 10);
                if (isNaN(val) || val < 50) val = 50;
                if (val > 10000) val = 10000;
                scrollbackInput.value = val;
                window.BrowserPreferences?.set('terminalScrollback', val);
                // Update all existing terminals
                Object.keys(TerminalManager.terminals).forEach(key => {
                    TerminalManager.terminals[key].options.scrollback = val;
                });
            });
        }

        const confirmSessionCloseInput = document.getElementById('confirmSessionCloseInput');
        if (confirmSessionCloseInput) {
            confirmSessionCloseInput.checked = SessionManager.confirmSessionClose;
            confirmSessionCloseInput.addEventListener('change', () => {
                const previousValue = SessionManager.confirmSessionClose;
                const requestedValue = confirmSessionCloseInput.checked;
                confirmSessionCloseInput.disabled = true;

                if (!window.socket) {
                    confirmSessionCloseInput.checked = previousValue;
                    confirmSessionCloseInput.disabled = false;
                    showNotification(
                        window.i18n ? i18n.t('settings.saveFailed') : 'Failed to save setting',
                        'error',
                    );
                    return;
                }

                window.socket.emit(
                    'set_confirm_session_close',
                    { enabled: requestedValue },
                    response => {
                        const savedValue = response?.confirm_session_close;
                        if (response?.success && typeof savedValue === 'boolean') {
                            SessionManager.confirmSessionClose = savedValue;
                            document.body.dataset.confirmSessionClose = String(savedValue);
                            confirmSessionCloseInput.checked = savedValue;
                        } else {
                            confirmSessionCloseInput.checked = previousValue;
                            showNotification(
                                window.i18n ? i18n.t('settings.saveFailed') : 'Failed to save setting',
                                'error',
                            );
                        }
                        confirmSessionCloseInput.disabled = false;
                    },
                );
            });
        }

        const disconnectSessionActionSelect = document.getElementById('disconnectSessionActionSelect');
        if (disconnectSessionActionSelect) {
            disconnectSessionActionSelect.value = SessionManager.disconnectSessionAction;
            disconnectSessionActionSelect.addEventListener('change', () => {
                const previousValue = SessionManager.disconnectSessionAction;
                const requestedValue = disconnectSessionActionSelect.value;
                disconnectSessionActionSelect.disabled = true;

                if (!window.socket || !['retry', 'close'].includes(requestedValue)) {
                    disconnectSessionActionSelect.value = previousValue;
                    disconnectSessionActionSelect.disabled = false;
                    showNotification(
                        window.i18n ? i18n.t('settings.saveFailed') : 'Failed to save setting',
                        'error',
                    );
                    return;
                }

                window.socket.emit(
                    'set_disconnect_session_action',
                    { action: requestedValue },
                    response => {
                        const savedValue = response?.disconnect_session_action;
                        if (response?.success && ['retry', 'close'].includes(savedValue)) {
                            SessionManager.disconnectSessionAction = savedValue;
                            document.body.dataset.disconnectSessionAction = savedValue;
                            disconnectSessionActionSelect.value = savedValue;
                        } else {
                            disconnectSessionActionSelect.value = previousValue;
                            showNotification(
                                window.i18n ? i18n.t('settings.saveFailed') : 'Failed to save setting',
                                'error',
                            );
                        }
                        disconnectSessionActionSelect.disabled = false;
                    },
                );
            });
        }

        document.getElementById('logoutBtn').addEventListener('click', () => {
            const message = window.i18n ? i18n.t('auth.logoutConfirm') : 'Are you sure you want to logout? Remote tmux sessions keep running; other SSH sessions end.';
            if (confirm(message)) {
                SessionManager.clearScopedBrowserStorage();
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = APP_ROOT + '/logout';
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                if (csrfToken) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    input.value = csrfToken;
                    form.appendChild(input);
                }
                document.body.appendChild(form);
                window.AuthSessionGuard?.markSignedOut?.();
                form.submit();
            }
        });

        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                if (e.target.classList.contains('primary-workspace-view')) return;
                if (e.target.id === 'sshAuthBannerModal' || e.target.id === 'sshGatewayModal' || e.target.id === 'filePreviewModal') return;
                if (e.target.id === 'commandFormModal' || e.target.id === 'commandWorkspaceModal') return;
                if (e.target.id === 'connectionModal') {
                    dismissConnectionModal();
                    return;
                }
                window.ModalManager.close(e.target);
            }
        });

        document.addEventListener('keydown', (e) => {
            // Before the text-field early return: Tab from the last enabled
            // field of a dialog must stay inside it as well.
            window.ModalManager.trapFocus(e);
            const tag = document.activeElement?.tagName;
            if ((tag === 'INPUT' || tag === 'TEXTAREA') && e.key !== 'F1' && e.key !== 'Escape') {
                return;
            }

            if (e.key === 'F1') {
                e.preventDefault();
                CommandLibrary.openLibrary();
            }

            if (e.ctrlKey && e.key.toLowerCase() === 'f') {
                if (SessionManager.hasAnySessions()) {
                    e.preventDefault();
                    TerminalSearch.toggle();
                }
            }

            if (e.ctrlKey && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                if (openPalette) {
                    openPalette();
                }
            }

            if (e.ctrlKey && (e.key === '/' || e.key === '?')) {
                e.preventDefault();
                if (openShortcuts) {
                    openShortcuts();
                }
            }

            if (e.ctrlKey && e.shiftKey && e.key === 'N') {
                e.preventDefault();
                openConnectionModalForPane(getDefaultPaneIndex());
            }

            if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key >= '1' && e.key <= '9') {
                e.preventDefault();
                const index = parseInt(e.key) - 1;
                const tabs = document.querySelectorAll('.session-tab');
                if (tabs[index]) {
                    tabs[index].click();
                }
            }

            if (e.ctrlKey && e.key === 'Tab') {
                e.preventDefault();
                const tabs = Array.from(document.querySelectorAll('.session-tab'));
                const activeIndex = tabs.findIndex(t => t.classList.contains('active'));
                if (tabs.length > 0) {
                    const nextIndex = e.shiftKey
                        ? (activeIndex - 1 + tabs.length) % tabs.length
                        : (activeIndex + 1) % tabs.length;
                    tabs[nextIndex].click();
                }
            }

            if (e.key === 'Escape') {
                if (e.defaultPrevented) return;
                if (TerminalSearch.isOpen) {
                    TerminalSearch.close();
                } else {
                    const openModals = Array.from(document.querySelectorAll('.modal.show'));
                    let handled = false;
                    openModals.forEach(modal => {
                        if (
                            modal.id === 'sftpFileManager'
                            || modal.id === 'sshAuthBannerModal'
                            || modal.id === 'sshGatewayModal'
                            || modal.id === 'filePreviewModal'
                            || modal.classList.contains('primary-workspace-view')
                        ) return;
                        if (modal.id === 'connectionModal') {
                            dismissConnectionModal();
                            handled = true;
                            return;
                        }
                        window.ModalManager.close(modal);
                        handled = true;
                    });
                    if (!openModals.length) {
                        handled = Boolean(SessionManager.restoreConnectionLauncher?.(
                            SessionManager.getActivePaneIndex()
                        ));
                    }
                    if (handled) {
                        e.preventDefault();
                        e.stopImmediatePropagation();
                    }
                }
            }
        });

        document.getElementById('mobileMenuBtn').addEventListener('click', () => {
            if (window.mobileAppShell?.isPhone?.()) {
                window.mobileAppShell.toggleMoreMenu();
                return;
            }
            const menu = document.querySelector('.header-buttons');
            const open = menu.classList.toggle('is-open');
            document.getElementById('mobileMenuBtn').setAttribute(
                'aria-expanded',
                String(open),
            );
        });

        document.getElementById('sshAuthBannerCancel')?.addEventListener(
            'click', () => answerAuthBannerPrompt(false)
        );
        document.getElementById('sshAuthBannerContinue')?.addEventListener(
            'click', () => answerAuthBannerPrompt(true)
        );

        document.addEventListener('click', (e) => {
            const menu = document.querySelector('.header-buttons');
            const menuBtn = document.getElementById('mobileMenuBtn');
            if (!menu || !menuBtn) {
                return;
            }
            if (!e.target.closest('.header-buttons') && !menuBtn.contains(e.target)) {
                if (window.mobileAppShell?.isPhone?.()) {
                    if (!e.target.closest('#mobileMoreBtn')) {
                        window.mobileAppShell.closeMoreMenu();
                    }
                } else {
                    menu.classList.remove('is-open');
                    menuBtn.setAttribute('aria-expanded', 'false');
                }
            }
        });

        setupConnectionValidation();
        setupPasswordToggles();
        setupClipboardActions();
        setupSplitControls();
        setupNotepad();
        window.AuthSessionGuard?.start?.();
        TerminalSearch.init();
        FilePreview.init();
        window.sessionWorkspace = window.SessionWorkspaceUI?.init({
            socket: window.socket,
            sessionManager: SessionManager,
            terminalManager: TerminalManager,
            document,
        });

        shortcutsModal = setupShortcutsModal();
        openShortcuts = () => {
            if (shortcutsModal) {
                window.ModalManager.open(shortcutsModal);
            }
        };
        document.getElementById('accountShortcutsBtn')?.addEventListener('click', openShortcuts);

        openPalette = setupCommandPalette();
        window.openCommandPalette = openPalette;

        document.getElementById('closeCommandPaletteModal')?.addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('commandPaletteModal'));
        });

        // Register every session consumer before the server sends restoration events.
        socket.connect();

    });
})();
