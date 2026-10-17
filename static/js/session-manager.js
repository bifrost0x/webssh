/* exported SessionManager */
const SessionManager = {
    endpointKey(host, port, username) {
        return String(username).includes(':')
            ? 'gateway:v1:' + JSON.stringify([host, String(port), username])
            : `${host}:${port}:${username}`;
    },
    legacyDisplayNameStorageKey: 'sessionDisplayNames',
    displayNameStoragePrefix: 'sessionDisplayNames:',
    activeDisplayNameScopeKey: 'sessionDisplayNames:activeScope',
    sessions: {},
    activeSessionId: null,
    pendingConnections: {},
    layout: 1,
    paneAssignments: [],
    connectionLauncherSessions: new Map(),
    activePaneIndex: 0,
    confirmSessionClose: document.body?.dataset.confirmSessionClose === 'true',
    disconnectSessionAction: ['retry', 'close'].includes(
        document.body?.dataset.disconnectSessionAction
    ) ? document.body.dataset.disconnectSessionAction : 'retry',
    windowMode: false,
    windowModePreferred: false,
    windowDesktop: null,
    windowCompactMedia: null,
    windowSyncTimer: null,
    maxWindows: 16,
    windowModeStorageKey: 'webssh.workspace.windowMode',
    windowLayoutStoragePrefix: 'webssh.workspace.windows:',

    init() {
        this.initializeDisplayNameStorage();
        if (window.socket) {
            window.socket.on('ssh_session_restored', (data) => {
                this.restoreSession(data);
            });
            window.socket.on('persistent_session_available', (data) => {
                this.showPersistentSessionTab(data);
            });
        }
        this.ensureTerminalGrid();
        this.setSplitLayout(1);
        this.initWindowMode();
        this.initTabScrollAffordances();
        window.addEventListener('languageChanged', () => {
            this.refreshEmptyPanes();
        });
        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }
        this.updateSessionMeta(null);
    },

    displayNameScope() {
        return String(document.body?.dataset.connectionHistoryScope || '').trim();
    },

    displayNameStorageKey() {
        const scope = this.displayNameScope();
        return scope ? `${this.displayNameStoragePrefix}${scope}` : null;
    },

    initializeDisplayNameStorage() {
        try {
            localStorage.removeItem(this.legacyDisplayNameStorageKey);
            localStorage.removeItem(this.activeDisplayNameScopeKey);
        } catch {
            // Session aliases are optional when browser storage is unavailable.
        }
    },

    readDisplayNames() {
        const key = this.displayNameStorageKey();
        if (!key) return {};
        try {
            const value = JSON.parse(localStorage.getItem(key) || '{}');
            return value && typeof value === 'object' && !Array.isArray(value)
                ? value
                : {};
        } catch {
            return {};
        }
    },

    writeDisplayNames(value) {
        const key = this.displayNameStorageKey();
        if (!key) return;
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch {
            console.error('Failed to save session display name');
        }
    },

    clearScopedBrowserStorage() {
        try {
            localStorage.removeItem(this.legacyDisplayNameStorageKey);
            localStorage.removeItem(this.activeDisplayNameScopeKey);
        } catch {
            // Logout must continue even when browser storage is unavailable.
        }
    },

    restoreSession(data) {
        const sessionId = data.session_id;

        if (this.sessions[sessionId]) {
            TerminalManager.resyncRestoredOutput(
                sessionId,
                data.buffered_output,
                data.output_sequence,
            );
            if (data.file_source) this.sessions[sessionId].fileSource = data.file_source;
            this.updateSessionStatus(sessionId, 'connected');
            return;
        }

        const sessionData = {
            session_id: sessionId,
            host: data.host,
            port: data.port,
            username: data.username,
            auth_type: data.auth_type,
            via_jump: data.via_jump,
            jump_host_id: data.jump_host_id,
            reconnect_route_known: data.reconnect_route_known,
            key_id: data.key_id,
            display_name: data.display_name,
            file_source: data.file_source,
            use_tmux: data.use_tmux,
            tmux_session_name: data.tmux_session_name,
            restored: true,
        };

        // Seed the authoritative snapshot before terminal attachment. Any live
        // output already received is merged behind it without replay overlap.
        TerminalManager.seedRestoredOutput(
            sessionId,
            data.buffered_output,
            data.output_sequence,
        );

        const restoredId = this.createSession(sessionData);

        this.assignSessionToPane(restoredId, this.resolvePaneForNewSession(null));

    },

    showPersistentSessionTab(data) {
        const {
            session_id, host, port, username, key_id, auth_type,
            tmux_session_name, display_name
        } = data;

        if (this.sessions[session_id]) {
            return;
        }

        const terminalId = `terminal-${session_id}`;
        const terminalContainer = document.createElement('div');
        terminalContainer.id = terminalId;
        terminalContainer.className = 'terminal-wrapper unassigned';
        document.getElementById('terminalsContainer').appendChild(terminalContainer);

        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }

        this.sessions[session_id] = {
            id: session_id,
            host,
            port,
            username,
            connected: false,
            terminalId,
            os: 'all',
            displayName: display_name || null,
            viaJump: data.via_jump || null,
            jumpHostId: data.jump_host_id || null,
            reconnectRouteKnown: data.reconnect_route_known === true,
            useTmux: true,
            tmuxSessionName: tmux_session_name,
            isPersistentCandidate: true,
            keyId: key_id,
            authType: auth_type || 'password'
        };

        // Save display name to localStorage by host:port:user key
        if (display_name) {
            const stored = this.readDisplayNames();
            const hostKey = this.endpointKey(host, port, username);
            stored[hostKey] = display_name;
            this.writeDisplayNames(stored);
        }

        this.createSessionTab(session_id);
        this.updateSessionStatus(session_id, 'disconnected');

        this.assignSessionToPane(session_id, this.resolvePaneForNewSession(null));

    },

    createSession(sessionData) {
        const { session_id, host, port, username, display_name } = sessionData;

        const terminalId = `terminal-${session_id}`;
        const terminalContainer = document.createElement('div');
        terminalContainer.id = terminalId;
        terminalContainer.className = 'terminal-wrapper unassigned';
        document.getElementById('terminalsContainer').appendChild(terminalContainer);

        TerminalManager.createTerminal(session_id, null, {
            allowOsc52Clipboard: Boolean(
                sessionData.use_tmux && sessionData.tmux_session_name
            ),
            restoredOutput: sessionData.restored === true,
        });
        TerminalManager.attachTerminal(session_id, terminalId);
        TerminalManager.setupInputHandler(session_id, (data) => {
            if (window.socket) {
                // Filter out Device Attributes responses (ESC[c sequences only).
                // Bare-pattern regexes were removed because they corrupt legitimate input.
                data = data.replace(/\x1b\[[?>]?[0-9;]*c/g, '');
                if (data) {
                    if (window.SSHInput) {
                        window.SSHInput.send(session_id, data);
                    } else {
                        window.socket.emit('ssh_input', {
                            session_id: session_id,
                            data: data
                        });
                    }
                }
            }
        });

        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }

        const fallbackKey = this.endpointKey(host, port, username);
        const fallbackName = this.pendingDisplayNames ? this.pendingDisplayNames[fallbackKey] : null;
        const storedName = display_name || this.pendingDisplayName || fallbackName || this.getStoredDisplayName(session_id, host, port, username);
        this.pendingDisplayName = null;
        if (this.pendingDisplayNames) {
            delete this.pendingDisplayNames[fallbackKey];
        }
        this.sessions[session_id] = {
            id: session_id,
            host,
            port,
            username,
            connected: true,
            hostKeyVerified: true,
            terminalId,
            os: 'all',
            displayName: storedName || null,
            viaJump: sessionData.via_jump || null,
            jumpHostId: sessionData.jump_host_id || null,
            reconnectRouteKnown: sessionData.reconnect_route_known,
            useTmux: sessionData.use_tmux || false,
            tmuxSessionName: sessionData.tmux_session_name || null,
            keyId: sessionData.key_id || null,
            authType: sessionData.auth_type || 'password',
            fileSource: sessionData.file_source || null,
            restored: sessionData.restored === true,
        };

        this.createSessionTab(session_id);
        this.updateSessionStatus(session_id, 'connected');

        this.hideReconnectOverlay(session_id);

        return session_id;
    },

    createSessionTab(sessionId) {
        const tab = document.createElement('div');
        tab.className = 'session-tab';
        tab.id = `tab-${sessionId}`;

        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot connected';

        const tabLabel = document.createElement('span');
        tabLabel.className = 'tab-label';
        this.renderTabLabelContent(tabLabel, sessionId);

        const tabEdit = document.createElement('span');
        tabEdit.className = 'tab-edit material-icons';
        tabEdit.textContent = 'edit';
        const renameLabel = window.i18n ? i18n.t('session.rename') : 'Rename session';
        tabEdit.setAttribute('aria-label', renameLabel);
        tabEdit.setAttribute('title', renameLabel);
        tabEdit.dataset.i18nAriaLabel = 'session.rename';
        tabEdit.dataset.i18nTitle = 'session.rename';

        const tabClose = document.createElement('span');
        tabClose.className = 'tab-close material-icons';
        tabClose.dataset.sessionId = sessionId;
        tabClose.textContent = 'close';
        tabClose.setAttribute('aria-label', window.i18n ? i18n.t('session.close') : 'Close session');
        tabClose.dataset.i18nAriaLabel = 'session.close';

        tab.appendChild(statusDot);
        tab.appendChild(tabLabel);
        const sess = this.sessions[sessionId];
        if (sess && sess.viaJump) {
            const jumpBadge = document.createElement('span');
            jumpBadge.className = 'tab-jump-badge material-icons';
            jumpBadge.textContent = 'alt_route';
            jumpBadge.title = 'via ' + sess.viaJump;
            tab.appendChild(jumpBadge);
        }
        if (sess && sess.useTmux) {
            const tmuxBadge = document.createElement('span');
            tmuxBadge.className = 'tab-tmux-badge material-icons';
            tmuxBadge.textContent = 'push_pin';
            tmuxBadge.title = 'Persistent tmux session' + (sess.tmuxSessionName ? ': ' + sess.tmuxSessionName : '');
            tab.appendChild(tmuxBadge);
        }
        const tabReconnect = document.createElement('span');
        tabReconnect.className = 'tab-reconnect material-icons';
        tabReconnect.textContent = 'refresh';
        tabReconnect.setAttribute('aria-label', window.i18n ? i18n.t('session.reconnect') : 'Reconnect');
        tabReconnect.setAttribute('title', window.i18n ? i18n.t('session.reconnect') : 'Reconnect');
        tabReconnect.dataset.i18nAriaLabel = 'session.reconnect';
        tabReconnect.dataset.i18nTitle = 'session.reconnect';

        tab.appendChild(tabEdit);
        tab.appendChild(tabReconnect);
        tab.appendChild(tabClose);

        tab.addEventListener('click', () => {
            this.switchSession(sessionId);
        });

        tabLabel.addEventListener('dblclick', (e) => {
            e.stopPropagation();
            this.startRenameSession(sessionId, tabLabel);
        });

        tabEdit.addEventListener('click', (e) => {
            e.stopPropagation();
            this.startRenameSession(sessionId, tabLabel);
        });

        tabReconnect.addEventListener('click', (e) => {
            e.stopPropagation();
            this.requestReconnect(sessionId);
        });

        tabClose.addEventListener('click', (e) => {
            e.stopPropagation();
            this.requestCloseSession(sessionId);
        });

        document.getElementById('sessionTabs').appendChild(tab);
        this.scrollTabIntoView(sessionId);
    },

    switchSession(sessionId) {
        if (!this.sessions[sessionId]) {
            console.error('Session not found');
            return;
        }

        const assignedIndex = this.paneAssignments.findIndex(id => id === sessionId);
        if (assignedIndex !== -1) {
            if (this.connectionLauncherSessions.has(assignedIndex)) {
                this.restoreConnectionLauncher(assignedIndex);
                return;
            }
            this.setActivePane(assignedIndex);
            return;
        }

        if (this.windowMode) {
            this.assignSessionToPane(sessionId, this.resolvePaneForNewSession(null));
            return;
        }

        let targetIndex = this.activePaneIndex;
        if (targetIndex === null || targetIndex === undefined) {
            targetIndex = 0;
        }
        if (this.paneAssignments[targetIndex]) {
            const emptyIndex = this.getFirstEmptyPaneIndex();
            if (emptyIndex !== -1) {
                targetIndex = emptyIndex;
            }
        }
        this.assignSessionToPane(sessionId, targetIndex);
    },

    closeSession(sessionId) {
        if (!this.sessions[sessionId]) {
            return;
        }

        if (window.socket) {
            window.socket.emit('ssh_disconnect', { session_id: sessionId });
        }

        this.removeSessionUI(sessionId);
    },

    removeSessionUI(sessionId, {keepWindow = false} = {}) {
        window.SSHInput?.cancelSession?.(sessionId);
        if (!this.sessions[sessionId]) {
            return;
        }

        const terminalContainer = document.getElementById(this.sessions[sessionId].terminalId);
        if (terminalContainer) {
            terminalContainer.remove();
        }

        TerminalManager.destroyTerminal(sessionId);

        const tab = document.getElementById(`tab-${sessionId}`);
        if (tab) {
            tab.remove();
        }

        const paneIndex = this.paneAssignments.findIndex(id => id === sessionId);
        if (paneIndex !== -1) {
            this.connectionLauncherSessions.delete(paneIndex);
            this.paneAssignments[paneIndex] = null;
            if (this.windowMode && !keepWindow) {
                this.forgetWindowLayout(sessionId);
                this.closeWindowSlot(paneIndex, {activate: false});
            } else {
                this.renderPane(paneIndex);
                this.updateWindowChrome(paneIndex);
            }
        }

        window.dispatchEvent(new CustomEvent('session-removed', {
            detail: { sessionId },
        }));
        delete this.sessions[sessionId];

        const remainingSessions = Object.keys(this.sessions);
        if (this.windowMode) {
            this.activateTopWindow();
        } else if (remainingSessions.length > 0) {
            const assignedIndex = this.paneAssignments.findIndex(id => id);
            if (assignedIndex !== -1) {
                this.setActivePane(assignedIndex);
            } else {
                this.setActivePane(this.activePaneIndex);
            }
        } else {
            this.activeSessionId = null;
            this.updateSessionMeta(null);
            this.notifyWorkspaceChange();
        }
    },

    requestCloseSession(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }

        if (!this.confirmSessionClose) {
            this.closeSession(sessionId);
            return;
        }

        const label = this.getDisplayLabel(sessionId, session.username, session.host);
        const message = window.i18n
            ? i18n.t('session.closeConfirm').replace('{label}', label)
            : `Close session "${label}"?`;
        if (confirm(message)) {
            this.closeSession(sessionId);
        }
    },

    requestReconnect(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }

        const route = this.reconnectRoute(session);
        if (route.requiresForm || ((session.viaJump || session.jumpHostId)
                && !session.keyId && session.authType !== 'tailscale')) {
            this.prefillConnectionForm(sessionId, true);
            return;
        }

        const label = this.getDisplayLabel(sessionId, session.username, session.host);

        // Persistent key and Tailscale sessions can reconnect directly. A
        // password-backed candidate must reopen the form for its password.
        if (session.isPersistentCandidate) {
            const authType = session.authType || (session.keyId ? 'key' : 'password');
            if (session.keyId || authType === 'tailscale') {
                this.directReconnect(sessionId);
            } else {
                this.prefillConnectionForm(sessionId);
            }
            return;
        }

        // Active session — disconnect first, then reconnect
        if (session.connected) {
            const message = window.i18n
                ? i18n.t('session.reconnectConfirm').replace('{label}', label)
                : `Reconnect session "${label}"?`;
            if (!confirm(message)) {
                return;
            }

            const host = session.host;
            const port = session.port;
            const username = session.username;
            const displayName = session.displayName;
            const useTmux = session.useTmux;
            const tmuxSessionName = session.tmuxSessionName;
            const keyId = session.keyId;
            const authType = session.authType || (keyId ? 'key' : 'password');

            // Store display name for reconnect
            this.pendingDisplayName = displayName;
            this.pendingDisplayNames = this.pendingDisplayNames || {};
            if (displayName) {
                this.pendingDisplayNames[this.endpointKey(host, port, username)] = displayName;
            }

            // Disconnect the current session (sends ssh_disconnect to server)
            this.closeSession(sessionId);

            // Key and Tailscale sessions can reconnect without prompting for a
            // password. Password sessions reopen the pre-filled modal.
            if (keyId || authType === 'tailscale') {
                setTimeout(() => {
                    if (window.socket) {
                        const connectionData = {
                            host: host,
                            port: parseInt(port),
                            username: username,
                            client_request_id: `reconnect_${Date.now().toString(36)}`,
                            auth_type: authType,
                            use_tmux: useTmux,
                            reconnect_tmux_name: useTmux ? tmuxSessionName : null,
                            display_name: displayName
                        };
                        if (authType === 'key') {
                            connectionData.key_id = keyId;
                        }
                        if (route.proxyJump) connectionData.proxy_jump = route.proxyJump;
                        window.SSHGatewayDialog?.prepare(connectionData);
                        window.socket.emit('ssh_connect', connectionData);
                        const message = window.i18n
                            ? i18n.t('session.reconnecting').replace('{label}', label)
                            : `Reconnecting to ${label}...`;
                        window.showNotification(message, 'info');
                    }
                }, 500);
            } else {
                // No key_id — open pre-filled connection modal
                setTimeout(() => {
                    window.clearConnectionProfileState();
                    const hostInput = document.getElementById('hostInput');
                    const portInput = document.getElementById('portInput');
                    const userInput = document.getElementById('usernameInput');
                    if (hostInput) hostInput.value = host;
                    if (portInput) portInput.value = port;
                    if (userInput) userInput.value = username;

                    const authTypeSelect = document.getElementById('authTypeSelect');
                    if (authTypeSelect) {
                        authTypeSelect.value = authType;
                        authTypeSelect.dispatchEvent(new Event('change'));
                    }

                    if (useTmux) {
                        const tmuxCheck = document.getElementById('useTmuxCheck');
                        if (tmuxCheck) tmuxCheck.checked = true;
                        this.pendingReconnectTmux = tmuxSessionName || null;
                    }

                    const modal = document.getElementById('connectionModal');
                    if (window.ModalManager && modal) {
                        window.ModalManager.open(modal);
                    } else if (modal) {
                        modal.classList.add('show');
                    }
                }, 300);
            }
        }
    },

    updateSessionStatus(sessionId, status) {
        const tab = document.getElementById(`tab-${sessionId}`);
        if (tab) {
            if (status === 'connected') {
                tab.classList.add('connected');
                tab.classList.remove('disconnected');
            } else if (status === 'disconnected') {
                tab.classList.remove('connected');
                tab.classList.add('disconnected');
            }

            const dot = tab.querySelector('.status-dot');
            if (dot) {
                dot.classList.remove('connected', 'disconnected', 'connecting');
                dot.classList.add(status);
            }
        }

        if (this.sessions[sessionId]) {
            this.sessions[sessionId].connected = (status === 'connected');
        }

        if (
            status === 'disconnected'
            && this.disconnectSessionAction === 'close'
            && !this.sessions[sessionId]?.isPersistentCandidate
            && !this.sessions[sessionId]?.useTmux
            && !this.sessions[sessionId]?.tmuxSessionName
        ) {
            this.removeSessionUI(sessionId);
            return;
        }

        if (status === 'disconnected') {
            this.showReconnectOverlay(sessionId);
        } else if (status === 'connected') {
            this.hideReconnectOverlay(sessionId);
        }
        this.refreshWindowChrome(sessionId);
        this.notifyWorkspaceChange();
    },

    createPendingConnection(requestId, host, username, port) {
        const tab = document.createElement('div');
        tab.className = 'session-tab';
        tab.id = `pending-${requestId}`;
        tab.dataset.pendingId = requestId;

        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot connecting';

        const tabLabel = document.createElement('span');
        tabLabel.className = 'tab-label';
        tabLabel.textContent = `${username}@${host}`;

        const tabClose = document.createElement('button');
        tabClose.type = 'button';
        tabClose.className = 'tab-close';
        tabClose.dataset.pendingId = requestId;
        tabClose.classList.add('material-icons');
        tabClose.textContent = 'close';
        tabClose.setAttribute('aria-label', 'Cancel connection');
        tabClose.setAttribute('title', 'Cancel connection');

        tab.appendChild(statusDot);
        tab.appendChild(tabLabel);
        tab.appendChild(tabClose);

        tabClose.addEventListener('click', (e) => {
            e.stopPropagation();
            window.dispatchEvent?.(new CustomEvent(
                'ssh-connection-cancel-requested',
                { detail: { requestId } },
            ));
        });

        document.getElementById('sessionTabs').appendChild(tab);
        this.scrollTabIntoView(requestId);
        this.pendingConnections[requestId] = { host, username, port };
    },

    clearPendingConnection(requestId) {
        const tab = document.getElementById(`pending-${requestId}`);
        const shouldRestoreFocus = Boolean(
            tab && tab.contains?.(document.activeElement)
        );
        if (tab) {
            tab.remove();
        }
        delete this.pendingConnections[requestId];
        if (shouldRestoreFocus) {
            const restoreFocus = () => {
                if (this.getActiveSession()) {
                    this.focusActivePane();
                } else {
                    this.focusConnectionLauncher(this.activePaneIndex);
                }
            };
            if (typeof window.requestAnimationFrame === 'function') {
                window.requestAnimationFrame(restoreFocus);
            } else {
                restoreFocus();
            }
        }
    },

    getDisplayLabel(sessionId, username, host) {
        const session = this.sessions[sessionId];
        if (session && session.displayName) {
            return session.displayName;
        }
        return `${username}@${host}`;
    },

    renderTabLabelContent(labelEl, sessionId) {
        const session = this.sessions[sessionId];
        labelEl.innerHTML = '';
        if (!session) return;
        if (session.displayName) {
            const nameSpan = document.createElement('span');
            nameSpan.className = 'tab-display-name';
            nameSpan.textContent = session.displayName;
            labelEl.appendChild(nameSpan);
        } else {
            const hostSpan = document.createElement('span');
            hostSpan.className = 'tab-host-name';
            hostSpan.textContent = session.host;
            const userSpan = document.createElement('span');
            userSpan.className = 'tab-user-name';
            userSpan.textContent = session.username;
            labelEl.appendChild(hostSpan);
            labelEl.appendChild(userSpan);
        }
    },

    updateSessionLabel(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }
        const tab = document.getElementById(`tab-${sessionId}`);
        if (!tab) {
            return;
        }
        const label = tab.querySelector('.tab-label');
        if (label) {
            this.renderTabLabelContent(label, sessionId);
        }
        this.refreshWindowChrome(sessionId);
    },

    startRenameSession(sessionId, labelElement) {
        const session = this.sessions[sessionId];
        if (!session) return;

        const currentName = session.displayName || `${session.username}@${session.host}`;
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'tab-rename-input';
        input.value = currentName;
        input.placeholder = `${session.username}@${session.host}`;

        labelElement.innerHTML = '';
        labelElement.appendChild(input);
        input.focus();
        input.select();

        let renameFinished = false;
        const finishRename = (save) => {
            if (renameFinished) return;
            renameFinished = true;
            const newName = input.value.trim();
            input.remove();

            if (save && newName && newName !== `${session.username}@${session.host}`) {
                session.displayName = newName;
                this.saveSessionDisplayName(sessionId, newName);
            } else if (save && !newName) {
                session.displayName = null;
                this.saveSessionDisplayName(sessionId, null);
            }
            this.renderTabLabelContent(labelElement, sessionId);
            this.updateSessionMeta(sessionId);
            this.refreshWindowChrome(sessionId);
        };

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                finishRename(true);
            } else if (e.key === 'Escape') {
                e.preventDefault();
                finishRename(false);
            }
        });

        input.addEventListener('blur', () => {
            finishRename(true);
        });

        input.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    },

    saveSessionDisplayName(sessionId, displayName) {
        const session = this.sessions[sessionId];
        const stored = this.readDisplayNames();
        if (displayName) {
            stored[sessionId] = displayName;
        } else {
            delete stored[sessionId];
        }
        // Also save by host:port:user key so it survives session ID changes.
        if (session) {
            const hostKey = this.endpointKey(session.host, session.port, session.username);
            if (displayName) {
                stored[hostKey] = displayName;
            } else {
                delete stored[hostKey];
            }
        }
        this.writeDisplayNames(stored);
        // Save to server DB
        if (window.socket) {
            window.socket.emit('save_session_name', {
                session_id: sessionId,
                display_name: displayName
            });
        }
    },

    getStoredDisplayName(sessionId, host, port, username) {
        const stored = this.readDisplayNames();
        // Check by session ID first.
        if (stored[sessionId]) return stored[sessionId];
        // Check by host:port:user key (persists across session ID changes).
        if (host && port && username) {
            const hostKey = this.endpointKey(host, port, username);
            if (stored[hostKey]) return stored[hostKey];
        }
        return null;
    },

    updateSessionMeta(sessionId) {
        const meta = document.getElementById('sessionMeta');
        const titleEl = document.getElementById('sessionMetaTitle');
        const notesEl = document.getElementById('sessionMetaNotes');
        if (!meta || !titleEl || !notesEl) {
            return;
        }
        const session = this.sessions[sessionId];
        if (!session) {
            titleEl.textContent = window.i18n ? window.i18n.t('panes.emptyPane') : 'Empty pane';
            notesEl.textContent = window.i18n ? window.i18n.t('panes.selectSession') : 'Select a session or open a connection';
            notesEl.classList.add('empty');
            return;
        }

        titleEl.textContent = this.getDisplayLabel(sessionId, session.username, session.host);

        notesEl.textContent = `${session.username}@${session.host}:${session.port}`;
        if (session.viaJump) {
            const via = window.i18n ? i18n.t('connection.via') : 'via';
            notesEl.appendChild(document.createTextNode('  ·  '));
            const viaSpan = document.createElement('span');
            viaSpan.className = 'session-via';
            viaSpan.textContent = `${via} ${session.viaJump}`;
            notesEl.appendChild(viaSpan);
        }
        notesEl.classList.remove('empty');
    },

    ensureTerminalGrid() {
        return document.getElementById('terminalGrid');
    },

    getSessionTabsElement() {
        return document.getElementById('sessionTabs');
    },

    isSessionTabsRowHidden() {
        const tabs = this.getSessionTabsElement();
        const row = tabs?.closest?.('.session-tabs-row');
        return Boolean(row?.hidden);
    },

    scrollTabIntoView(sessionId) {
        if (!sessionId || this.isSessionTabsRowHidden()) {
            return;
        }
        const tab = document.getElementById(`tab-${sessionId}`)
            || document.getElementById(`pending-${sessionId}`);
        tab?.scrollIntoView?.({block: 'nearest', inline: 'nearest'});
    },

    initNewTabPlacement() {
        const tabs = this.getSessionTabsElement();
        const row = tabs?.closest?.('.session-tabs-row');
        const button = document.getElementById('newTabBtn');
        const actions = row?.querySelector('.tab-row-actions');
        if (!row || !button || !actions) return;

        const mobile = window.matchMedia?.(
            '(max-width: 767px), (max-height: 520px) and (pointer: coarse)'
        );
        const update = () => {
            if (row.hidden || !row.clientWidth) return;
            // Both positions reserve the same width, so moving the button cannot
            // change the overflow threshold and make its position oscillate.
            const atEnd = mobile?.matches || tabs.scrollWidth > tabs.clientWidth + 1;
            const reference = atEnd ? null : actions;
            if (button.parentNode === row && button.nextElementSibling === reference) return;
            const focused = document.activeElement === button;
            const scrollLeft = tabs.scrollLeft;
            row.insertBefore(button, reference);
            if (focused) button.focus({preventScroll: true});
            tabs.scrollLeft = scrollLeft;
        };
        let scheduled = false;
        const schedule = () => {
            if (scheduled) return;
            scheduled = true;
            window.setTimeout(() => {
                scheduled = false;
                update();
            }, 0);
        };
        if (window.ResizeObserver) {
            const observer = new window.ResizeObserver(schedule);
            [row, tabs, actions, button].forEach(element => observer.observe(element));
        }
        if (window.MutationObserver) {
            const observer = new window.MutationObserver(schedule);
            observer.observe(tabs, {childList: true, subtree: true, characterData: true, attributes: true});
            observer.observe(row, {attributes: true, attributeFilter: ['hidden']});
        }
        mobile?.addEventListener?.('change', schedule);
        window.addEventListener('resize', schedule);
        update();
    },

    initTabScrollAffordances() {
        const tabs = this.getSessionTabsElement();
        if (!tabs || tabs.dataset.tabScrollReady === 'true') {
            return;
        }
        tabs.dataset.tabScrollReady = 'true';
        this.initNewTabPlacement();

        tabs.addEventListener('wheel', (event) => {
            if (event.ctrlKey || event.metaKey || event.shiftKey) {
                return;
            }
            const delta = Math.abs(event.deltaX) > Math.abs(event.deltaY)
                ? event.deltaX
                : event.deltaY;
            if (!delta) {
                return;
            }
            const maxScroll = tabs.scrollWidth - tabs.clientWidth;
            if (maxScroll <= 0) {
                return;
            }
            const next = tabs.scrollLeft + delta;
            if ((delta < 0 && tabs.scrollLeft <= 0)
                || (delta > 0 && tabs.scrollLeft >= maxScroll)) {
                return;
            }
            event.preventDefault();
            tabs.scrollLeft = next;
        }, {passive: false});

        let dragPointerId = null;
        let dragStartX = 0;
        let dragStartScrollLeft = 0;
        let dragDistance = 0;
        let suppressClick = false;

        const endDrag = () => {
            if (dragPointerId === null) {
                return;
            }
            dragPointerId = null;
            const wasDrag = dragDistance > 6;
            dragDistance = 0;
            if (tabs.style) {
                tabs.style.userSelect = '';
            }
            window.removeEventListener('pointermove', onDragMove);
            window.removeEventListener('pointerup', onDragEnd);
            window.removeEventListener('pointercancel', onDragEnd);
            window.setTimeout(() => {
                suppressClick = false;
            }, 0);
            suppressClick = wasDrag;
        };

        const onDragMove = (event) => {
            if (dragPointerId === null || event.pointerId !== dragPointerId) {
                return;
            }
            if (event.pointerType === 'touch') {
                return;
            }
            const deltaX = event.clientX - dragStartX;
            if (Math.abs(deltaX) <= 6) {
                return;
            }
            dragDistance = Math.max(dragDistance, Math.abs(deltaX));
            if (tabs.style) {
                tabs.style.userSelect = 'none';
            }
            tabs.scrollLeft = dragStartScrollLeft - deltaX;
            suppressClick = true;
        };

        const onDragEnd = (event) => {
            if (dragPointerId === null || event.pointerId !== dragPointerId) {
                return;
            }
            endDrag();
        };

        tabs.addEventListener('pointerdown', (event) => {
            if (event.pointerType === 'mouse' && event.button !== 0) {
                return;
            }
            if (dragPointerId !== null) {
                return;
            }
            dragPointerId = event.pointerId;
            dragStartX = event.clientX;
            dragStartScrollLeft = tabs.scrollLeft;
            dragDistance = 0;
            suppressClick = false;
            window.addEventListener('pointermove', onDragMove);
            window.addEventListener('pointerup', onDragEnd);
            window.addEventListener('pointercancel', onDragEnd);
        });

        tabs.addEventListener('click', (event) => {
            if (!suppressClick) {
                return;
            }
            suppressClick = false;
            event.stopPropagation();
            event.preventDefault();
        }, true);
    },

    notifyWorkspaceChange() {
        if (!window.dispatchEvent || !window.CustomEvent) {
            return;
        }
        window.dispatchEvent(new CustomEvent('session-workspace-change', {
            detail: {
                layout: this.layout,
                sessionId: this.getWorkspaceSession(),
            },
        }));
    },

    setSplitLayout(layout) {
        if (layout === 'windows') {
            this.setWindowMode(true);
            return;
        }
        if (this.windowMode) {
            this.setWindowModePreference(false);
            this.leaveWindowMode(layout);
            return;
        }
        this.buildSplitLayout(layout);
    },

    buildSplitLayout(layout) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }
        if (this.layout === layout && this.paneAssignments.length === layout) {
            this.updateSplitControls();
            return;
        }

        const previousAssignments = this.paneAssignments.slice();
        this.connectionLauncherSessions.clear();
        this.layout = layout;
        this.paneAssignments = new Array(layout).fill(null);
        for (let i = 0; i < layout; i++) {
            this.paneAssignments[i] = previousAssignments[i] || null;
        }

        this.parkTerminalWrappers();

        grid.className = `terminal-grid split-${layout}`;
        grid.innerHTML = '';

        for (let i = 0; i < layout; i++) {
            const pane = document.createElement('div');
            pane.className = 'terminal-pane';
            pane.dataset.paneIndex = String(i);
            pane.addEventListener('click', () => {
                this.setActivePane(i);
            });
            grid.appendChild(pane);
            this.renderPane(i);
        }

        if (this.activePaneIndex >= layout) {
            this.activePaneIndex = 0;
        }
        this.setActivePane(this.activePaneIndex);
        this.updateSplitControls();
        this.notifyWorkspaceChange();
    },

    refreshEmptyPanes() {
        this.paneAssignments.forEach((sessionId, index) => {
            if (!this.paneAssignments[index]
                    || this.connectionLauncherSessions.has(index)) {
                this.renderPane(index, {preserveLauncherSearch: true});
            }
        });
        if (this.windowMode) {
            this.windowDesktop?.relabel();
            this.paneAssignments.forEach((sessionId, index) => this.updateWindowChrome(index));
        }
    },

    renderPane(paneIndex, {preserveLauncherSearch = false} = {}) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }
        const pane = grid.querySelector(`.terminal-pane[data-pane-index="${paneIndex}"]`);
        if (!pane) {
            return;
        }
        const previousSearch = preserveLauncherSearch
            ? pane.querySelector('.profile-launcher-search') : null;
        const searchQuery = previousSearch?.value || '';
        const restoreSearchFocus = previousSearch && document.activeElement === previousSearch;
        const searchSelection = restoreSearchFocus
            ? [previousSearch.selectionStart, previousSearch.selectionEnd, previousSearch.selectionDirection]
            : null;
        // Clearing the pane must never detach a live terminal from the page.
        const container = document.getElementById('terminalsContainer');
        Array.from(pane.children || []).forEach(child => {
            if (container && child.classList?.contains('terminal-wrapper')) {
                child.classList.add('unassigned');
                container.appendChild(child);
            }
        });
        pane.innerHTML = '';

        const sessionId = this.paneAssignments[paneIndex];
        const launcherSessionId = this.connectionLauncherSessions.get(paneIndex);
        if (this.windowMode && this.windowDesktop?.isMinimized(paneIndex)) {
            // Minimized windows keep their slot; the terminal runs in the
            // background exactly like an unassigned tab.
            return;
        }
        if (sessionId && !launcherSessionId) {
            const session = this.sessions[sessionId];
            if (!session) {
                return;
            }
            const wrapper = document.getElementById(session.terminalId);
            if (wrapper) {
                wrapper.classList.remove('unassigned');
                pane.appendChild(wrapper);
            }
            TerminalManager.fitTerminal(sessionId);
            TerminalManager.resumeVisibleOutput?.(sessionId);
            TerminalManager.repaintVisibleTerminal?.(sessionId);
            return;
        }

        if (sessionId && launcherSessionId) {
            const session = this.sessions[sessionId];
            const wrapper = session
                ? document.getElementById(session.terminalId)
                : null;
            const container = document.getElementById('terminalsContainer');
            if (wrapper && container && wrapper.parentElement !== container) {
                wrapper.classList.add('unassigned');
                container.appendChild(wrapper);
            }
        }

        const empty = typeof ProfileManager !== 'undefined'
            ? ProfileManager.createEmptyPaneContent(paneIndex, {
                searchQuery,
                ...(launcherSessionId ? {
                    returnLabel: this.getDisplayLabel(
                        launcherSessionId,
                        this.sessions[launcherSessionId]?.username,
                        this.sessions[launcherSessionId]?.host,
                    ),
                    onReturn: () => this.restoreConnectionLauncher(paneIndex),
                } : {}),
            })
            : document.createElement('div');
        if (!empty.className) {
            empty.className = 'pane-empty';
            empty.textContent = window.i18n ? i18n.t('panes.emptyPane') : 'Empty pane';
        }
        pane.appendChild(empty);
        if (restoreSearchFocus) {
            const search = empty.querySelector('.profile-launcher-search');
            search?.focus({preventScroll: true});
            if (searchSelection) search?.setSelectionRange(...searchSelection);
        }
    },

    assignSessionToPane(sessionId, paneIndex) {
        if (paneIndex === null || paneIndex === undefined) {
            return;
        }
        if (paneIndex < 0 || paneIndex >= this.paneAssignments.length) {
            return;
        }
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }
        const slotWasEmpty = !this.paneAssignments[paneIndex];

        this.connectionLauncherSessions.delete(paneIndex);
        const clearedIndices = [];
        this.paneAssignments = this.paneAssignments.map((existing, index) => {
            if (existing === sessionId) {
                this.connectionLauncherSessions.delete(index);
                clearedIndices.push(index);
                return null;
            }
            return existing;
        });

        if (this.paneAssignments[paneIndex] && this.paneAssignments[paneIndex] !== sessionId) {
            const oldSessionId = this.paneAssignments[paneIndex];
            const oldSession = this.sessions[oldSessionId];
            if (oldSession) {
                const wrapper = document.getElementById(oldSession.terminalId);
                if (wrapper) {
                    wrapper.classList.add('unassigned');
                    const container = document.getElementById('terminalsContainer');
                    if (container && wrapper.parentElement !== container) {
                        container.appendChild(wrapper);
                    }
                }
            }
        }

        this.paneAssignments[paneIndex] = sessionId;
        if (this.windowMode) {
            this.openWindowForSlot(paneIndex, sessionId, {slotWasEmpty});
        }
        this.renderPane(paneIndex);
        clearedIndices.forEach(index => {
            if (index === paneIndex) {
                return;
            }
            if (this.windowMode) {
                this.closeWindowSlot(index, {activate: false});
            } else {
                this.renderPane(index);
            }
        });
        if (this.windowMode) {
            this.updateWindowChrome(paneIndex);
            this.saveWindowLayouts();
            if (this.windowDesktop?.isMinimized(paneIndex)) {
                // A restored session reopens minimized when it was left that way.
                this.updateWindowTabState();
                this.notifyWorkspaceChange();
                return;
            }
        }
        this.setActivePane(paneIndex);
    },

    setActivePane(paneIndex) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }
        if (paneIndex < 0 || paneIndex >= this.paneAssignments.length) {
            return;
        }
        if (this.windowMode) {
            if (!this.windowDesktop?.isOpen(paneIndex)) {
                return;
            }
            if (this.windowDesktop.isMinimized(paneIndex)) {
                this.windowDesktop.restore(paneIndex);
            }
            this.windowDesktop.focus(paneIndex);
        }
        const previousPaneIndex = this.activePaneIndex;
        if (
            previousPaneIndex !== paneIndex
            && this.connectionLauncherSessions.has(previousPaneIndex)
        ) {
            this.restoreConnectionLauncher(previousPaneIndex, { activate: false });
        }

        this.activePaneIndex = paneIndex;
        grid.querySelectorAll('.terminal-pane').forEach(pane => {
            pane.classList.toggle('active', pane.dataset.paneIndex === String(paneIndex));
        });

        const assignedSessionId = this.paneAssignments[paneIndex] || null;
        const launcherOpen = this.connectionLauncherSessions.has(paneIndex);
        const sessionId = assignedSessionId;
        // Preserve the pane context for Files and diagnostics, but never expose
        // a hidden terminal as the target for paste, mobile input, or commands.
        this.activeSessionId = launcherOpen ? null : sessionId;
        this.updateSessionMeta(sessionId);

        document.querySelectorAll('.session-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        if (sessionId) {
            const tab = document.getElementById(`tab-${sessionId}`);
            if (tab) {
                tab.classList.add('active');
                this.scrollTabIntoView(sessionId);
            }
        }
        if (launcherOpen) {
            this.focusConnectionLauncher(paneIndex);
        } else {
            this.focusActivePane();
        }

        if (sessionId && !launcherOpen) {
            TerminalManager.scheduleFitAndSyncVisibleTerminals?.({
                socket: window.socket,
                isConnected: candidateId => (
                    candidateId === sessionId
                    && Boolean(this.sessions[sessionId]?.connected)
                ),
            });
        }
        if (this.windowMode) {
            this.updateWindowTabState();
            this.saveWindowLayouts();
        }
        this.notifyWorkspaceChange();
    },

    focusActivePane() {
        const sessionId = this.getActiveSession();
        if (!sessionId) {
            return;
        }
        const terminal = TerminalManager.terminals[sessionId];
        if (terminal) {
            terminal.focus();
        }
    },

    getActiveTerminal() {
        const sessionId = this.getActiveSession();
        if (!sessionId) {
            return null;
        }
        return TerminalManager.terminals[sessionId] || null;
    },

    getActivePaneIndex() {
        return this.activePaneIndex;
    },

    isConnectionLauncherOpen(paneIndex = this.activePaneIndex) {
        return this.connectionLauncherSessions.has(paneIndex);
    },

    getWorkspaceSession() {
        return this.paneAssignments[this.activePaneIndex] || null;
    },

    getFirstEmptyPaneIndex() {
        return this.paneAssignments.findIndex(
            (sessionId, index) => !sessionId && this.isPaneSlotOpen(index)
        );
    },

    getEmptyPaneIndices() {
        return this.paneAssignments
            .map((sessionId, index) => (
                sessionId || !this.isPaneSlotOpen(index) ? null : index
            ))
            .filter(index => index !== null);
    },

    isPaneSlotOpen(index) {
        return !this.windowMode || Boolean(this.windowDesktop?.isOpen(index));
    },

    // New sessions fill an empty pane. In window mode they open a window of
    // their own instead of replacing the session in the focused one.
    resolvePaneForNewSession(preferredIndex) {
        if (!this.windowMode) {
            if (preferredIndex !== null && preferredIndex !== undefined) {
                return preferredIndex;
            }
            const emptyIndex = this.getFirstEmptyPaneIndex();
            return emptyIndex !== -1 ? emptyIndex : this.activePaneIndex;
        }
        const isOpenEmptyWindow = index => (
            Number.isInteger(index)
            && index >= 0
            && index < this.paneAssignments.length
            && !this.paneAssignments[index]
            && this.isPaneSlotOpen(index)
        );
        if (isOpenEmptyWindow(preferredIndex)) return preferredIndex;
        if (isOpenEmptyWindow(this.activePaneIndex)) return this.activePaneIndex;
        const emptyIndex = this.getFirstEmptyPaneIndex();
        if (emptyIndex !== -1) return emptyIndex;
        const created = this.allocateWindowSlot({render: false});
        return created !== -1 ? created : this.activePaneIndex;
    },

    // The pane a connection started from a global control should land in:
    // in window mode only an empty window qualifies, otherwise a new one opens.
    getLauncherPaneIndex() {
        if (!this.windowMode) return null;
        const active = this.activePaneIndex;
        if (!this.paneAssignments[active] && this.isPaneSlotOpen(active)
                && active < this.paneAssignments.length) {
            return active;
        }
        const emptyIndex = this.getFirstEmptyPaneIndex();
        return emptyIndex !== -1 ? emptyIndex : null;
    },

    showConnectionLauncher(paneIndex) {
        if (this.windowMode) {
            return this.openNewWindow() !== -1;
        }
        if (
            !Number.isInteger(paneIndex)
            || paneIndex < 0
            || paneIndex >= this.paneAssignments.length
        ) {
            return false;
        }

        const sessionId = this.paneAssignments[paneIndex];
        const session = sessionId ? this.sessions[sessionId] : null;
        const wrapper = session
            ? document.getElementById(session.terminalId)
            : null;
        const container = document.getElementById('terminalsContainer');
        if (window.TerminalSearch?.isOpen) {
            window.TerminalSearch.close();
        }
        const workspaceState = window.workspaceLayoutController?.getState?.();
        if (workspaceState?.mode !== 'desktop' && workspaceState?.activeContext) {
            window.workspaceLayoutController.closeContext?.('connection-launcher');
        }
        if (wrapper && container) {
            wrapper.classList.add('unassigned');
            container.appendChild(wrapper);
        }

        if (sessionId) {
            this.connectionLauncherSessions.set(paneIndex, sessionId);
        }
        this.renderPane(paneIndex);
        this.setActivePane(paneIndex);
        return true;
    },

    restoreConnectionLauncher(paneIndex, options = {}) {
        if (!this.connectionLauncherSessions.has(paneIndex)) {
            return false;
        }
        this.connectionLauncherSessions.delete(paneIndex);
        this.renderPane(paneIndex);
        if (options.activate !== false) {
            this.setActivePane(paneIndex);
        }
        return true;
    },

    focusConnectionLauncher(paneIndex = this.activePaneIndex) {
        const grid = this.ensureTerminalGrid();
        const pane = grid?.querySelector(
            `.terminal-pane[data-pane-index="${paneIndex}"]`
        );
        pane?.querySelector(
            '.profile-launcher-return, .profile-launcher-search, '
            + '.profile-launcher-card, .profile-launcher-new'
        )?.focus?.();
    },

    updateSplitControls() {
        document.querySelectorAll('.split-btn').forEach(btn => {
            const active = btn.dataset.layout === 'windows'
                ? this.windowMode
                : !this.windowMode && parseInt(btn.dataset.layout, 10) === this.layout;
            btn.classList.toggle('active', active);
        });
        const arrange = document.getElementById('windowArrangeControls');
        if (arrange) {
            arrange.hidden = !this.windowMode;
        }
        document.body?.classList.toggle('terminal-window-mode', this.windowMode);
    },

    showReconnectOverlay(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }
        const container = document.getElementById(session.terminalId);
        if (!container) {
            return;
        }
        let overlay = container.querySelector('.session-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.className = 'session-overlay';
            const isPersistent = session.isPersistentCandidate;

            const card = document.createElement('div');
            card.className = 'session-overlay-card';

            const heading = document.createElement('h3');
            heading.dataset.i18n = isPersistent ? 'session.persistent' : 'session.disconnected';
            heading.textContent = isPersistent
                ? (window.i18n ? i18n.t('session.persistent') : 'Persistent session')
                : (window.i18n ? i18n.t('session.disconnected') : 'Session disconnected');
            card.appendChild(heading);

            const desc = document.createElement('p');
            desc.dataset.i18n = isPersistent
                ? 'session.persistentDescription'
                : 'session.disconnectedDescription';
            desc.textContent = isPersistent
                ? (window.i18n ? i18n.t('session.persistentDescription') : 'tmux session running on remote host. Reconnect to resume.')
                : (window.i18n ? i18n.t('session.disconnectedDescription') : 'Reconnect to resume your work.');
            card.appendChild(desc);

            const tmuxName = session.tmuxSessionName || '';
            if (tmuxName) {
                const tmuxInfo = document.createElement('p');
                tmuxInfo.style.cssText = 'font-size:12px;opacity:0.7;';
                tmuxInfo.textContent = 'tmux: ' + tmuxName;
                card.appendChild(tmuxInfo);
            }

            const actions = document.createElement('div');
            actions.className = 'session-overlay-actions';

            const retryButton = document.createElement('button');
            retryButton.className = 'btn btn-primary';
            retryButton.dataset.sessionId = sessionId;
            retryButton.dataset.i18n = isPersistent ? 'session.reconnect' : 'session.retry';
            retryButton.textContent = isPersistent
                ? (window.i18n ? i18n.t('session.reconnect') : 'Reconnect')
                : (window.i18n ? i18n.t('session.retry') : 'Retry');
            retryButton.addEventListener('click', () => {
                this.prefillConnectionForm(sessionId);
            });

            const closeButton = document.createElement('button');
            closeButton.className = 'btn btn-secondary session-overlay-close-tab';
            closeButton.dataset.sessionId = sessionId;
            closeButton.dataset.i18n = 'session.closeTab';
            closeButton.textContent = window.i18n
                ? i18n.t('session.closeTab')
                : 'Close tab';
            closeButton.addEventListener('click', () => {
                this.closeSession(sessionId);
            });

            actions.appendChild(retryButton);
            actions.appendChild(closeButton);
            card.appendChild(actions);

            overlay.appendChild(card);
            container.appendChild(overlay);
        }
        overlay.classList.remove('hidden');
    },

    hideReconnectOverlay(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }
        const container = document.getElementById(session.terminalId);
        if (!container) {
            return;
        }
        const overlay = container.querySelector('.session-overlay');
        if (overlay) {
            overlay.classList.add('hidden');
        }
    },

    reconnectRoute(session) {
        if (window.prepareSessionReconnectJump) {
            return window.prepareSessionReconnectJump(session);
        }
        return {requiresForm: Boolean(session.viaJump || session.jumpHostId
            || session.reconnectRouteKnown === false)};
    },

    prefillConnectionForm(sessionId, forceForm = false) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }

        const authType = session.authType || (session.keyId ? 'key' : 'password');

        // Key and Tailscale persistent sessions can reconnect directly without
        // opening the connection modal.
        if (!forceForm && session.isPersistentCandidate && session.useTmux
                && (session.keyId || authType === 'tailscale')) {
            this.directReconnect(sessionId);
            return;
        }

        // For persistent candidate sessions (password auth), save display name
        // and remove the old tab before opening the modal.
        if (session.isPersistentCandidate) {
            this.pendingDisplayName = session.displayName;
            this.pendingDisplayNames = this.pendingDisplayNames || {};
            if (session.displayName) {
                this.pendingDisplayNames[this.endpointKey(session.host, session.port, session.username)] = session.displayName;
            }
            this.pendingReconnectTmux = session.useTmux ? session.tmuxSessionName : null;
            this.removeSessionUI(sessionId);
        }

        window.clearConnectionProfileState();
        this.pendingReconnectSessionId = session.connected && !session.isPersistentCandidate
            ? sessionId : null;
        const hostInput = document.getElementById('hostInput');
        const portInput = document.getElementById('portInput');
        const userInput = document.getElementById('usernameInput');
        if (hostInput) {
            hostInput.value = session.host;
        }
        if (portInput) {
            portInput.value = session.port;
        }
        if (userInput) {
            userInput.value = session.username;
        }

        const authTypeSelect = document.getElementById('authTypeSelect');
        if (authTypeSelect) {
            authTypeSelect.value = authType;
            authTypeSelect.dispatchEvent(new Event('change'));
        }

        // If persistent session with key_id, auto-select the key
        if (session.keyId) {
            setTimeout(() => {
                const keySelect = document.getElementById('keySelect');
                if (keySelect) {
                    for (let opt of keySelect.options) {
                        if (opt.value === session.keyId) {
                            opt.selected = true;
                            break;
                        }
                    }
                }
            }, 200);
        }

        // Pre-check tmux checkbox for persistent sessions
        if (session.useTmux) {
            const tmuxCheck = document.getElementById('useTmuxCheck');
            if (tmuxCheck) {
                tmuxCheck.checked = true;
            }
            // Store the tmux session name for reconnection
            this.pendingReconnectTmux = session.tmuxSessionName || null;
        } else {
            this.pendingReconnectTmux = null;
        }

        window.prepareSessionReconnectJump?.(session, {applyToForm: true});

        const modal = document.getElementById('connectionModal');
        if (window.ModalManager && modal) {
            window.ModalManager.open(modal);
        } else if (modal) {
            modal.classList.add('show');
        }
    },

    directReconnect(sessionId) {
        const session = this.sessions[sessionId];
        if (!session || !session.isPersistentCandidate) {
            return;
        }
        const route = this.reconnectRoute(session);
        if (route.requiresForm) {
            this.prefillConnectionForm(sessionId, true);
            return;
        }

        const host = session.host;
        const port = session.port;
        const username = session.username;
        const keyId = session.keyId;
        const authType = session.authType || (keyId ? 'key' : 'password');
        const tmuxSessionName = session.tmuxSessionName;
        const displayName = session.displayName;


        // Store display name BEFORE removing UI so it survives the reconnect
        this.pendingDisplayName = displayName;
        // Also store by host:port:user as a fallback key
        if (displayName) {
            this.pendingDisplayNames = this.pendingDisplayNames || {};
            this.pendingDisplayNames[this.endpointKey(host, port, username)] = displayName;
        }

        // Remove the persistent candidate UI without notifying server
        this.removeSessionUI(sessionId);

        // Emit reconnect directly
        if (window.socket) {
            const connectionData = {
                host: host,
                port: parseInt(port),
                username: username,
                client_request_id: `reconnect_${Date.now().toString(36)}`,
                auth_type: authType,
                use_tmux: true,
                reconnect_tmux_name: tmuxSessionName,
                display_name: displayName
            };
            if (authType === 'key') {
                connectionData.key_id = keyId;
            }
            if (route.proxyJump) connectionData.proxy_jump = route.proxyJump;
            window.SSHGatewayDialog?.prepare(connectionData);
            window.socket.emit('ssh_connect', connectionData);
            const label = `${username}@${host}`;
            const message = window.i18n
                ? i18n.t('session.reconnecting').replace('{label}', label)
                : `Reconnecting to ${label}...`;
            window.showNotification(message, 'info');
        }
    },

    pendingDisplayName: null,

    pendingReconnectTmux: null,

    getActiveSession() {
        return this.activeSessionId;
    },

    getSession(sessionId) {
        return this.sessions[sessionId];
    },

    getAllSessions() {
        return Object.values(this.sessions);
    },

    hasAnySessions() {
        return Object.keys(this.sessions).length > 0;
    },

    showPaneAssignmentModal(targetLayout) {
        const modal = document.getElementById('paneAssignmentModal');
        if (!modal) {
            return;
        }

        const list = document.getElementById('paneAssignmentList');
        if (!list) {
            return;
        }

        const currentAssignments = this.paneAssignments.slice();
        const tempAssignments = new Array(targetLayout).fill(null);

        for (let i = 0; i < Math.min(targetLayout, currentAssignments.length); i++) {
            tempAssignments[i] = currentAssignments[i];
        }

        list.innerHTML = '';
        const allSessions = Object.values(this.sessions);

        for (let paneIndex = 0; paneIndex < targetLayout; paneIndex++) {
            const paneItem = document.createElement('div');
            paneItem.className = 'pane-assignment-item';

            const header = document.createElement('div');
            header.className = 'pane-assignment-header';

            const paneNum = document.createElement('div');
            paneNum.className = 'pane-number';
            paneNum.textContent = paneIndex + 1;

            const paneTitle = document.createElement('h4');
            paneTitle.textContent = `${window.i18n ? window.i18n.t('panes.pane') : 'Pane'} ${paneIndex + 1}`;

            header.appendChild(paneNum);
            header.appendChild(paneTitle);
            paneItem.appendChild(header);

            const optionsContainer = document.createElement('div');
            optionsContainer.className = 'pane-assignment-options';

            const emptyOption = this.createPaneOption(
                paneIndex,
                null,
                window.i18n ? window.i18n.t('panes.empty') : 'Empty',
                window.i18n ? window.i18n.t('panes.emptyDesc') : 'Leave this pane empty',
                tempAssignments[paneIndex] === null
            );
            optionsContainer.appendChild(emptyOption);

            allSessions.forEach(session => {
                const label = this.getDisplayLabel(session.id, session.username, session.host);
                const subtitle = session.connected ?
                    (window.i18n ? window.i18n.t('panes.connected') : 'Connected') :
                    (window.i18n ? window.i18n.t('panes.disconnected') : 'Disconnected');
                const option = this.createPaneOption(
                    paneIndex,
                    session.id,
                    label,
                    subtitle,
                    tempAssignments[paneIndex] === session.id
                );
                optionsContainer.appendChild(option);
            });

            const newOption = this.createPaneOption(
                paneIndex,
                '__new__',
                window.i18n ? window.i18n.t('panes.newConnection') : '+ Quick Connect',
                window.i18n ? window.i18n.t('panes.newConnectionDesc') : 'Open Quick Connect for this pane',
                false
            );
            optionsContainer.appendChild(newOption);

            paneItem.appendChild(optionsContainer);
            list.appendChild(paneItem);
        }

        const closeBtn = document.getElementById('closePaneAssignmentModal');
        const cancelBtn = document.getElementById('cancelPaneAssignment');
        const applyBtn = document.getElementById('applyPaneAssignment');

        const closeHandler = () => {
            if (window.ModalManager) {
                window.ModalManager.close(modal);
            } else {
                modal.classList.remove('show');
            }
        };

        const applyHandler = () => {
            const newAssignments = [];
            for (let i = 0; i < targetLayout; i++) {
                const selected = list.querySelector(`input[name="pane-${i}"]:checked`);
                if (selected) {
                    const value = selected.value;
                    if (value === '__empty__') {
                        newAssignments[i] = null;
                    } else if (value === '__new__') {
                        newAssignments[i] = null;
                    } else {
                        newAssignments[i] = value;
                    }
                } else {
                    newAssignments[i] = null;
                }
            }

            this.applyPaneAssignments(targetLayout, newAssignments);

            for (let i = 0; i < targetLayout; i++) {
                const selected = list.querySelector(`input[name="pane-${i}"]:checked`);
                if (selected && selected.value === '__new__') {
                    if (window.openConnectionModalForPane) {
                        setTimeout(() => window.openConnectionModalForPane(i), 100);
                    }
                }
            }

            closeHandler();
        };

        closeBtn.onclick = closeHandler;
        cancelBtn.onclick = closeHandler;
        applyBtn.onclick = applyHandler;

        if (window.ModalManager) {
            window.ModalManager.open(modal);
        } else {
            modal.classList.add('show');
        }
    },

    createPaneOption(paneIndex, sessionId, title, subtitle, isSelected) {
        const option = document.createElement('label');
        option.className = 'pane-option' + (isSelected ? ' selected' : '');

        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = `pane-${paneIndex}`;
        radio.value = sessionId === null ? '__empty__' : sessionId;
        radio.checked = isSelected;

        const label = document.createElement('div');
        label.className = 'pane-option-label';

        const titleEl = document.createElement('div');
        titleEl.className = 'pane-option-title';
        titleEl.textContent = title;

        const subtitleEl = document.createElement('div');
        subtitleEl.className = 'pane-option-subtitle';
        subtitleEl.textContent = subtitle;

        label.appendChild(titleEl);
        label.appendChild(subtitleEl);

        option.appendChild(radio);
        option.appendChild(label);

        option.addEventListener('click', () => {
            const allOptions = option.parentElement.querySelectorAll('.pane-option');
            allOptions.forEach(opt => opt.classList.remove('selected'));
            option.classList.add('selected');
        });

        return option;
    },

    applyPaneAssignments(layout, assignments) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }

        if (this.windowMode) {
            this.setWindowModePreference(false);
            this.teardownWindowMode();
        }
        this.connectionLauncherSessions.clear();
        this.layout = layout;
        this.paneAssignments = new Array(layout).fill(null);

        this.parkTerminalWrappers();

        grid.className = `terminal-grid split-${layout}`;
        grid.innerHTML = '';

        for (let i = 0; i < layout; i++) {
            const pane = document.createElement('div');
            pane.className = 'terminal-pane';
            pane.dataset.paneIndex = String(i);
            pane.addEventListener('click', () => {
                this.setActivePane(i);
            });
            grid.appendChild(pane);
        }

        for (let i = 0; i < layout; i++) {
            if (assignments[i]) {
                this.paneAssignments[i] = assignments[i];
            }
            this.renderPane(i);
        }

        if (this.activePaneIndex >= layout) {
            this.activePaneIndex = 0;
        }
        this.setActivePane(this.activePaneIndex);
        this.updateSplitControls();
    },

    // Floating windows -----------------------------------------------------
    // Each pane slot becomes a window on a desktop. Slots keep their index
    // while a window is open so in-flight connections still find their pane.

    initWindowMode() {
        try {
            this.windowCompactMedia = window.matchMedia?.(
                '(max-width: 767px), (max-height: 520px) and (pointer: coarse)'
            ) || null;
        } catch {
            this.windowCompactMedia = null;
        }
        this.windowCompactMedia?.addEventListener?.(
            'change', () => this.applyWindowModePreference()
        );
        this.windowModePreferred = this.readWindowModePreference();
        this.applyWindowModePreference();
    },

    isWindowModeAvailable() {
        return typeof TerminalWindows !== 'undefined'
            && Boolean(this.ensureTerminalGrid())
            && !this.windowCompactMedia?.matches;
    },

    readWindowModePreference() {
        try {
            return localStorage.getItem(this.windowModeStorageKey) === 'on';
        } catch {
            return false;
        }
    },

    setWindowModePreference(enabled) {
        this.windowModePreferred = Boolean(enabled);
        try {
            localStorage.setItem(this.windowModeStorageKey, enabled ? 'on' : 'off');
        } catch {
            // The layout still applies to this page without storage.
        }
    },

    setWindowMode(enabled) {
        this.setWindowModePreference(enabled);
        this.applyWindowModePreference();
    },

    // Narrow screens fall back to a single pane and return to windows when
    // there is room again, without forgetting the preference.
    applyWindowModePreference() {
        const wanted = this.windowModePreferred && this.isWindowModeAvailable();
        if (wanted && !this.windowMode) {
            this.enterWindowMode();
        } else if (!wanted && this.windowMode) {
            this.leaveWindowMode(1);
        } else {
            this.updateSplitControls();
        }
    },

    windowText(key, fallback) {
        const value = window.i18n ? i18n.t(key) : null;
        return value && value !== key ? value : fallback;
    },

    getTabOrderedSessionIds() {
        const tabs = this.getSessionTabsElement();
        const ordered = Array.from(tabs?.children || [])
            .map(tab => (String(tab.id || '').startsWith('tab-') ? tab.id.slice(4) : null))
            .filter(sessionId => sessionId && this.sessions[sessionId]);
        Object.keys(this.sessions).forEach(sessionId => {
            if (!ordered.includes(sessionId)) ordered.push(sessionId);
        });
        return ordered;
    },

    parkTerminalWrappers() {
        const container = document.getElementById('terminalsContainer');
        if (!container) {
            return;
        }
        Object.values(this.sessions).forEach(session => {
            const wrapper = document.getElementById(session.terminalId);
            if (wrapper && wrapper.parentElement !== container) {
                wrapper.classList.add('unassigned');
                container.appendChild(wrapper);
            }
        });
    },

    windowDesktopCallbacks() {
        return {
            label: key => (window.i18n ? i18n.t(key) : null),
            minSize: {width: TerminalWindows.MIN_WIDTH, height: TerminalWindows.MIN_HEIGHT},
            onActivate: index => this.setActivePane(index),
            onInteractionEnd: index => {
                if (index === this.activePaneIndex) this.focusWindowContent(index);
            },
            onMinimizeRequest: index => this.minimizeWindow(index),
            onCloseRequest: index => this.closeWindow(index),
            onMinimizeStart: index => {
                this.updateWindowTabState();
                if (index === this.activePaneIndex) this.activateTopWindow();
            },
            onMinimized: index => {
                this.renderPane(index);
                this.saveWindowLayouts();
            },
            onRestored: index => {
                this.renderPane(index);
                this.updateWindowTabState();
            },
            onLayout: (index, {final}) => this.syncWindowTerminal(index, final),
            onChange: () => this.saveWindowLayouts(),
            onReflow: () => this.scheduleWindowTerminalSync(),
            minimizeTarget: index => {
                const sessionId = this.paneAssignments[index];
                const tab = sessionId ? document.getElementById(`tab-${sessionId}`) : null;
                return tab?.getBoundingClientRect?.() || null;
            },
            renderEmpty: container => this.renderWindowDesktopEmpty(container),
        };
    },

    enterWindowMode() {
        const grid = this.ensureTerminalGrid();
        if (!grid || this.windowMode || typeof TerminalWindows === 'undefined') {
            return;
        }
        const focusedSessionId = this.getWorkspaceSession();
        const sessionIds = this.getTabOrderedSessionIds().slice(0, this.maxWindows);
        const saved = this.readWindowLayouts();

        this.parkTerminalWrappers();
        this.connectionLauncherSessions.clear();
        this.windowMode = true;
        this.layout = 'windows';
        this.paneAssignments = sessionIds.length ? sessionIds.slice() : [null];
        grid.className = 'terminal-grid window-mode';
        grid.innerHTML = '';
        this.windowDesktop = TerminalWindows.createDesktop(grid, this.windowDesktopCallbacks());

        const fresh = [];
        this.paneAssignments.forEach((sessionId, index) => {
            const layout = sessionId ? saved[sessionId] : null;
            this.windowDesktop.open(index, {
                ...(sessionId ? this.windowOpenConfig(layout) : {fraction: this.centeredWindowFraction()}),
                animate: false,
            });
            if (!layout) fresh.push(index);
        });
        if (sessionIds.length && fresh.length) {
            this.windowDesktop.arrange('tile', fresh, {animated: false});
        }
        sessionIds
            .map((sessionId, index) => ({index, z: Number(saved[sessionId]?.z ?? -1)}))
            .sort((a, b) => a.z - b.z)
            .forEach(item => this.windowDesktop.focus(item.index));

        this.paneAssignments.forEach((sessionId, index) => {
            this.renderPane(index);
            this.updateWindowChrome(index);
        });

        const focusedIndex = focusedSessionId ? this.paneAssignments.indexOf(focusedSessionId) : -1;
        this.updateSplitControls();
        if (focusedIndex !== -1 && !this.windowDesktop.isMinimized(focusedIndex)) {
            this.setActivePane(focusedIndex);
        } else {
            this.activateTopWindow();
        }
        this.scheduleWindowTerminalSync();
    },

    leaveWindowMode(layout = 1) {
        if (!this.windowMode) {
            return;
        }
        this.teardownWindowMode();
        this.buildSplitLayout(layout);
    },

    teardownWindowMode() {
        if (!this.windowMode) {
            return;
        }
        const ordered = this.getWindowStackOrder();
        this.saveWindowLayouts();
        clearTimeout(this.windowSyncTimer);
        this.windowSyncTimer = null;
        this.parkTerminalWrappers();
        this.windowDesktop?.destroy();
        this.windowDesktop = null;
        this.windowMode = false;
        this.connectionLauncherSessions.clear();
        this.paneAssignments = ordered;
        this.layout = null;
        this.activePaneIndex = 0;
        const grid = this.ensureTerminalGrid();
        if (grid) {
            grid.innerHTML = '';
            grid.className = 'terminal-grid';
        }
        this.updateWindowTabState();
        this.updateSplitControls();
    },

    // Front-most windows first, then minimized ones, so a split layout picks
    // up the sessions the user was looking at.
    getWindowStackOrder() {
        const desktop = this.windowDesktop;
        if (!desktop) {
            return this.paneAssignments.filter(Boolean);
        }
        const visible = desktop.visibleOrder().reverse();
        const hidden = desktop.order().reverse().filter(index => !visible.includes(index));
        return [...visible, ...hidden]
            .map(index => this.paneAssignments[index])
            .filter(sessionId => sessionId && this.sessions[sessionId]);
    },

    centeredWindowFraction() {
        const bounds = this.windowDesktop.bounds();
        const size = TerminalWindows.defaultSize(bounds);
        return TerminalWindows.toFraction({
            x: Math.round((bounds.width - size.width) / 2),
            y: Math.max(16, Math.round((bounds.height - size.height) / 2) - 16),
            width: size.width,
            height: size.height,
        }, bounds);
    },

    windowOpenConfig(layout) {
        if (!layout || typeof layout !== 'object') {
            return {};
        }
        return {
            fraction: layout.fraction,
            restoreFraction: layout.restoreFraction,
            maximized: layout.maximized === true,
            minimized: layout.minimized === true,
        };
    },

    openWindowForSlot(index, sessionId, {slotWasEmpty = false} = {}) {
        const desktop = this.windowDesktop;
        if (!desktop) {
            return;
        }
        const layout = this.readWindowLayouts()[sessionId];
        // A restored session reclaims its own placement, even when it lands
        // in the launcher window that was waiting for it.
        if (!desktop.isOpen(index) || (layout && slotWasEmpty)) {
            desktop.open(index, this.windowOpenConfig(layout));
        }
    },

    allocateWindowSlot({render = true} = {}) {
        const desktop = this.windowDesktop;
        if (!desktop) {
            return -1;
        }
        const openCount = this.paneAssignments.filter((_, index) => desktop.isOpen(index)).length;
        if (openCount >= this.maxWindows) {
            return -1;
        }
        let index = this.paneAssignments.findIndex(
            (sessionId, slot) => !sessionId && !desktop.isOpen(slot)
        );
        if (index === -1) {
            index = this.paneAssignments.length;
            this.paneAssignments.push(null);
        }
        desktop.open(index, desktop.visibleOrder().length ? {} : {
            fraction: this.centeredWindowFraction(),
        });
        if (render) {
            this.renderPane(index);
            this.updateWindowChrome(index);
        }
        return index;
    },

    openNewWindow() {
        if (!this.windowMode) {
            return -1;
        }
        const emptyIndex = this.getFirstEmptyPaneIndex();
        if (emptyIndex !== -1) {
            this.setActivePane(emptyIndex);
            return emptyIndex;
        }
        const index = this.allocateWindowSlot();
        if (index === -1) {
            window.showNotification?.(
                this.windowText('windows.limitReached', 'Close a window to open another one.'),
                'info',
            );
            return -1;
        }
        this.setActivePane(index);
        return index;
    },

    minimizeWindow(index) {
        if (!this.windowMode || !this.paneAssignments[index]) {
            return false;
        }
        return Boolean(this.windowDesktop?.minimize(index));
    },

    closeWindow(index) {
        if (!this.windowMode || !this.windowDesktop?.isOpen(index)) {
            return;
        }
        if (this.connectionLauncherSessions.has(index)) {
            this.restoreConnectionLauncher(index);
            return;
        }
        const sessionId = this.paneAssignments[index];
        if (sessionId && this.sessions[sessionId]) {
            this.requestCloseSession(sessionId);
            return;
        }
        this.closeWindowSlot(index);
    },

    closeWindowSlot(index, {activate = true} = {}) {
        const desktop = this.windowDesktop;
        if (!desktop) {
            return;
        }
        this.connectionLauncherSessions.delete(index);
        if (index < this.paneAssignments.length) {
            this.paneAssignments[index] = null;
        }
        desktop.close(index);
        while (this.paneAssignments.length
                && !this.paneAssignments[this.paneAssignments.length - 1]
                && !desktop.isOpen(this.paneAssignments.length - 1)) {
            this.paneAssignments.pop();
        }
        if (activate) {
            this.activateTopWindow();
        }
        this.updateWindowTabState();
    },

    activateTopWindow() {
        const top = this.windowDesktop?.topMost();
        if (top !== null && top !== undefined) {
            this.setActivePane(top);
            return;
        }
        this.activeSessionId = null;
        this.updateSessionMeta(null);
        document.querySelectorAll('.session-tab.active').forEach(tab => {
            tab.classList.remove('active');
        });
        this.windowDesktop?.refreshEmpty({rerender: true});
        this.updateWindowTabState();
        this.notifyWorkspaceChange();
    },

    focusWindowContent(index) {
        if (this.connectionLauncherSessions.has(index) || !this.paneAssignments[index]) {
            this.focusConnectionLauncher(index);
        } else {
            this.focusActivePane();
        }
    },

    arrangeWindows(mode) {
        const desktop = this.windowDesktop;
        if (!this.windowMode || !desktop) {
            return;
        }
        // Arrange in tab order; a cascade keeps the focused window on top.
        const visible = desktop.visibleOrder();
        const ordered = [
            ...this.getTabOrderedSessionIds().map(sessionId => this.paneAssignments.indexOf(sessionId)),
            ...this.paneAssignments.map((sessionId, index) => (sessionId ? -1 : index)),
        ].filter((index, position, list) => (
            visible.includes(index) && list.indexOf(index) === position
        ));
        if (mode === 'cascade' && ordered.includes(this.activePaneIndex)) {
            ordered.splice(ordered.indexOf(this.activePaneIndex), 1);
            ordered.push(this.activePaneIndex);
        }
        desktop.arrange(mode === 'cascade' ? 'cascade' : 'tile', ordered);
        const top = this.windowDesktop.topMost();
        if (top !== null && top !== this.activePaneIndex) {
            this.setActivePane(top);
        }
        this.saveWindowLayouts();
    },

    updateWindowTabState() {
        Object.keys(this.sessions).forEach(sessionId => {
            const tab = document.getElementById(`tab-${sessionId}`);
            if (!tab) return;
            const index = this.windowMode ? this.paneAssignments.indexOf(sessionId) : -1;
            tab.classList.toggle(
                'is-minimized',
                index !== -1 && Boolean(this.windowDesktop?.isMinimized(index)),
            );
        });
    },

    refreshWindowChrome(sessionId) {
        if (!this.windowMode) {
            return;
        }
        const index = this.paneAssignments.indexOf(sessionId);
        if (index !== -1) {
            this.updateWindowChrome(index);
        }
    },

    updateWindowChrome(index) {
        if (!this.windowMode || !this.windowDesktop?.isOpen(index)) {
            return;
        }
        const sessionId = this.paneAssignments[index];
        const session = sessionId ? this.sessions[sessionId] : null;
        if (!session || this.connectionLauncherSessions.has(index)) {
            this.windowDesktop.setChrome(index, {
                title: this.windowText('windows.newConnection', 'New connection'),
                subtitle: this.windowText(
                    'windows.newConnectionHint', 'Pick a saved host or use Quick Connect'
                ),
                status: 'idle',
                minimizable: false,
            });
            return;
        }
        const dot = document.getElementById(`tab-${sessionId}`)?.querySelector('.status-dot');
        const status = dot?.classList.contains('connecting')
            ? 'connecting'
            : (session.connected ? 'connected' : 'disconnected');
        const parts = [session.displayName
            ? `${session.username}@${session.host}:${session.port}`
            : `SSH · ${session.port}`];
        if (session.viaJump) {
            parts.push(`${this.windowText('connection.via', 'via')} ${session.viaJump}`);
        }
        const badges = [];
        if (session.useTmux) {
            badges.push({
                icon: 'push_pin',
                title: session.tmuxSessionName ? `tmux: ${session.tmuxSessionName}` : 'tmux',
            });
        }
        this.windowDesktop.setChrome(index, {
            title: this.getDisplayLabel(sessionId, session.username, session.host),
            subtitle: parts.join('  ·  '),
            status,
            badges,
            closeLabel: this.windowText('session.close', 'Close session'),
        });
    },

    renderWindowDesktopEmpty(container) {
        const hasSessions = Object.keys(this.sessions).length > 0;
        const icon = document.createElement('span');
        icon.className = 'ws-desktop-empty-icon material-icons';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = hasSessions ? 'web_asset_off' : 'web_asset';
        const title = document.createElement('h2');
        title.textContent = this.windowText('windows.emptyTitle', 'No open windows');
        const text = document.createElement('p');
        text.textContent = hasSessions
            ? this.windowText(
                'windows.emptyMinimized',
                'Your sessions are minimized. Pick one from the tabs above to bring it back.',
            )
            : this.windowText('windows.emptyHint', 'Open a connection to start a terminal window.');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-primary ws-desktop-empty-action';
        const buttonIcon = document.createElement('span');
        buttonIcon.className = 'material-icons';
        buttonIcon.setAttribute('aria-hidden', 'true');
        buttonIcon.textContent = 'add';
        const buttonLabel = document.createElement('span');
        buttonLabel.textContent = this.windowText('windows.newWindow', 'New window');
        button.append(buttonIcon, buttonLabel);
        button.addEventListener('click', () => this.openNewWindow());
        container.append(icon, title, text, button);
    },

    // Live resizes refit locally; the remote PTY learns the size once the
    // gesture settles so full-screen programs redraw once, not per frame.
    syncWindowTerminal(index, final) {
        const sessionId = this.paneAssignments[index];
        if (!sessionId || this.connectionLauncherSessions.has(index)
                || this.windowDesktop?.isMinimized(index)) {
            return;
        }
        if (!final) {
            TerminalManager.fitTerminal?.(sessionId);
            this.scheduleWindowTerminalSync(400);
            return;
        }
        TerminalManager.fitAndSyncVisibleTerminals?.({
            socket: window.socket,
            isConnected: candidateId => (
                candidateId === sessionId && Boolean(this.sessions[sessionId]?.connected)
            ),
        });
    },

    scheduleWindowTerminalSync(delay = 120) {
        clearTimeout(this.windowSyncTimer);
        this.windowSyncTimer = setTimeout(() => {
            this.windowSyncTimer = null;
            if (!this.windowMode) return;
            TerminalManager.fitAndSyncVisibleTerminals?.({
                socket: window.socket,
                isConnected: sessionId => Boolean(this.sessions[sessionId]?.connected),
            });
        }, delay);
    },

    windowLayoutStorageKey() {
        const scope = this.displayNameScope();
        return scope ? `${this.windowLayoutStoragePrefix}${scope}` : null;
    },

    readWindowLayouts() {
        const key = this.windowLayoutStorageKey();
        if (!key) return {};
        try {
            const value = JSON.parse(window.sessionStorage?.getItem(key) || '{}');
            return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
        } catch {
            return {};
        }
    },

    writeWindowLayouts(layouts) {
        const key = this.windowLayoutStorageKey();
        if (!key) return;
        try {
            const entries = Object.entries(layouts).slice(-32);
            window.sessionStorage?.setItem(key, JSON.stringify(Object.fromEntries(entries)));
        } catch {
            // Window placement is a convenience; the workspace works without it.
        }
    },

    saveWindowLayouts() {
        if (!this.windowMode || !this.windowDesktop) {
            return;
        }
        const layouts = this.readWindowLayouts();
        this.paneAssignments.forEach((sessionId, index) => {
            const snapshot = sessionId ? this.windowDesktop.snapshot(index) : null;
            if (snapshot) {
                delete layouts[sessionId];
                layouts[sessionId] = snapshot;
            }
        });
        this.writeWindowLayouts(layouts);
    },

    forgetWindowLayout(sessionId) {
        const layouts = this.readWindowLayouts();
        if (!Object.prototype.hasOwnProperty.call(layouts, sessionId)) return;
        delete layouts[sessionId];
        this.writeWindowLayouts(layouts);
    }
};
