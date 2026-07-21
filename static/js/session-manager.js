const SessionManager = {
    sessions: {},
    activeSessionId: null,
    pendingConnections: {},
    layout: 1,
    paneAssignments: [],
    activePaneIndex: 0,

    init() {
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
        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }
        this.updateSessionMeta(null);
    },

    restoreSession(data) {
        const sessionId = data.session_id;

        console.log(`[RESTORE] Restoring SSH session: ${sessionId}`, data);

        if (this.sessions[sessionId]) {
            console.log(`[RESTORE] Session ${sessionId} already exists, skipping restore`);
            return;
        }

        const sessionData = {
            session_id: sessionId,
            host: data.host,
            port: data.port,
            username: data.username,
            auth_type: data.auth_type,
            via_jump: data.via_jump,
            display_name: data.display_name
        };

        const restoredId = this.createSession(sessionData);
        console.log(`[RESTORE] Session UI created for ${sessionId}`);

        const emptyIndex = this.getFirstEmptyPaneIndex();
        const targetPane = emptyIndex !== -1 ? emptyIndex : this.activePaneIndex;
        this.assignSessionToPane(restoredId, targetPane);

        // Write buffered output to the restored terminal
        if (data.buffered_output) {
            setTimeout(() => {
                TerminalManager.writeOutput(sessionId, data.buffered_output);
            }, 200);
        }

        console.log(`[RESTORE] Session ${sessionId} fully restored - waiting for output`);
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

        document.getElementById('noSessions').classList.add('hidden');
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
            viaJump: null,
            useTmux: true,
            tmuxSessionName: tmux_session_name,
            isPersistentCandidate: true,
            keyId: key_id,
            authType: auth_type || 'password'
        };

        // Save display name to localStorage by host:port:user key
        if (display_name) {
            try {
                const stored = JSON.parse(localStorage.getItem('sessionDisplayNames') || '{}');
                const hostKey = `${host}:${port}:${username}`;
                stored[hostKey] = display_name;
                localStorage.setItem('sessionDisplayNames', JSON.stringify(stored));
            } catch (e) {}
        }

        this.createSessionTab(session_id, host, username);
        this.updateSessionStatus(session_id, 'disconnected');

        const emptyIndex = this.getFirstEmptyPaneIndex();
        const targetPane = emptyIndex !== -1 ? emptyIndex : this.activePaneIndex;
        this.assignSessionToPane(session_id, targetPane);

        console.log(`[PERSISTENT] Showing persistent tmux session tab: ${host}:${port} (${session_id})`);
    },

    createSession(sessionData) {
        const { session_id, host, port, username, display_name } = sessionData;

        const terminalId = `terminal-${session_id}`;
        const terminalContainer = document.createElement('div');
        terminalContainer.id = terminalId;
        terminalContainer.className = 'terminal-wrapper unassigned';
        document.getElementById('terminalsContainer').appendChild(terminalContainer);

        TerminalManager.createTerminal(session_id);
        TerminalManager.attachTerminal(session_id, terminalId);
        TerminalManager.setupInputHandler(session_id, (data) => {
            if (window.socket) {
                // Filter out Device Attributes responses (ESC[c sequences only).
                // Bare-pattern regexes were removed because they corrupt legitimate input.
                data = data.replace(/\x1b\[[?>]?[0-9;]*c/g, '');
                if (data) {
                    window.socket.emit('ssh_input', {
                        session_id: session_id,
                        data: data
                    });
                }
            }
        });

        document.getElementById('noSessions').classList.add('hidden');
        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }

        const fallbackKey = `${host}:${port}:${username}`;
        const fallbackName = this.pendingDisplayNames ? this.pendingDisplayNames[fallbackKey] : null;
        const storedName = display_name || this.pendingDisplayName || fallbackName || this.getStoredDisplayName(session_id, host, port, username);
        console.log(`[CREATE] createSession: display_name="${display_name}", pendingDisplayName="${this.pendingDisplayName}", fallbackName="${fallbackName}", storedName="${storedName}"`);
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
            terminalId,
            os: 'all',
            displayName: storedName || null,
            viaJump: sessionData.via_jump || null,
            useTmux: sessionData.use_tmux || false,
            tmuxSessionName: sessionData.tmux_session_name || null,
            keyId: sessionData.key_id || null,
            authType: sessionData.auth_type || 'password'
        };

        this.createSessionTab(session_id, host, username);
        this.updateSessionStatus(session_id, 'connected');

        this.hideReconnectOverlay(session_id);

        return session_id;
    },

    createSessionTab(sessionId, host, username) {
        const tab = document.createElement('div');
        tab.className = 'session-tab';
        tab.id = `tab-${sessionId}`;

        const statusDot = document.createElement('span');
        statusDot.className = 'status-dot connected';

        const tabLabel = document.createElement('span');
        tabLabel.className = 'tab-label';
        this.renderTabLabelContent(tabLabel, sessionId);

        const tabEdit = document.createElement('span');
        tabEdit.className = 'tab-edit';
        tabEdit.innerHTML = '✎';
        const renameLabel = window.i18n ? i18n.t('session.rename') : 'Rename session';
        tabEdit.setAttribute('aria-label', renameLabel);
        tabEdit.setAttribute('title', renameLabel);
        tabEdit.dataset.i18nAriaLabel = 'session.rename';
        tabEdit.dataset.i18nTitle = 'session.rename';

        const tabClose = document.createElement('span');
        tabClose.className = 'tab-close';
        tabClose.dataset.sessionId = sessionId;
        tabClose.innerHTML = '&times;';
        tabClose.setAttribute('aria-label', window.i18n ? i18n.t('session.close') : 'Close session');
        tabClose.dataset.i18nAriaLabel = 'session.close';

        tab.appendChild(statusDot);
        tab.appendChild(tabLabel);
        const sess = this.sessions[sessionId];
        if (sess && sess.viaJump) {
            const jumpBadge = document.createElement('span');
            jumpBadge.className = 'tab-jump-badge';
            jumpBadge.textContent = '🛰️';
            jumpBadge.title = 'via ' + sess.viaJump;
            tab.appendChild(jumpBadge);
        }
        if (sess && sess.useTmux) {
            const tmuxBadge = document.createElement('span');
            tmuxBadge.className = 'tab-tmux-badge';
            tmuxBadge.textContent = '📌';
            tmuxBadge.title = 'Persistent tmux session' + (sess.tmuxSessionName ? ': ' + sess.tmuxSessionName : '');
            tab.appendChild(tmuxBadge);
        }
        const tabReconnect = document.createElement('span');
        tabReconnect.className = 'tab-reconnect';
        tabReconnect.innerHTML = '⟳';
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
    },

    switchSession(sessionId) {
        if (!this.sessions[sessionId]) {
            console.error('Session not found:', sessionId);
            return;
        }

        const assignedIndex = this.paneAssignments.findIndex(id => id === sessionId);
        if (assignedIndex !== -1) {
            this.setActivePane(assignedIndex);
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

    removeSessionUI(sessionId) {
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
            this.paneAssignments[paneIndex] = null;
            this.renderPane(paneIndex);
        }

        delete this.sessions[sessionId];

        const remainingSessions = Object.keys(this.sessions);
        if (remainingSessions.length > 0) {
            const assignedIndex = this.paneAssignments.findIndex(id => id);
            if (assignedIndex !== -1) {
                this.setActivePane(assignedIndex);
            } else {
                this.setActivePane(this.activePaneIndex);
            }
        } else {
            this.activeSessionId = null;
            document.getElementById('noSessions').classList.remove('hidden');
            this.updateSessionMeta(null);
        }
    },

    requestCloseSession(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
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
                this.pendingDisplayNames[`${host}:${port}:${username}`] = displayName;
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

        if (status === 'disconnected') {
            this.showReconnectOverlay(sessionId);
        } else if (status === 'connected') {
            this.hideReconnectOverlay(sessionId);
        }
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

        const tabClose = document.createElement('span');
        tabClose.className = 'tab-close';
        tabClose.dataset.pendingId = requestId;
        tabClose.innerHTML = '&times;';
        tabClose.setAttribute('aria-label', 'Cancel connection');

        tab.appendChild(statusDot);
        tab.appendChild(tabLabel);
        tab.appendChild(tabClose);

        tabClose.addEventListener('click', (e) => {
            e.stopPropagation();
            this.clearPendingConnection(requestId);
        });

        document.getElementById('sessionTabs').appendChild(tab);
        this.pendingConnections[requestId] = { host, username, port };
    },

    clearPendingConnection(requestId) {
        const tab = document.getElementById(`pending-${requestId}`);
        if (tab) {
            tab.remove();
        }
        delete this.pendingConnections[requestId];
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

        const finishRename = (save) => {
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
        // Save to localStorage by session ID
        try {
            const stored = JSON.parse(localStorage.getItem('sessionDisplayNames') || '{}');
            if (displayName) {
                stored[sessionId] = displayName;
            } else {
                delete stored[sessionId];
            }
            // Also save by host:port:user key so it survives session ID changes
            if (session) {
                const hostKey = `${session.host}:${session.port}:${session.username}`;
                if (displayName) {
                    stored[hostKey] = displayName;
                } else {
                    delete stored[hostKey];
                }
            }
            localStorage.setItem('sessionDisplayNames', JSON.stringify(stored));
        } catch (e) {
            console.error('Failed to save session display name:', e);
        }
        // Save to server DB
        if (window.socket) {
            window.socket.emit('save_session_name', {
                session_id: sessionId,
                display_name: displayName
            });
        }
    },

    getStoredDisplayName(sessionId, host, port, username) {
        try {
            const stored = JSON.parse(localStorage.getItem('sessionDisplayNames') || '{}');
            // Check by session ID first
            if (stored[sessionId]) return stored[sessionId];
            // Check by host:port:user key (persists across session ID changes)
            if (host && port && username) {
                const hostKey = `${host}:${port}:${username}`;
                if (stored[hostKey]) return stored[hostKey];
            }
            return null;
        } catch (e) {
            return null;
        }
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

    setSplitLayout(layout) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }
        if (this.layout === layout && this.paneAssignments.length === layout) {
            this.updateSplitControls();
            return;
        }

        const previousAssignments = this.paneAssignments.slice();
        this.layout = layout;
        this.paneAssignments = new Array(layout).fill(null);
        for (let i = 0; i < layout; i++) {
            this.paneAssignments[i] = previousAssignments[i] || null;
        }

        const container = document.getElementById('terminalsContainer');
        if (container) {
            Object.values(this.sessions).forEach(session => {
                const wrapper = document.getElementById(session.terminalId);
                if (wrapper && wrapper.parentElement !== container) {
                    wrapper.classList.add('unassigned');
                    container.appendChild(wrapper);
                }
            });
        }

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
    },

    renderPane(paneIndex) {
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }
        const pane = grid.querySelector(`.terminal-pane[data-pane-index="${paneIndex}"]`);
        if (!pane) {
            return;
        }
        pane.innerHTML = '';

        const sessionId = this.paneAssignments[paneIndex];
        if (sessionId) {
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
            return;
        }

        const empty = document.createElement('div');
        empty.className = 'pane-empty';

        const icon = document.createElement('div');
        icon.className = 'pane-empty-icon';
        icon.textContent = '💻';
        empty.appendChild(icon);

        const emptyText = document.createElement('div');
        emptyText.className = 'pane-empty-text';
        emptyText.textContent = window.i18n ? window.i18n.t('panes.emptyPane') : 'Empty pane';
        empty.appendChild(emptyText);

        const button = document.createElement('button');
        button.className = 'btn btn-primary';
        button.textContent = window.i18n ? window.i18n.t('connection.newConnection') : 'New connection';
        button.addEventListener('click', () => {
            if (window.openConnectionModalForPane) {
                window.openConnectionModalForPane(paneIndex);
            }
        });
        empty.appendChild(button);
        pane.appendChild(empty);
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

        const clearedIndices = [];
        this.paneAssignments = this.paneAssignments.map((existing, index) => {
            if (existing === sessionId) {
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
        this.renderPane(paneIndex);
        clearedIndices.forEach(index => {
            if (index !== paneIndex) {
                this.renderPane(index);
            }
        });
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
        this.activePaneIndex = paneIndex;
        grid.querySelectorAll('.terminal-pane').forEach(pane => {
            pane.classList.toggle('active', pane.dataset.paneIndex === String(paneIndex));
        });

        const sessionId = this.paneAssignments[paneIndex] || null;
        this.activeSessionId = sessionId;
        this.updateSessionMeta(sessionId);

        document.querySelectorAll('.session-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        if (sessionId) {
            const tab = document.getElementById(`tab-${sessionId}`);
            if (tab) {
                tab.classList.add('active');
            }
        }
        this.focusActivePane();

        if (sessionId) {
            setTimeout(() => {
                TerminalManager.fitTerminal(sessionId);
                const size = TerminalManager.getTerminalSize(sessionId);
                if (size && window.socket) {
                    window.socket.emit('ssh_resize', {
                        session_id: sessionId,
                        rows: size.rows,
                        cols: size.cols
                    });
                }
            }, 50);
        }
    },

    focusActivePane() {
        const sessionId = this.paneAssignments[this.activePaneIndex];
        if (!sessionId) {
            return;
        }
        const terminal = TerminalManager.terminals[sessionId];
        if (terminal) {
            terminal.focus();
        }
    },

    getActiveTerminal() {
        const sessionId = this.paneAssignments[this.activePaneIndex];
        if (!sessionId) {
            return null;
        }
        return TerminalManager.terminals[sessionId] || null;
    },

    getActivePaneIndex() {
        return this.activePaneIndex;
    },

    getFirstEmptyPaneIndex() {
        return this.paneAssignments.findIndex(sessionId => !sessionId);
    },

    getEmptyPaneIndices() {
        return this.paneAssignments
            .map((sessionId, index) => (sessionId ? null : index))
            .filter(index => index !== null);
    },

    updateSplitControls() {
        document.querySelectorAll('.split-btn').forEach(btn => {
            const layout = parseInt(btn.dataset.layout, 10);
            btn.classList.toggle('active', layout === this.layout);
        });
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

            const button = document.createElement('button');
            button.className = 'btn btn-primary';
            button.dataset.sessionId = sessionId;
            button.dataset.i18n = isPersistent ? 'session.reconnect' : 'session.retry';
            button.textContent = isPersistent
                ? (window.i18n ? i18n.t('session.reconnect') : 'Reconnect')
                : (window.i18n ? i18n.t('session.retry') : 'Retry');
            button.addEventListener('click', () => {
                this.prefillConnectionForm(sessionId);
            });
            card.appendChild(button);

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

    prefillConnectionForm(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) {
            return;
        }

        const authType = session.authType || (session.keyId ? 'key' : 'password');

        // Key and Tailscale persistent sessions can reconnect directly without
        // opening the connection modal.
        if (session.isPersistentCandidate && session.useTmux
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
                this.pendingDisplayNames[`${session.host}:${session.port}:${session.username}`] = session.displayName;
            }
            this.pendingReconnectTmux = session.useTmux ? session.tmuxSessionName : null;
            this.removeSessionUI(sessionId);
        }

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

        const host = session.host;
        const port = session.port;
        const username = session.username;
        const keyId = session.keyId;
        const authType = session.authType || (keyId ? 'key' : 'password');
        const tmuxSessionName = session.tmuxSessionName;
        const displayName = session.displayName;

        console.log(`[RECONNECT] directReconnect: displayName="${displayName}", host=${host}, tmux=${tmuxSessionName}`);

        // Store display name BEFORE removing UI so it survives the reconnect
        this.pendingDisplayName = displayName;
        // Also store by host:port:user as a fallback key
        if (displayName) {
            this.pendingDisplayNames = this.pendingDisplayNames || {};
            this.pendingDisplayNames[`${host}:${port}:${username}`] = displayName;
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
                window.i18n ? window.i18n.t('panes.newConnection') : '+ New Connection',
                window.i18n ? window.i18n.t('panes.newConnectionDesc') : 'Open connection dialog for this pane',
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

        this.layout = layout;
        this.paneAssignments = new Array(layout).fill(null);

        const container = document.getElementById('terminalsContainer');
        if (container) {
            Object.values(this.sessions).forEach(session => {
                const wrapper = document.getElementById(session.terminalId);
                if (wrapper && wrapper.parentElement !== container) {
                    wrapper.classList.add('unassigned');
                    container.appendChild(wrapper);
                }
            });
        }

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
    }
};
