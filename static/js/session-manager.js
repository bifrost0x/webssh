// Session Manager - Manages multiple SSH sessions
const SessionManager = {
    sessions: {},
    activeSessionId: null,
    pendingConnections: {},
    layout: 1,
    paneAssignments: [],
    activePaneIndex: 0,

    // Initialize event listeners for session restore
    init() {
        if (window.socket) {
            window.socket.on('ssh_session_restored', (data) => {
                this.restoreSession(data);
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

        // Don't restore if session already exists
        if (this.sessions[sessionId]) {
            console.log(`[RESTORE] Session ${sessionId} already exists, skipping restore`);
            return;
        }

        // Create session data structure
        const sessionData = {
            session_id: sessionId,
            host: data.host,
            port: data.port,
            username: data.username
        };

        // Create the session UI (terminal, tab, etc.)
        const restoredId = this.createSession(sessionData);
        console.log(`[RESTORE] Session UI created for ${sessionId}`);

        const emptyIndex = this.getFirstEmptyPaneIndex();
        const targetPane = emptyIndex !== -1 ? emptyIndex : this.activePaneIndex;
        this.assignSessionToPane(restoredId, targetPane);

        console.log(`[RESTORE] Session ${sessionId} fully restored - waiting for output`);

        // CRITICAL FIX: Send a newline to trigger the shell prompt and verify connection
        setTimeout(() => {
            console.log(`[RESTORE] Sending keepalive newline to session ${sessionId}`);
            window.socket.emit('ssh_input', {
                session_id: sessionId,
                data: '\n'
            });
        }, 500);

        // OS detection removed to avoid terminal noise.
    },

    createSession(sessionData) {
        const { session_id, host, port, username } = sessionData;

        // Create terminal container
        const terminalId = `terminal-${session_id}`;
        const terminalContainer = document.createElement('div');
        terminalContainer.id = terminalId;
        terminalContainer.className = 'terminal-wrapper unassigned';
        document.getElementById('terminalsContainer').appendChild(terminalContainer);

        TerminalManager.createTerminal(session_id);
        TerminalManager.attachTerminal(session_id, terminalId);
        TerminalManager.setupInputHandler(session_id, (data) => {
            if (window.socket) {
                window.socket.emit('ssh_input', {
                    session_id: session_id,
                    data: data
                });
            }
        });

        // Hide "no sessions" message
        document.getElementById('noSessions').classList.add('hidden');
        const sessionBar = document.getElementById('sessionBar');
        if (sessionBar) {
            sessionBar.classList.remove('hidden');
        }

        // Store session data
        const storedName = this.getStoredDisplayName(session_id);
        this.sessions[session_id] = {
            id: session_id,
            host,
            port,
            username,
            connected: true,
            terminalId,
            os: 'all',  // Default to 'all', will be detected later
            displayName: storedName || null
        };

        // Create session tab
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

        // Security Fix: Use textContent to prevent XSS
        const tabLabel = document.createElement('span');
        tabLabel.className = 'tab-label';
        tabLabel.textContent = this.getDisplayLabel(sessionId, username, host);

        // Edit icon for renaming
        const tabEdit = document.createElement('span');
        tabEdit.className = 'tab-edit';
        tabEdit.innerHTML = '✎';
        tabEdit.setAttribute('aria-label', 'Rename session');
        tabEdit.setAttribute('title', 'Rename session');

        const tabClose = document.createElement('span');
        tabClose.className = 'tab-close';
        tabClose.dataset.sessionId = sessionId;
        tabClose.innerHTML = '&times;';
        tabClose.setAttribute('aria-label', 'Close session');

        tab.appendChild(statusDot);
        tab.appendChild(tabLabel);
        tab.appendChild(tabEdit);
        tab.appendChild(tabClose);

        // Click tab to switch session
        tab.addEventListener('click', () => {
            this.switchSession(sessionId);
        });

        // Double-click on label to rename
        tabLabel.addEventListener('dblclick', (e) => {
            e.stopPropagation();
            this.startRenameSession(sessionId, tabLabel);
        });

        // Edit icon click to rename
        tabEdit.addEventListener('click', (e) => {
            e.stopPropagation();
            this.startRenameSession(sessionId, tabLabel);
        });

        // Close button
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

        // Send disconnect to backend
        if (window.socket) {
            window.socket.emit('ssh_disconnect', { session_id: sessionId });
        }

        // Remove terminal
        const terminalContainer = document.getElementById(this.sessions[sessionId].terminalId);
        if (terminalContainer) {
            terminalContainer.remove();
        }

        // Destroy terminal instance
        TerminalManager.destroyTerminal(sessionId);

        // Remove tab
        const tab = document.getElementById(`tab-${sessionId}`);
        if (tab) {
            tab.remove();
        }

        const paneIndex = this.paneAssignments.findIndex(id => id === sessionId);
        if (paneIndex !== -1) {
            this.paneAssignments[paneIndex] = null;
            this.renderPane(paneIndex);
        }

        // Remove from sessions
        delete this.sessions[sessionId];

        // Switch to another session or show "no sessions"
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
        if (confirm(`Close session "${label}"?`)) {
            this.closeSession(sessionId);
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
            label.textContent = this.getDisplayLabel(sessionId, session.username, session.host);
        }
    },

    startRenameSession(sessionId, labelElement) {
        const session = this.sessions[sessionId];
        if (!session) return;

        // Create inline input
        const currentName = session.displayName || `${session.username}@${session.host}`;
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'tab-rename-input';
        input.value = currentName;
        input.placeholder = `${session.username}@${session.host}`;

        // Replace label with input
        const originalText = labelElement.textContent;
        labelElement.textContent = '';
        labelElement.appendChild(input);
        input.focus();
        input.select();

        const finishRename = (save) => {
            const newName = input.value.trim();
            labelElement.removeChild(input);

            if (save && newName && newName !== `${session.username}@${session.host}`) {
                session.displayName = newName;
                labelElement.textContent = newName;
                // Save to localStorage for persistence
                this.saveSessionDisplayName(sessionId, newName);
            } else if (save && !newName) {
                // Reset to default if empty
                session.displayName = null;
                labelElement.textContent = `${session.username}@${session.host}`;
                this.saveSessionDisplayName(sessionId, null);
            } else {
                labelElement.textContent = originalText;
            }
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

        // Prevent tab click from switching session while renaming
        input.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    },

    saveSessionDisplayName(sessionId, displayName) {
        try {
            const stored = JSON.parse(localStorage.getItem('sessionDisplayNames') || '{}');
            if (displayName) {
                stored[sessionId] = displayName;
            } else {
                delete stored[sessionId];
            }
            localStorage.setItem('sessionDisplayNames', JSON.stringify(stored));
        } catch (e) {
            console.error('Failed to save session display name:', e);
        }
    },

    getStoredDisplayName(sessionId) {
        try {
            const stored = JSON.parse(localStorage.getItem('sessionDisplayNames') || '{}');
            return stored[sessionId] || null;
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

        // Show connection info instead of notes
        const connInfo = `${session.username}@${session.host}:${session.port}`;
        notesEl.textContent = connInfo;
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
            overlay.innerHTML = `
                <div class="session-overlay-card">
                    <h3>Session disconnected</h3>
                    <p>Reconnect to resume your work.</p>
                    <button class="btn btn-primary" data-session-id="${sessionId}">Retry</button>
                </div>
            `;
            container.appendChild(overlay);
            const button = overlay.querySelector('button');
            button.addEventListener('click', () => {
                this.prefillConnectionForm(sessionId);
            });
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
        const modal = document.getElementById('connectionModal');
        if (window.ModalManager && modal) {
            window.ModalManager.open(modal);
        } else if (modal) {
            modal.classList.add('show');
        }
    },

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

    // Show pane assignment modal for selecting sessions when changing layouts
    showPaneAssignmentModal(targetLayout) {
        const modal = document.getElementById('paneAssignmentModal');
        if (!modal) {
            return;
        }

        const list = document.getElementById('paneAssignmentList');
        if (!list) {
            return;
        }

        // Store current assignments as defaults
        const currentAssignments = this.paneAssignments.slice();
        const tempAssignments = new Array(targetLayout).fill(null);

        // Preserve existing assignments that fit in new layout
        for (let i = 0; i < Math.min(targetLayout, currentAssignments.length); i++) {
            tempAssignments[i] = currentAssignments[i];
        }

        // Build the UI
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

            // Empty option
            const emptyOption = this.createPaneOption(
                paneIndex,
                null,
                window.i18n ? window.i18n.t('panes.empty') : 'Empty',
                window.i18n ? window.i18n.t('panes.emptyDesc') : 'Leave this pane empty',
                tempAssignments[paneIndex] === null
            );
            optionsContainer.appendChild(emptyOption);

            // Session options
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

            // New connection option
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

        // Set up event handlers
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
            // Collect selections
            const newAssignments = [];
            for (let i = 0; i < targetLayout; i++) {
                const selected = list.querySelector(`input[name="pane-${i}"]:checked`);
                if (selected) {
                    const value = selected.value;
                    if (value === '__empty__') {
                        newAssignments[i] = null;
                    } else if (value === '__new__') {
                        newAssignments[i] = null; // Will trigger new connection
                    } else {
                        newAssignments[i] = value;
                    }
                } else {
                    newAssignments[i] = null;
                }
            }

            // Apply the new layout
            this.applyPaneAssignments(targetLayout, newAssignments);

            // Handle new connection requests
            for (let i = 0; i < targetLayout; i++) {
                const selected = list.querySelector(`input[name="pane-${i}"]:checked`);
                if (selected && selected.value === '__new__') {
                    // Queue new connection for this pane
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

        // Open modal
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

        // Toggle selected class on click
        option.addEventListener('click', () => {
            const allOptions = option.parentElement.querySelectorAll('.pane-option');
            allOptions.forEach(opt => opt.classList.remove('selected'));
            option.classList.add('selected');
        });

        return option;
    },

    applyPaneAssignments(layout, assignments) {
        // First, set the layout
        const grid = this.ensureTerminalGrid();
        if (!grid) {
            return;
        }

        this.layout = layout;
        this.paneAssignments = new Array(layout).fill(null);

        // Move all terminals back to container
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

        // Rebuild grid
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

        // Apply assignments
        for (let i = 0; i < layout; i++) {
            if (assignments[i]) {
                this.paneAssignments[i] = assignments[i];
            }
            this.renderPane(i);
        }

        // Set active pane
        if (this.activePaneIndex >= layout) {
            this.activePaneIndex = 0;
        }
        this.setActivePane(this.activePaneIndex);
        this.updateSplitControls();
    }
};
