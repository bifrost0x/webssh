const CommandLibrary = {
    commands: [],
    filteredCommands: [],
    currentOs: 'all',
    editingCommandId: null,
    detectingOsForSession: null,
    renderCursor: 0,
    chunkSize: 40,

    init() {
        this.loadCommands();

        if (window.socket) {
            window.socket.on('commands_list', (data) => {
                this.setCommands(data.commands);
            });

            window.socket.on('command_added', (data) => {
                window.showNotification('Command added successfully', 'success');
            });

            window.socket.on('command_updated', (data) => {
                window.showNotification('Command updated successfully', 'success');
            });

            window.socket.on('command_deleted', (data) => {
                window.showNotification('Command deleted successfully', 'success');
            });

            window.socket.on('os_detection_started', (data) => {
                console.log('OS detection started for session:', data.session_id);
                this.detectingOsForSession = data.session_id;
            });
        }

        this.setupEventListeners();
    },

    setupEventListeners() {
        const commandLibraryBtn = document.getElementById('commandLibraryBtn');
        if (commandLibraryBtn) {
            commandLibraryBtn.addEventListener('click', () => this.openLibrary());
        }

        const closeCommandLibraryModal = document.getElementById('closeCommandLibraryModal');
        if (closeCommandLibraryModal) {
            closeCommandLibraryModal.addEventListener('click', () => this.closeLibrary());
        }

        const commandSearchInput = document.getElementById('commandSearchInput');
        if (commandSearchInput) {
            commandSearchInput.addEventListener('input', (e) => this.searchCommands(e.target.value));
        }

        const addCommandBtn = document.getElementById('addCommandBtn');
        if (addCommandBtn) {
            addCommandBtn.addEventListener('click', () => this.showAddCommandForm());
        }

        const closeCommandFormModal = document.getElementById('closeCommandFormModal');
        if (closeCommandFormModal) {
            closeCommandFormModal.addEventListener('click', () => this.closeCommandForm());
        }

        const cancelCommandFormBtn = document.getElementById('cancelCommandFormBtn');
        if (cancelCommandFormBtn) {
            cancelCommandFormBtn.addEventListener('click', () => this.closeCommandForm());
        }

        const commandForm = document.getElementById('commandForm');
        if (commandForm) {
            commandForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveCommand();
            });
        }

        window.addEventListener('click', (e) => {
            const commandLibraryModal = document.getElementById('commandLibraryModal');
            const commandFormModal = document.getElementById('commandFormModal');

            if (e.target === commandLibraryModal) {
                this.closeLibrary();
            }
            if (e.target === commandFormModal) {
                this.closeCommandForm();
            }
        });

        document.querySelectorAll('.os-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.os-filter-btn').forEach(b => b.classList.remove('active'));
                e.currentTarget.classList.add('active');
                this.currentOs = e.currentTarget.dataset.os;
                this.loadCommands();
            });
        });
    },

    loadCommands() {
        if (window.socket) {
            window.socket.emit('list_commands', {
                os_filter: this.currentOs === 'all' ? null : this.currentOs
            });
        }
    },

    setCommands(commands) {
        this.commands = commands;
        this.filteredCommands = commands;
        this.renderCommandsList();
        const osDisplay = document.getElementById('currentOsDisplay');
        if (osDisplay) {
            osDisplay.textContent = this.currentOs.charAt(0).toUpperCase() + this.currentOs.slice(1);
        }
    },

    openLibrary() {
        const activeSessionId = SessionManager.getActiveSession();

        if (!activeSessionId) {
            this.currentOs = 'all';
            this.loadCommands();
        }

        if (window.ModalManager) {
            window.ModalManager.open(document.getElementById('commandLibraryModal'));
        } else {
            document.getElementById('commandLibraryModal').classList.add('show');
        }

        setTimeout(() => {
            document.getElementById('commandSearchInput').focus();
        }, 100);
    },

    closeLibrary() {
        if (window.ModalManager) {
            window.ModalManager.close(document.getElementById('commandLibraryModal'));
        } else {
            document.getElementById('commandLibraryModal').classList.remove('show');
        }
        document.getElementById('commandSearchInput').value = '';
        this.filteredCommands = this.commands;
        this.renderCommandsList();
    },

    detectOs() {
    },

    searchCommands(query) {
        if (!query) {
            this.filteredCommands = this.commands;
        } else {
            const lowerQuery = query.toLowerCase();
            this.filteredCommands = this.commands.filter(cmd => {
                const matchesEnglish = (
                    cmd.name.toLowerCase().includes(lowerQuery) ||
                    cmd.command.toLowerCase().includes(lowerQuery) ||
                    cmd.parameters.toLowerCase().includes(lowerQuery) ||
                    cmd.description.toLowerCase().includes(lowerQuery)
                );

                if (matchesEnglish) {
                    return true;
                }

                if (window.i18n) {
                    const currentLang = window.i18n.getLanguage();
                    const translations = window.i18n.translations[currentLang];

                    if (translations) {
                        const categoryKey = 'commands.category' + cmd.category.charAt(0).toUpperCase() + cmd.category.slice(1);
                        if (translations[categoryKey] && translations[categoryKey].toLowerCase().includes(lowerQuery)) {
                            return true;
                        }
                    }
                }

                return false;
            });
        }
        this.renderCommandsList();
    },

    renderCommandsList() {
        const container = document.getElementById('commandsList');

        if (this.filteredCommands.length === 0) {
            container.innerHTML = '<p class="no-items">No commands found</p>';
            return;
        }

        container.innerHTML = '';
        this.renderCursor = 0;
        container.scrollTop = 0;
        this.renderNextChunk();

        container.onscroll = () => {
            if (container.scrollTop + container.clientHeight >= container.scrollHeight - 40) {
                this.renderNextChunk();
            }
        };
    },

    renderNextChunk() {
        const container = document.getElementById('commandsList');
        if (!container) {
            return;
        }
        const start = this.renderCursor;
        const end = Math.min(start + this.chunkSize, this.filteredCommands.length);
        if (start >= end) {
            return;
        }
        this.renderCursor = end;

        this.filteredCommands.slice(start, end).forEach(cmd => {
            const row = document.createElement('div');
            row.className = 'command-row';
            if (cmd.isSystem) {
                row.classList.add('system-command');
            }

            row.innerHTML = `
                <div class="command-cell command-name">
                    <strong>${this.escapeHtml(cmd.name)}</strong>
                    <div class="command-os-badges">
                        ${cmd.os.map(os => `<span class="os-badge">${this.escapeHtml(os)}</span>`).join('')}
                    </div>
                </div>
                <div class="command-cell command-text">
                    <code>${this.escapeHtml(cmd.command)}</code>
                </div>
                <div class="command-cell command-params">
                    <code>${this.escapeHtml(cmd.parameters)}</code>
                </div>
                <div class="command-cell command-desc">
                    ${this.escapeHtml(cmd.description)}
                </div>
                <div class="command-cell command-actions">
                    <button class="btn-icon cmd-execute" data-cmd-id="${this.escapeHtml(cmd.id)}" title="Execute">▶️</button>
                    ${cmd.isSystem ? `
                        <button class="btn-icon cmd-copy" data-cmd-id="${this.escapeHtml(cmd.id)}" title="Copy to My Commands">📋</button>
                    ` : `
                        <button class="btn-icon cmd-edit" data-cmd-id="${this.escapeHtml(cmd.id)}" title="Edit">✏️</button>
                        <button class="btn-icon cmd-delete" data-cmd-id="${this.escapeHtml(cmd.id)}" title="Delete">🗑️</button>
                    `}
                </div>
            `;

            container.appendChild(row);
        });

        this.attachCommandListeners(container);
    },

    attachCommandListeners(container) {
        container.querySelectorAll('.cmd-execute').forEach(btn => {
            btn.addEventListener('click', () => {
                this.executeCommand(btn.dataset.cmdId);
            });
        });
        container.querySelectorAll('.cmd-copy').forEach(btn => {
            btn.addEventListener('click', () => {
                this.copyCommand(btn.dataset.cmdId);
            });
        });
        container.querySelectorAll('.cmd-edit').forEach(btn => {
            btn.addEventListener('click', () => {
                this.editCommand(btn.dataset.cmdId);
            });
        });
        container.querySelectorAll('.cmd-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                this.deleteCommand(btn.dataset.cmdId);
            });
        });
    },

    executeCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd) return;

        const activeSessionId = SessionManager.getActiveSession();
        if (!activeSessionId) {
            window.showNotification('No active session', 'warning');
            return;
        }

        let fullCommand = cmd.command;
        if (cmd.parameters) {
            fullCommand += ' ' + cmd.parameters;
        }

        if (window.socket) {
            window.socket.emit('ssh_input', {
                session_id: activeSessionId,
                data: fullCommand
            });
        }

        this.closeLibrary();

        window.showNotification(`Command inserted: ${cmd.name}`, 'success');
    },

    showAddCommandForm() {
        this.editingCommandId = null;
        document.getElementById('commandFormTitle').textContent = 'Add New Command';
        document.getElementById('commandFormName').value = '';
        document.getElementById('commandFormCommand').value = '';
        document.getElementById('commandFormParams').value = '';
        document.getElementById('commandFormDescription').value = '';
        document.getElementById('commandFormCategory').value = 'custom';

        document.querySelectorAll('input[name="commandOs"]').forEach(cb => cb.checked = false);
        document.getElementById('osAll').checked = true;

        if (window.ModalManager) {
            window.ModalManager.open(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.add('show');
        }
    },

    copyCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd) return;

        this.editingCommandId = null;
        document.getElementById('commandFormTitle').textContent = 'Copy Command to My Library';
        document.getElementById('commandFormName').value = cmd.name;
        document.getElementById('commandFormCommand').value = cmd.command;
        document.getElementById('commandFormParams').value = cmd.parameters;
        document.getElementById('commandFormDescription').value = cmd.description;
        document.getElementById('commandFormCategory').value = cmd.category || 'custom';

        document.querySelectorAll('input[name="commandOs"]').forEach(cb => {
            cb.checked = cmd.os.includes(cb.value);
        });

        if (window.ModalManager) {
            window.ModalManager.open(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.add('show');
        }
    },

    editCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd || cmd.isSystem) return;

        this.editingCommandId = commandId;
        document.getElementById('commandFormTitle').textContent = 'Edit Command';
        document.getElementById('commandFormName').value = cmd.name;
        document.getElementById('commandFormCommand').value = cmd.command;
        document.getElementById('commandFormParams').value = cmd.parameters;
        document.getElementById('commandFormDescription').value = cmd.description;
        document.getElementById('commandFormCategory').value = cmd.category || 'custom';

        document.querySelectorAll('input[name="commandOs"]').forEach(cb => {
            cb.checked = cmd.os.includes(cb.value);
        });

        if (window.ModalManager) {
            window.ModalManager.open(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.add('show');
        }
    },

    saveCommand() {
        const name = document.getElementById('commandFormName').value.trim();
        const command = document.getElementById('commandFormCommand').value.trim();
        const parameters = document.getElementById('commandFormParams').value.trim();
        const description = document.getElementById('commandFormDescription').value.trim();
        const category = document.getElementById('commandFormCategory').value;

        const osList = [];
        document.querySelectorAll('input[name="commandOs"]:checked').forEach(cb => {
            osList.push(cb.value);
        });

        if (!name || !command || !description) {
            window.showNotification('Name, command, and description are required', 'error');
            return;
        }

        if (osList.length === 0) {
            window.showNotification('Select at least one OS', 'error');
            return;
        }

        const data = {
            name,
            command,
            parameters,
            description,
            os: osList,
            category
        };

        if (this.editingCommandId) {
            data.command_id = this.editingCommandId;
            window.socket.emit('update_command', data);
        } else {
            window.socket.emit('add_command', data);
        }

        this.closeCommandForm();
    },

    deleteCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd || cmd.isSystem) return;

        if (confirm(`Delete command "${cmd.name}"?`)) {
            window.socket.emit('delete_command', { command_id: commandId });
        }
    },

    closeCommandForm() {
        if (window.ModalManager) {
            window.ModalManager.close(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.remove('show');
        }
        this.editingCommandId = null;
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};
