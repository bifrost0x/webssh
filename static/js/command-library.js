const CommandLibrary = {
    commands: [],
    filteredCommands: [],
    currentOs: 'all',
    searchQuery: '',
    editingCommandId: null,
    renderCursor: 0,
    chunkSize: 40,
    pendingSaveCallback: null,
    returnToModalId: null,
    osManuallySelected: false,
    formEpoch: 0,
    saving: false,
    saveTimer: null,
    saveAttempt: 0,
    formBaseline: null,
    saveOutcomeUnknown: false,
    retryConfirmation: false,

    init() {
        this.loadCommands();

        if (window.socket) {
            window.socket.on('commands_list', (data) => {
                this.setCommands(data.commands);
            });

            window.socket.on('command_added', () => {
                window.showNotification(window.i18n?.t('commands.added') || 'Command added successfully', 'success');
            });

            window.socket.on('command_updated', () => {
                window.showNotification(window.i18n?.t('commands.updated') || 'Command updated successfully', 'success');
            });

            window.socket.on('command_deleted', () => {
                window.showNotification(window.i18n?.t('commands.deleted') || 'Command deleted successfully', 'success');
            });

        }

        this.setupEventListeners();
        document.addEventListener?.('keydown', event => {
            const form = document.getElementById('commandFormModal');
            if (event.key !== 'Escape' || !form?.classList.contains('show')
                || document.querySelector?.('dialog[open]')) return;
            event.preventDefault();
            event.stopImmediatePropagation();
            this.requestCloseCommandForm();
        }, true);
        window.addEventListener?.('session-target-os-change', () => this.detectOs());
    },

    setupEventListeners() {
        const commandLibraryBtn = document.getElementById('commandLibraryBtn');
        if (commandLibraryBtn) {
            commandLibraryBtn.addEventListener('click', () => {
                if (['library', 'favorites'].includes(window.CommandWorkspace?.activeSection)) {
                    this.returnToModalId = null;
                    window.CommandWorkspace.open();
                    const searchId = window.CommandWorkspace.activeSection === 'favorites' ? 'commandFavoritesSearch' : 'commandSearchInput';
                    setTimeout(() => document.getElementById(searchId)?.focus({preventScroll: true}), 0);
                } else {
                    window.CommandSetManager?.openManagement();
                }
            });
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
            closeCommandFormModal.addEventListener('click', () => this.requestCloseCommandForm());
        }

        const cancelCommandFormBtn = document.getElementById('cancelCommandFormBtn');
        if (cancelCommandFormBtn) {
            cancelCommandFormBtn.addEventListener('click', () => this.requestCloseCommandForm());
        }

        const commandForm = document.getElementById('commandForm');
        if (commandForm) {
            commandForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveCommand();
            });
            commandForm.addEventListener('input', () => this.updateFormPreview());
        }

        window.addEventListener('click', (e) => {
            const commandFormModal = document.getElementById('commandFormModal');

            if (e.target === commandFormModal) {
                this.requestCloseCommandForm();
            }
        });

        document.querySelectorAll('#commandLibraryPanel .os-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('#commandLibraryPanel .os-filter-btn').forEach(b => b.classList.remove('active'));
                e.currentTarget.classList.add('active');
                this.currentOs = e.currentTarget.dataset.os;
                this.osManuallySelected = true;
                this.searchCommands(this.searchQuery);
            });
        });
    },

    loadCommands() {
        if (window.socket) {
            window.socket.emit('list_commands', {
                os_filter: null
            });
        }
    },

    setCommands(commands) {
        this.commands = commands;
        this.searchCommands(this.searchQuery);
        window.CommandSetManager?.onCommandsChanged();
        window.ConnectionCommandManager?.onDataChanged();
        window.CommandWorkspace?.renderFavorites?.();
    },

    openLibrary() {
        this.returnToModalId = null;
        this.detectOs();
        this.loadCommands();

        window.CommandWorkspace.open('library', {primary: true});

        setTimeout(() => {
            document.getElementById('commandSearchInput').focus({preventScroll: true});
        }, 100);
    },

    openEditor(commandId, returnToModalId = null) {
        const command = this.commands.find(item => item.id === commandId);
        if (!command) return;
        this.returnToModalId = returnToModalId;
        window.CommandWorkspace.open('library', {primary: !returnToModalId});
        if (command.isSystem) this.copyCommand(commandId);
        else this.editCommand(commandId);
    },

    closeLibrary() {
        const returnModalId = this.returnToModalId;
        window.CommandWorkspace.close();
        document.getElementById('commandSearchInput').value = '';
        this.searchCommands('');
        if (returnModalId && window.ModalManager) {
            const returnModal = document.getElementById(returnModalId);
            if (returnModal?.classList.contains('show')) {
                window.ModalManager.activeModal = returnModal;
                document.getElementById('editSelectedCommandBtn')?.focus();
            }
        }
        this.returnToModalId = null;
    },

    detectOs() {
        if (this.osManuallySelected) return this.currentOs;
        const sessionId = window.SessionManager?.getActiveSession?.();
        const osName = window.WEBSSH_TARGET_OS_BY_SESSION?.[sessionId];
        const normalized = String(osName || '').toLowerCase();
        let detected = null;
        if (/windows|mingw|msys/.test(normalized)) detected = 'windows';
        else if (/darwin|mac\s?os|os x/.test(normalized)) detected = 'macos';
        else if (/linux|bsd|ubuntu|debian|fedora|centos|rhel|suse|alpine|arch/.test(normalized)) detected = 'linux';
        if (!detected) return this.currentOs;
        const button = document.querySelector(`#commandLibraryPanel .os-filter-btn[data-os="${detected}"]`);
        if (!button) return this.currentOs;
        document.querySelectorAll('#commandLibraryPanel .os-filter-btn').forEach(candidate => {
            candidate.classList.toggle('active', candidate === button);
        });
        this.currentOs = detected;
        this.searchCommands(this.searchQuery);
        return detected;
    },

    searchCommands(query) {
        this.searchQuery = query || '';
        const commands = this.commands.filter(command => this.currentOs === 'all'
            || (command.os || ['all']).some(os => os.toLowerCase() === 'all' || os.toLowerCase() === this.currentOs.toLowerCase()));
        if (!query) {
            this.filteredCommands = commands;
        } else {
            const lowerQuery = query.toLowerCase();
            this.filteredCommands = commands.filter(cmd => {
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
                    const categoryKey = 'commands.category' + cmd.category.charAt(0).toUpperCase() + cmd.category.slice(1);
                    const translatedCategory = window.i18n.t(categoryKey);
                    if (translatedCategory !== categoryKey
                        && translatedCategory.toLowerCase().includes(lowerQuery)) {
                        return true;
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
            container.innerHTML = '';
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = window.i18n?.t('commands.noCommands') || 'No commands found';
            container.appendChild(empty);
            return;
        }

        container.innerHTML = '';
        this.renderCursor = 0;
        container.scrollTop = 0;
        this.attachCommandListeners(container);
        this.renderNextChunk();

        container.onscroll = () => {
            if (container.scrollTop + container.clientHeight >= container.scrollHeight - 40) {
                this.renderNextChunk();
            }
        };
        const body = container.closest('.command-workspace-body');
        if (body) body.onscroll = () => {
            if (!document.getElementById('commandLibraryPanel').classList.contains('hidden')
                && container.getBoundingClientRect().bottom <= body.getBoundingClientRect().bottom + 40) {
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
                    ${cmd.isSystem ? `
                        <button class="btn btn-secondary cmd-copy" data-cmd-id="${this.escapeHtml(cmd.id)}" title="${this.escapeHtml(window.SessionCommandLauncher.t('commands.copyToMine', 'Add to my commands'))}" aria-label="${this.escapeHtml(window.SessionCommandLauncher.t('commands.copyToMine', 'Add to my commands'))}"><span class="material-icons" aria-hidden="true">add</span><span>${this.escapeHtml(window.SessionCommandLauncher.t('commands.copyToMine', 'Add to my commands'))}</span></button>
                    ` : `
                        <button class="btn-icon cmd-edit material-icons" data-cmd-id="${this.escapeHtml(cmd.id)}" title="${this.escapeHtml(window.SessionCommandLauncher.t('commands.edit', 'Edit'))}" aria-label="${this.escapeHtml(window.SessionCommandLauncher.t('commands.edit', 'Edit'))}">edit</button>
                        <button class="btn-icon cmd-delete material-icons" data-cmd-id="${this.escapeHtml(cmd.id)}" title="${this.escapeHtml(window.SessionCommandLauncher.t('commands.delete', 'Delete'))}" aria-label="${this.escapeHtml(window.SessionCommandLauncher.t('commands.delete', 'Delete'))}">delete</button>
                    `}
                </div>
            `;

            row.classList.add('command-kind-command');
            const badge = document.createElement('span');
            badge.className = 'command-type-badge';
            badge.textContent = window.SessionCommandLauncher.t('commands.singleCommand', 'Command');
            row.querySelector('.command-name')?.prepend(badge);
            const favorite = window.CommandWorkspace?.favoriteButton?.('command', cmd.id);
            if (favorite) row.querySelector('.command-actions')?.prepend(favorite);
            container.appendChild(row);
        });
    },

    attachCommandListeners(container) {
        // Single delegated listener bound once per render. Attaching per-chunk
        // over the whole container (as before) stacked duplicate listeners on
        // already-rendered rows during infinite scroll, firing actions 2x/3x.
        container.onclick = (event) => {
            const btn = event.target.closest('button[data-cmd-id]');
            if (!btn || !container.contains(btn)) {
                return;
            }
            const cmdId = btn.dataset.cmdId;
            if (btn.classList.contains('cmd-copy')) {
                this.copyCommand(cmdId);
            } else if (btn.classList.contains('cmd-edit')) {
                this.editCommand(cmdId);
            } else if (btn.classList.contains('cmd-delete')) {
                this.deleteCommand(cmdId);
            }
        };
    },

    showAddCommandForm(options = {}) {
        this.beginForm();
        this.editingCommandId = null;
        this.pendingSaveCallback = typeof options.onSaved === 'function' ? options.onSaved : null;
        document.getElementById('commandFormTitle').textContent = window.i18n?.t('commands.addCommand') || 'Add Command';
        document.getElementById('commandFormName').value = options.name || '';
        document.getElementById('commandFormCommand').value = options.command || '';
        document.getElementById('commandFormParams').value = '';
        document.getElementById('commandFormDescription').value = options.description || '';
        document.getElementById('commandFormCategory').value = 'custom';

        document.querySelectorAll('input[name="commandOs"]').forEach(cb => cb.checked = false);
        document.getElementById('osAll').checked = true;

        if (window.ModalManager) {
            window.ModalManager.open(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.add('show');
        }
        this.formBaseline = this.formSnapshot();
        this.updateFormPreview();
    },

    copyCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd) return;

        this.beginForm();
        this.editingCommandId = null;
        document.getElementById('commandFormTitle').textContent = window.i18n?.t('commands.copyToMine') || 'Copy to My Commands';
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
        this.formBaseline = this.formSnapshot();
        this.updateFormPreview();
    },

    editCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd || cmd.isSystem) return;

        this.beginForm();
        this.editingCommandId = commandId;
        document.getElementById('commandFormTitle').textContent = window.i18n?.t('commands.editCommand') || 'Edit Command';
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
        this.formBaseline = this.formSnapshot();
        this.updateFormPreview();
    },

    formSnapshot() {
        return JSON.stringify({fields: ['commandFormName', 'commandFormCommand', 'commandFormParams',
            'commandFormDescription', 'commandFormCategory'].map(id => document.getElementById(id)?.value || ''),
        os: Array.from(document.querySelectorAll('input[name="commandOs"]:checked')).map(input => input.value)});
    },

    updateFormPreview() {
        const preview = document.getElementById('commandFormPreview');
        if (preview) {
            const command = document.getElementById('commandFormCommand')?.value || '';
            const parameters = document.getElementById('commandFormParams')?.value || '';
            preview.textContent = command + (parameters ? ` ${parameters}` : '');
        }
    },

    async requestCloseCommandForm() {
        const epoch = this.formEpoch;
        const snapshot = this.formSnapshot();
        if (this.formBaseline !== null && snapshot !== this.formBaseline) {
            const manager = window.CommandSetManager;
            if (!manager?.confirmDialog || !await manager.confirmDialog({
                title: manager.t('commandSets.discardTitle', 'Discard changes?'),
                message: manager.t('commandSets.discardHint', 'Your unsaved changes will be lost.'),
                confirmLabel: manager.t('commandSets.discard', 'Discard'),
                cancelLabel: manager.t('commandSets.keepEditing', 'Keep editing'),
            })) return false;
            if (epoch !== this.formEpoch || snapshot !== this.formSnapshot()) return false;
        }
        this.closeCommandForm();
        return true;
    },

    beginForm() {
        this.formEpoch += 1;
        this.saveOutcomeUnknown = false;
        this.retryConfirmation = false;
        this.saving = false;
        if (this.saveTimer) clearTimeout(this.saveTimer);
        this.saveTimer = null;
        const button = document.querySelector?.('#commandForm [type="submit"]');
        if (button) button.disabled = false;
    },

    saveCommand(options = {}) {
        if (this.saving || this.retryConfirmation) return;
        if (this.saveOutcomeUnknown && !options.confirmed) {
            const manager = window.CommandSetManager;
            if (!manager?.confirmDialog) return;
            const epoch = this.formEpoch, snapshot = this.formSnapshot();
            this.retryConfirmation = true;
            manager.confirmDialog({
                title: manager.t('common.saveUnknownTitle', 'Save outcome unknown'),
                message: manager.t('common.saveUnknownHint', 'The previous save may have succeeded. Check the saved list before trying again. Saving again may create a duplicate.'),
                confirmLabel: manager.t('common.saveAgain', 'Save again'),
                cancelLabel: manager.t('commandSets.keepEditing', 'Keep editing'),
            }).then(accepted => {
                this.retryConfirmation = false;
                if (accepted && epoch === this.formEpoch && snapshot === this.formSnapshot()) this.saveCommand({confirmed: true});
            });
            return;
        }
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
            window.showNotification(window.i18n?.t('commands.requiredFields') || 'Name, command, and description are required', 'error');
            return;
        }

        if (osList.length === 0) {
            window.showNotification(window.i18n?.t('commands.osRequired') || 'Select at least one OS', 'error');
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

        const submittedSnapshot = this.formSnapshot();
        const epoch = this.formEpoch;
        const attempt = ++this.saveAttempt;
        const callback = this.pendingSaveCallback;
        const event = this.editingCommandId ? 'update_command' : 'add_command';
        if (this.editingCommandId) data.command_id = this.editingCommandId;
        this.saving = true;
        this.saveOutcomeUnknown = false;
        const button = document.querySelector?.('#commandForm [type="submit"]');
        if (button) button.disabled = true;
        const finish = (acknowledgement, unknown = false) => {
            if (this.formEpoch !== epoch || this.saveAttempt !== attempt || !this.saving) return;
            this.saving = false;
            if (this.saveTimer) clearTimeout(this.saveTimer);
            this.saveTimer = null;
            if (button) button.disabled = false;
            if (unknown) {
                this.saveOutcomeUnknown = true;
                this.loadCommands();
                window.showNotification(window.i18n?.t('common.saveUnknownHint') || 'The save may have succeeded. Check the saved list before retrying.', 'warning');
                return;
            }
            if (!acknowledgement?.success) {
                window.showNotification(
                    window.i18n?.t('commands.saveFailed') || 'Could not save the command. Check the fields and try again.', 'error'
                );
                return;
            }
            if (submittedSnapshot !== this.formSnapshot()) {
                this.editingCommandId = acknowledgement.command?.id || data.command_id || null;
                this.formBaseline = submittedSnapshot;
                return;
            }
            this.closeCommandForm();
            callback?.(acknowledgement.command);
        };
        // Bound waiting preserves the draft if the connection drops without an ack.
        if (typeof setTimeout === 'function') this.saveTimer = setTimeout(() => finish(null, true), 10000);
        window.socket.emit(event, data, finish);
    },

    async deleteCommand(commandId) {
        const cmd = this.commands.find(c => c.id === commandId);
        if (!cmd || cmd.isSystem) return;

        const prompt = window.i18n?.t('commands.deleteConfirm') || 'Delete command "{name}"?';
        const message = prompt.replace('{name}', () => cmd.name);
        const accepted = window.CommandSetManager?.confirmDialog
            ? await window.CommandSetManager.confirmDialog({title: window.i18n?.t('commands.delete') || 'Delete', message,
                confirmLabel: window.i18n?.t('common.delete') || 'Delete'})
            : confirm(message);
        if (accepted && this.commands.some(item => item.id === commandId && !item.isSystem)) {
            window.socket.emit('delete_command', { command_id: commandId });
        }
    },

    closeCommandForm() {
        this.beginForm();
        if (window.ModalManager) {
            window.ModalManager.close(document.getElementById('commandFormModal'));
        } else {
            document.getElementById('commandFormModal').classList.remove('show');
        }
        this.editingCommandId = null;
        this.pendingSaveCallback = null;
        const workspace = document.getElementById('commandWorkspaceModal');
        if (
            workspace?.classList.contains('show')
            && window.ModalManager
            && !window.primaryWorkspaceController?.isElementActive(workspace)
        ) {
            window.ModalManager.activeModal = workspace;
        }
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

window.CommandLibrary = CommandLibrary;
