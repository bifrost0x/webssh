/* Named, reusable post-connect command sets. */
window.CommandSetManager = {
    commandSets: [],
    selectedId: '',
    draftSteps: [],
    editingId: null,
    convertingProfileId: null,
    returnToConnection: false,
    currentOs: 'all',
    searchQuery: '',
    draggedStepIndex: null,

    t(key, fallback) {
        if (window.i18n) {
            const translated = window.i18n.t(key);
            if (translated && translated !== key) return translated;
        }
        return fallback;
    },

    init() {
        if (window.socket) {
            window.socket.on('command_sets_list', data => {
                if (data && data.success !== false) {
                    this.setCommandSets(data.command_sets || []);
                }
            });
        }
        window.addEventListener('languageChanged', () => {
            this.renderSelect();
            this.renderPreview();
            this.renderManagementList();
            this.renderLibraryResults();
            this.renderSteps();
        });
        this.bindEvents();
        this.load();
    },

    bindEvents() {
        document.getElementById('commandSetSelect')?.addEventListener('change', event => {
            this.selectForConnection(event.target.value);
        });
        document.getElementById('createCommandSetBtn')?.addEventListener('click', () => {
            this.openBuilder(null, true);
        });
        document.getElementById('newCommandSetBtn')?.addEventListener('click', () => {
            this.openBuilder();
        });
        document.getElementById('cancelCommandSetBtn')?.addEventListener('click', () => {
            if (this.returnToConnection) this.close();
            else this.showManagementList();
        });
        document.getElementById('commandSetForm')?.addEventListener('submit', event => {
            event.preventDefault();
            this.save();
        });
        document.getElementById('commandSetSearchInput')?.addEventListener('input', event => {
            this.searchQuery = event.target.value;
            this.renderLibraryResults();
        });
        document.querySelectorAll('.command-set-os-filter').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.command-set-os-filter').forEach(item => {
                    item.classList.toggle('active', item === button);
                });
                this.currentOs = button.dataset.os || 'all';
                this.renderLibraryResults();
            });
        });
        document.getElementById('addInlineCommandStepBtn')?.addEventListener('click', () => {
            this.draftSteps.push({ type: 'inline', command: '' });
            this.renderSteps();
            document.querySelector('#commandSetSteps .command-set-inline-input:last-of-type')?.focus();
        });
        document.getElementById('commandSetLibraryResults')?.addEventListener('click', event => {
            const button = event.target.closest('[data-add-command-id]');
            if (button) this.addLibraryStep(button.dataset.addCommandId);
        });
        document.getElementById('commandSetManagementList')?.addEventListener('click', event => {
            const button = event.target.closest('button[data-command-set-action]');
            if (!button) return;
            const id = button.dataset.commandSetId;
            if (button.dataset.commandSetAction === 'edit') this.openBuilder(id);
            if (button.dataset.commandSetAction === 'duplicate') this.duplicate(id);
            if (button.dataset.commandSetAction === 'delete') this.delete(id);
        });
        const steps = document.getElementById('commandSetSteps');
        steps?.addEventListener('click', event => this.handleStepAction(event));
        steps?.addEventListener('input', event => this.handleStepInput(event));
        steps?.addEventListener('change', event => this.handleStepInput(event));
        steps?.addEventListener('dragstart', event => {
            const row = event.target.closest('[data-step-index]');
            this.draggedStepIndex = row ? Number(row.dataset.stepIndex) : null;
        });
        steps?.addEventListener('dragover', event => event.preventDefault());
        steps?.addEventListener('drop', event => {
            event.preventDefault();
            const row = event.target.closest('[data-step-index]');
            if (row && this.draggedStepIndex !== null) {
                this.moveStep(this.draggedStepIndex, Number(row.dataset.stepIndex));
            }
            this.draggedStepIndex = null;
        });
    },

    load() {
        window.socket?.emit('list_command_sets');
    },

    setCommandSets(commandSets) {
        this.commandSets = Array.isArray(commandSets) ? commandSets : [];
        this.renderSelect();
        this.renderPreview();
        this.renderManagementList();
        window.ConnectionCommandManager?.onDataChanged();
    },

    getById(id) {
        return this.commandSets.find(commandSet => commandSet.id === id) || null;
    },

    getCommandLibrary() {
        return typeof CommandLibrary !== 'undefined' ? CommandLibrary : null;
    },

    getSelectedId() {
        return this.selectedId || null;
    },

    selectForConnection(id) {
        this.selectedId = typeof id === 'string' ? id : '';
        this.renderSelect();
        this.renderPreview();
    },

    renderSelect() {
        const select = document.getElementById('commandSetSelect');
        if (!select) return;
        select.replaceChildren();
        const none = document.createElement('option');
        none.value = '';
        none.textContent = this.t('commandSets.none', 'None');
        select.appendChild(none);
        this.commandSets.forEach(commandSet => {
            const option = document.createElement('option');
            option.value = commandSet.id;
            option.textContent = commandSet.name;
            select.appendChild(option);
        });
        if (this.selectedId && !this.getById(this.selectedId)) {
            const missing = document.createElement('option');
            missing.value = this.selectedId;
            missing.textContent = this.t('commandSets.missingSet', 'Missing command set');
            select.appendChild(missing);
        }
        select.value = this.selectedId;
    },

    commandById(id) {
        return (this.getCommandLibrary()?.commands || [])
            .find(command => command.id === id) || null;
    },

    stepSummary(step) {
        if (step.type === 'inline') return step.command || this.t('commandSets.emptyInline', 'Empty free-text step');
        const command = this.commandById(step.command_id);
        if (!command) return this.t('commandSets.missingCommand', 'Missing library command');
        const parameters = Object.prototype.hasOwnProperty.call(step, 'parameters_override')
            ? (step.parameters_override || '')
            : (command.parameters || '');
        return command.command + (parameters ? ` ${parameters}` : '');
    },

    renderPreview() {
        const preview = document.getElementById('commandSetPreview');
        if (!preview) return;
        const commandSet = this.getById(this.selectedId);
        preview.replaceChildren();
        if (!commandSet && this.selectedId) {
            preview.textContent = this.t(
                'commandSets.missingSetHint',
                'This command set is unavailable. The connection will be blocked until you select another one.',
            );
            preview.classList.remove('empty');
            return;
        }
        if (!commandSet) {
            preview.textContent = this.t('commandSets.noSelectionHint', 'No commands will run after connecting.');
            preview.classList.add('empty');
            return;
        }
        preview.classList.remove('empty');
        const title = document.createElement('strong');
        title.textContent = commandSet.name;
        const detail = document.createElement('span');
        detail.textContent = this.t(
            'commandSets.stepCount',
            `${commandSet.steps.length} command step${commandSet.steps.length === 1 ? '' : 's'}`,
        );
        preview.append(title, detail);
    },

    openManagement() {
        this.returnToConnection = false;
        this.showManagementList();
        this.openModal();
    },

    openBuilder(id = null, returnToConnection = false) {
        this.returnToConnection = returnToConnection;
        this.editingId = id;
        this.convertingProfileId = null;
        const source = id ? this.getById(id) : null;
        this.draftSteps = source
            ? source.steps.map(step => ({ ...step }))
            : [];
        document.getElementById('commandSetNameInput').value = source?.name || '';
        document.getElementById('commandSetDescriptionInput').value = source?.description || '';
        const sudoInput = document.getElementById('commandSetUseSudoInput');
        if (sudoInput) sudoInput.checked = source ? source.use_sudo === true : false;
        document.getElementById('commandSetEditorTitle').textContent = source
            ? this.t('commandSets.edit', 'Edit command set')
            : this.t('commandSets.create', 'Create command set');
        document.getElementById('commandSetManagementView')?.classList.add('hidden');
        document.getElementById('commandSetEditorView')?.classList.remove('hidden');
        this.renderLibraryResults();
        this.renderSteps();
        this.openModal();
        setTimeout(() => document.getElementById('commandSetNameInput')?.focus(), 50);
    },

    openLegacyConversion(profile) {
        this.openBuilder(null, true);
        const sudoInput = document.getElementById('commandSetUseSudoInput');
        if (sudoInput) sudoInput.checked = false;
        this.convertingProfileId = profile.id;
        document.getElementById('commandSetNameInput').value = `${profile.name} commands`;
        this.draftSteps = [{ type: 'inline', command: profile.startup_commands || '' }];
        this.renderSteps();
    },

    showManagementList() {
        this.editingId = null;
        this.convertingProfileId = null;
        document.getElementById('commandSetEditorView')?.classList.add('hidden');
        document.getElementById('commandSetManagementView')?.classList.remove('hidden');
        this.renderManagementList();
    },

    openModal() {
        window.CommandWorkspace.open('sets');
    },

    close() {
        const returnToConnection = this.returnToConnection;
        window.CommandWorkspace.close();
        if (returnToConnection) {
            const connectionModal = document.getElementById('connectionModal');
            if (connectionModal?.classList.contains('show') && window.ModalManager) {
                window.ModalManager.activeModal = connectionModal;
                document.getElementById('createCommandSetBtn')?.focus();
            }
        }
        this.returnToConnection = false;
        this.showManagementList();
    },

    renderManagementList() {
        const container = document.getElementById('commandSetManagementList');
        if (!container) return;
        container.replaceChildren();
        if (!this.commandSets.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('commandSets.empty', 'No command sets saved.');
            container.appendChild(empty);
            return;
        }
        this.commandSets.forEach(commandSet => {
            const row = document.createElement('div');
            row.className = 'command-set-management-item';
            const info = document.createElement('div');
            const name = document.createElement('strong');
            name.textContent = commandSet.name;
            const description = document.createElement('span');
            description.textContent = commandSet.description
                || `${commandSet.steps.length} ${this.t('commandSets.steps', 'steps')}`;
            info.append(name, description);
            if (commandSet.use_sudo === true) {
                const sudoBadge = document.createElement('span');
                sudoBadge.className = 'command-set-sudo-badge';
                sudoBadge.textContent = this.t('commandSets.sudoBadge', 'sudo');
                info.appendChild(sudoBadge);
            }
            const actions = document.createElement('div');
            actions.className = 'command-set-actions';
            [['edit', 'common.edit', 'Edit'], ['duplicate', 'commandSets.duplicate', 'Duplicate'],
                ['delete', 'common.delete', 'Delete']].forEach(([action, key, fallback]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = action === 'delete' ? 'btn btn-danger btn-sm' : 'btn btn-secondary btn-sm';
                button.dataset.commandSetAction = action;
                button.dataset.commandSetId = commandSet.id;
                button.textContent = this.t(key, fallback);
                actions.appendChild(button);
            });
            row.append(info, actions);
            container.appendChild(row);
        });
    },

    renderLibraryResults() {
        const container = document.getElementById('commandSetLibraryResults');
        if (!container || !window.CommandSetUtils) return;
        const commands = window.CommandSetUtils.filterCommands(
            this.getCommandLibrary()?.commands || [], this.searchQuery, this.currentOs,
        );
        container.replaceChildren();
        commands.forEach(command => {
            const row = document.createElement('button');
            row.type = 'button';
            row.className = 'command-set-library-item';
            row.dataset.addCommandId = command.id;
            const name = document.createElement('strong');
            name.textContent = command.name;
            const code = document.createElement('code');
            code.textContent = command.command + (command.parameters ? ` ${command.parameters}` : '');
            row.append(name, code);
            container.appendChild(row);
        });
        if (!commands.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('commands.noCommands', 'No commands found');
            container.appendChild(empty);
        }
    },

    addLibraryStep(commandId) {
        if (!this.commandById(commandId)) return;
        this.draftSteps.push({ type: 'library', command_id: commandId });
        this.renderSteps();
    },

    renderSteps() {
        const container = document.getElementById('commandSetSteps');
        if (!container) return;
        container.replaceChildren();
        this.draftSteps.forEach((step, index) => {
            const row = document.createElement('div');
            row.className = 'command-set-step';
            row.dataset.stepIndex = index;
            row.draggable = true;

            const header = document.createElement('div');
            header.className = 'command-set-step-header';
            const label = document.createElement('strong');
            label.textContent = `${index + 1}. ${step.type === 'library'
                ? (this.commandById(step.command_id)?.name || this.t('commandSets.missingCommand', 'Missing command'))
                : this.t('commandSets.freeText', 'Free text')}`;
            const controls = document.createElement('div');
            [['up', '↑'], ['down', '↓'], ['remove', '×']].forEach(([action, text]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'btn-icon';
                button.dataset.stepAction = action;
                button.dataset.stepIndex = index;
                button.textContent = text;
                button.setAttribute('aria-label', this.t(`commandSets.${action}Step`, `${action} step`));
                controls.appendChild(button);
            });
            header.append(label, controls);
            row.appendChild(header);

            if (step.type === 'inline') {
                const textarea = document.createElement('textarea');
                textarea.className = 'form-control command-set-inline-input';
                textarea.rows = 3;
                textarea.maxLength = 4096;
                textarea.dataset.stepField = 'command';
                textarea.dataset.stepIndex = index;
                textarea.value = step.command || '';
                const promote = document.createElement('button');
                promote.type = 'button';
                promote.className = 'btn btn-secondary btn-sm';
                promote.dataset.stepAction = 'promote';
                promote.dataset.stepIndex = index;
                promote.textContent = this.t('commandSets.saveToLibrary', 'Save as library command');
                row.append(textarea, promote);
            } else {
                const summary = document.createElement('code');
                summary.textContent = this.stepSummary(step);
                const defaultLabel = document.createElement('label');
                defaultLabel.className = 'command-set-default-params';
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = !Object.prototype.hasOwnProperty.call(
                    step, 'parameters_override'
                );
                checkbox.dataset.stepField = 'use-default-parameters';
                checkbox.dataset.stepIndex = index;
                defaultLabel.append(checkbox, document.createTextNode(
                    this.t('commandSets.useDefaultParameters', 'Use library parameters'),
                ));
                const parameters = document.createElement('input');
                parameters.type = 'text';
                parameters.className = 'form-control';
                parameters.dataset.stepField = 'parameters_override';
                parameters.dataset.stepIndex = index;
                parameters.disabled = checkbox.checked;
                parameters.value = step.parameters_override || '';
                parameters.placeholder = this.commandById(step.command_id)?.parameters || '';
                row.append(summary, defaultLabel, parameters);
            }
            container.appendChild(row);
        });
        if (!this.draftSteps.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('commandSets.noSteps', 'Add a library command or free-text step.');
            container.appendChild(empty);
        }
    },

    handleStepAction(event) {
        const button = event.target.closest('[data-step-action]');
        if (!button) return;
        const index = Number(button.dataset.stepIndex);
        if (button.dataset.stepAction === 'up') this.moveStep(index, index - 1);
        if (button.dataset.stepAction === 'down') this.moveStep(index, index + 1);
        if (button.dataset.stepAction === 'remove') {
            this.draftSteps.splice(index, 1);
            this.renderSteps();
        }
        if (button.dataset.stepAction === 'promote') this.promoteInlineStep(index);
    },

    handleStepInput(event) {
        const field = event.target.dataset.stepField;
        const index = Number(event.target.dataset.stepIndex);
        const step = this.draftSteps[index];
        if (!step || !field) return;
        if (field === 'command') step.command = event.target.value;
        if (field === 'parameters_override') step.parameters_override = event.target.value;
        if (field === 'use-default-parameters') {
            if (event.target.checked) delete step.parameters_override;
            else step.parameters_override = '';
            this.renderSteps();
        }
    },

    moveStep(fromIndex, toIndex) {
        this.draftSteps = window.CommandSetUtils.moveStep(this.draftSteps, fromIndex, toIndex);
        this.renderSteps();
    },

    promoteInlineStep(index) {
        const step = this.draftSteps[index];
        if (!step || step.type !== 'inline' || !step.command.trim()) return;
        const library = this.getCommandLibrary();
        if (!library?.showAddCommandForm) return;
        library.showAddCommandForm({
            command: step.command,
            onSaved: command => {
                this.draftSteps[index] = { type: 'library', command_id: command.id };
                this.renderSteps();
                this.openModal();
            },
        });
    },

    emitWithAck(event, payload, onSuccess) {
        if (!window.socket) return;
        window.socket.emit(event, payload, acknowledgement => {
            if (!acknowledgement?.success) {
                window.showNotification?.(
                    acknowledgement?.error || this.t('common.error', 'Operation failed'), 'error',
                );
                return;
            }
            onSuccess?.(acknowledgement);
        });
    },

    save() {
        const payload = {
            name: document.getElementById('commandSetNameInput')?.value.trim(),
            description: document.getElementById('commandSetDescriptionInput')?.value.trim() || '',
            use_sudo: document.getElementById('commandSetUseSudoInput')?.checked === true,
            steps: this.draftSteps.map(step => ({ ...step })),
        };
        if (this.editingId) payload.id = this.editingId;
        const event = this.convertingProfileId ? 'convert_legacy_command_set' : 'save_command_set';
        const isLegacyConversion = Boolean(this.convertingProfileId);
        if (this.convertingProfileId) payload.profile_id = this.convertingProfileId;
        this.emitWithAck(event, payload, acknowledgement => {
            const saved = acknowledgement.command_set;
            if (saved) {
                const remaining = this.commandSets.filter(item => item.id !== saved.id);
                this.setCommandSets([...remaining, saved]);
                if (this.returnToConnection) this.selectForConnection(saved.id);
            }
            if (isLegacyConversion && typeof ProfileManager !== 'undefined') {
                ProfileManager.clearLegacyCommands();
            }
            this.load();
            this.close();
            window.showNotification?.(this.t('commandSets.saved', 'Command set saved'), 'success');
        });
    },

    duplicate(id) {
        this.emitWithAck('duplicate_command_set', { command_set_id: id }, () => this.load());
    },

    delete(id) {
        const commandSet = this.getById(id);
        if (!commandSet || !window.confirm(this.t('commandSets.confirmDelete', `Delete "${commandSet.name}"?`))) return;
        this.emitWithAck('delete_command_set', { command_set_id: id }, () => {
            if (this.selectedId === id) this.selectForConnection('');
            this.load();
        });
    },

    onCommandsChanged() {
        this.renderLibraryResults();
        this.renderSteps();
        this.renderPreview();
    },
};
