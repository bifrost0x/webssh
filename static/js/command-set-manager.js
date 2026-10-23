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
    managementSearchQuery: '',
    managementUsageFilter: 'all',
    draggedStepIndex: null,
    draftActive: false,
    draftBaseline: '',
    draftVersion: 0,
    pendingSave: false,
    saveAttempt: 0,
    saveTimer: null,
    saveOutcomeUnknown: false,

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
        document.getElementById('cancelCommandSetBtn')?.addEventListener('click', async () => {
            if (this.returnToConnection) this.close();
            else if (await this.confirmDiscard()) this.showManagementList();
        });
        ['commandSetNameInput', 'commandSetDescriptionInput', 'commandSetParameterNames',
            'commandSetUseSudoInput'].forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => this.renderDraftPreview());
        });
        document.getElementById('commandSetForm')?.addEventListener('submit', event => {
            event.preventDefault();
            this.save();
        });
        document.getElementById('commandSetSearchInput')?.addEventListener('input', event => {
            this.searchQuery = event.target.value;
            this.renderLibraryResults();
        });
        document.getElementById('commandSetManagementSearch')?.addEventListener('input', event => {
            this.managementSearchQuery = event.target.value;
            this.renderManagementList();
        });
        document.getElementById('commandSetUsageFilter')?.addEventListener('change', event => {
            this.managementUsageFilter = ['startup', 'interactive'].includes(event.target.value)
                ? event.target.value : 'all';
            this.renderManagementList();
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
        document.getElementById('addArgumentCommandStepBtn')?.addEventListener('click', () => {
            this.draftSteps.push({ type: 'argv', argv: ['ls', '--', '{{path}}'] });
            this.renderSteps();
            document.querySelector('#commandSetSteps [data-step-field="argv"]:last-of-type')?.focus();
        });
        document.getElementById('commandSetLibraryResults')?.addEventListener('click', event => {
            const button = event.target.closest('[data-add-command-id]');
            if (button) this.addLibraryStep(button.dataset.addCommandId);
        });
        document.getElementById('commandSetManagementList')?.addEventListener('click', event => {
            const button = event.target.closest('button[data-command-set-action]');
            if (!button) return;
            button.closest('.command-set-management-item')?.querySelector('details')?.removeAttribute('open');
            const id = button.dataset.commandSetId;
            if (['edit', 'edit-primary'].includes(button.dataset.commandSetAction)) this.openBuilder(id);
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
        this.commandSets.filter(commandSet => !commandSet.parameters?.length).forEach(commandSet => {
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
        if (step.type === 'argv') return JSON.stringify(step.argv);
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
            'Command steps: {count}',
        ).replace('{count}', String(commandSet.steps.length));
        preview.append(title, detail);
    },

    openManagement() {
        if (this.hasUnsavedChanges()) return this.confirmDiscard().then(confirmed => {
            if (confirmed) this.openManagement();
        });
        this.returnToConnection = false;
        this.showManagementList();
        this.openModal();
        setTimeout(() => {
            document.getElementById('commandSetManagementSearch')?.focus();
        }, 0);
    },

    openBuilder(id = null, returnToConnection = false) {
        if (this.hasUnsavedChanges()) return this.confirmDiscard().then(confirmed => {
            if (confirmed) this.openBuilder(id, returnToConnection);
        });
        this.draftVersion++;
        this.resetSaveState();
        this.draftActive = true;
        this.returnToConnection = returnToConnection;
        this.editingId = id;
        this.convertingProfileId = null;
        const source = id ? this.getById(id) : null;
        this.draftSteps = source
            ? source.steps.map(step => step.type === 'argv' ? {...step, argv: [...step.argv]} : {...step})
            : [];
        document.getElementById('commandSetNameInput').value = source?.name || '';
        document.getElementById('commandSetDescriptionInput').value = source?.description || '';
        const parameterNames = document.getElementById('commandSetParameterNames');
        if (parameterNames) parameterNames.value = (source?.parameters || []).map(item => item.name).join(', ');
        const sudoInput = document.getElementById('commandSetUseSudoInput');
        if (sudoInput) sudoInput.checked = source ? source.use_sudo === true : false;
        document.getElementById('commandSetEditorTitle').textContent = source
            ? this.t('commandSets.edit', 'Edit command set')
            : this.t('commandSets.create', 'Create command set');
        document.getElementById('commandSetManagementView')?.classList.add('hidden');
        document.getElementById('commandSetEditorView')?.classList.remove('hidden');
        this.renderLibraryResults();
        this.renderSteps();
        this.draftBaseline = this.draftSnapshot();
        this.openModal();
        document.getElementById('commandSetNameInput')?.focus();
    },

    openLegacyConversion(profile) {
        if (this.hasUnsavedChanges()) return this.confirmDiscard().then(confirmed => {
            if (confirmed) this.openLegacyConversion(profile);
        });
        this.openBuilder(null, true);
        const sudoInput = document.getElementById('commandSetUseSudoInput');
        if (sudoInput) sudoInput.checked = false;
        this.convertingProfileId = profile.id;
        document.getElementById('commandSetNameInput').value = `${profile.name} commands`;
        this.draftSteps = [{ type: 'inline', command: profile.startup_commands || '' }];
        this.renderSteps();
    },

    showManagementList() {
        this.draftActive = false;
        this.draftVersion++;
        this.resetSaveState();
        this.editingId = null;
        this.convertingProfileId = null;
        document.getElementById('commandSetEditorView')?.classList.add('hidden');
        document.getElementById('commandSetManagementView')?.classList.remove('hidden');
        this.renderManagementList();
    },

    openModal() {
        window.CommandWorkspace.open('sets', {primary: !this.returnToConnection});
    },

    async close(options = {}) {
        if (!options.saved && !await this.confirmDiscard()) return false;
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
        return true;
    },

    draftSnapshot() {
        return JSON.stringify({
            name: document.getElementById('commandSetNameInput')?.value || '',
            description: document.getElementById('commandSetDescriptionInput')?.value || '',
            parameters: document.getElementById('commandSetParameterNames')?.value || '',
            useSudo: document.getElementById('commandSetUseSudoInput')?.checked === true,
            steps: this.draftSteps,
        });
    },

    hasUnsavedChanges() {
        return this.draftActive && this.draftSnapshot() !== this.draftBaseline;
    },

    async confirmDiscard() {
        if (!this.hasUnsavedChanges()) return true;
        // A single confirmation owns its draft; a delayed answer must not discard a newer one.
        if (this.discardConfirmation) return false;
        const version = this.draftVersion;
        const snapshot = this.draftSnapshot();
        this.discardConfirmation = true;
        try {
            const confirmed = await this.requestConfirmation(
                this.t('commandSets.discardTitle', 'Discard unsaved changes?'),
                this.t('commandSets.discardHint', 'Your changes have not been saved.'),
                this.t('commandSets.discard', 'Discard changes'),
                this.t('commandSets.keepEditing', 'Keep editing'),
            );
            if (!confirmed || version !== this.draftVersion || snapshot !== this.draftSnapshot()) return false;
            this.showManagementList();
            return true;
        } finally {
            this.discardConfirmation = false;
        }
    },

    confirmDialog({title, message, confirmLabel, cancelLabel, danger = true}) {
        return this.requestConfirmation(title, message, confirmLabel, cancelLabel, danger);
    },

    requestConfirmation(title, message, action, cancel = this.t('common.cancel', 'Cancel'), danger = true) {
        const previousFocus = document.activeElement;
        const dialog = document.createElement('dialog');
        dialog.className = 'command-set-confirm-dialog';
        const content = document.createElement('div');
        content.className = 'modal-content';
        const heading = document.createElement('h3');
        heading.id = 'commandSetConfirmationTitle';
        heading.textContent = title;
        const body = document.createElement('p');
        body.textContent = message;
        const footer = document.createElement('div');
        footer.className = 'modal-footer';
        const keep = document.createElement('button');
        keep.type = 'button';
        keep.className = 'btn btn-secondary';
        keep.textContent = cancel;
        const discard = document.createElement('button');
        discard.type = 'button';
        discard.className = danger ? 'btn btn-danger' : 'btn btn-primary';
        discard.textContent = action;
        dialog.setAttribute('aria-labelledby', heading.id);
        footer.append(keep, discard);
        content.append(heading, body, footer);
        dialog.append(content);
        document.body.append(dialog);
        return new Promise(resolve => {
            const finish = result => {
                dialog.close();
                dialog.remove();
                previousFocus?.focus({preventScroll: true});
                resolve(result);
            };
            keep.addEventListener('click', () => finish(false));
            discard.addEventListener('click', () => finish(true));
            dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
            // Native dialog owns focus and Escape while the underlying workspace remains open.
            dialog.addEventListener('keydown', event => event.stopPropagation());
            dialog.showModal();
            keep.focus();
        });
    },

    renderManagementList() {
        const container = document.getElementById('commandSetManagementList');
        if (!container) return;
        const openMenus = new Set(Array.from(container.querySelectorAll('.command-set-action-menu[open]'))
            .map(menu => menu.dataset.commandSetId));
        const active = document.activeElement;
        const activeMenu = container.contains(active) ? active.closest('.command-set-action-menu') : null;
        const focusedId = activeMenu?.dataset.commandSetId;
        const focusedAction = activeMenu ? active.dataset.commandSetAction : null;
        let focusTarget = null;
        const restoreFocus = () => {
            if (activeMenu) (focusTarget || document.getElementById('commandSetManagementSearch'))?.focus({preventScroll: true});
        };
        container.replaceChildren();
        if (!this.commandSets.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('commandSets.empty', 'No command sets saved.');
            const hint = document.createElement('span');
            hint.className = 'empty-state-hint';
            hint.textContent = this.t('empty.setsHint', 'Create a command set above and build it from library commands or free-text steps.');
            empty.appendChild(hint);
            container.appendChild(empty);
            restoreFocus();
            return;
        }
        const managementQuery = String(this.managementSearchQuery || '').trim().toLowerCase();
        const visibleCommandSets = this.commandSets.filter(commandSet => {
            const interactive = Boolean(commandSet.parameters?.length);
            if (this.managementUsageFilter === 'startup' && interactive) return false;
            if (this.managementUsageFilter === 'interactive' && !interactive) return false;
            return !managementQuery
                || String(commandSet.name || '').toLowerCase().includes(managementQuery)
                || String(commandSet.description || '').toLowerCase().includes(managementQuery);
        });
        if (!visibleCommandSets.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('commandSets.emptySearch', 'No command sets match this search.');
            container.appendChild(empty);
            restoreFocus();
            return;
        }
        visibleCommandSets.forEach(commandSet => {
            const row = document.createElement('div');
            row.className = 'command-set-management-item';
            const info = document.createElement('div');
            const name = document.createElement('strong');
            name.textContent = commandSet.name;
            const description = document.createElement('span');
            const stepLabel = commandSet.steps.length === 1
                ? this.t('commandSets.step', 'step')
                : this.t('commandSets.steps', 'steps');
            description.textContent = commandSet.description || '';
            const badge = document.createElement('span');
            badge.className = 'command-type-badge command-type-badge-set';
            badge.textContent = this.t('commandSets.type', 'Command set');
            const count = document.createElement('span');
            count.className = 'command-set-step-count';
            count.textContent = `${commandSet.steps.length} ${stepLabel}`;
            info.className = 'command-set-card-content';
            info.append(badge, name);
            if (commandSet.parameters?.length) {
                const interactive = document.createElement('span');
                interactive.className = 'command-set-interactive-badge';
                interactive.textContent = this.t('commandSets.interactiveOnly', 'Requires manual launch');
                info.append(interactive);
            }
            if (commandSet.description) info.append(description);
            info.append(count);
            const preview = document.createElement('code');
            preview.className = 'command-set-card-preview';
            preview.textContent = commandSet.steps.map(step => this.stepSummary(step)).join('\n');
            info.append(preview);
            if (commandSet.use_sudo === true) {
                const sudoBadge = document.createElement('span');
                sudoBadge.className = 'command-set-sudo-badge';
                sudoBadge.textContent = this.t('commandSets.sudoBadge', 'sudo');
                info.appendChild(sudoBadge);
            }
            const actions = document.createElement('div');
            actions.className = 'command-set-actions';
            const favorite = window.CommandWorkspace?.favoriteButton?.('set', commandSet.id);
            if (favorite) actions.append(favorite);
            const edit = document.createElement('button');
            edit.type = 'button';
            edit.className = 'btn btn-primary btn-sm';
            edit.dataset.commandSetAction = 'edit-primary';
            edit.dataset.commandSetId = commandSet.id;
            edit.textContent = this.t('common.edit', 'Edit');
            actions.append(edit);
            const menu = document.createElement('details');
            menu.className = 'command-set-action-menu';
            menu.dataset.commandSetId = commandSet.id;
            menu.open = openMenus.has(commandSet.id);
            const summary = document.createElement('summary');
            summary.className = 'btn btn-secondary btn-sm material-icons';
            summary.setAttribute('aria-label',
                `${this.t('common.actions', 'Actions')} ${commandSet.name}`);
            summary.textContent = 'more_horiz';
            const menuItems = document.createElement('div');
            menuItems.className = 'command-set-action-menu-items';
            [['edit', 'common.edit', 'Edit'], ['duplicate', 'commandSets.duplicate', 'Duplicate'],
                ['delete', 'common.delete', 'Delete']].forEach(([action, key, fallback]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = action === 'delete' ? 'btn btn-danger btn-sm' : 'btn btn-secondary btn-sm';
                button.dataset.commandSetAction = action;
                button.dataset.commandSetId = commandSet.id;
                button.textContent = this.t(key, fallback);
                menuItems.appendChild(button);
            });
            menu.append(summary, menuItems);
            if (commandSet.id === focusedId) {
                focusTarget = focusedAction && menu.open
                    ? Array.from(menuItems.children).find(button => button.dataset.commandSetAction === focusedAction)
                    : summary;
            }
            actions.appendChild(menu);
            row.append(info, actions);
            container.appendChild(row);
        });
        restoreFocus();
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

    renderDraftPreview() {
        const count = document.getElementById('commandSetDraftCount');
        if (count) count.textContent = `${this.draftSteps.length} ${this.draftSteps.length === 1
            ? this.t('commandSets.step', 'step') : this.t('commandSets.steps', 'steps')}`;
        const preview = document.getElementById('commandSetDraftPreview');
        if (!preview) return;
        preview.replaceChildren();
        const sudo = document.getElementById('commandSetUseSudoInput')?.checked === true;
        if (sudo) {
            const hint = document.createElement('p');
            hint.className = 'command-set-sudo-badge';
            hint.textContent = this.t('commandSets.sudoPreviewHint', 'sudo applies to each command.');
            preview.append(hint);
        }
        this.draftSteps.forEach((step, index) => {
            const line = document.createElement('div');
            line.className = 'command-set-preview-step';
            const number = document.createElement('span');
            number.className = 'command-set-step-number';
            number.textContent = `${index + 1}. `;
            const code = document.createElement('code');
            code.textContent = step.type === 'argv' && step.argvError
                ? step.argvText : this.stepSummary(step);
            line.append(number, code);
            preview.append(line);
        });
        if (!this.draftSteps.length) preview.textContent = this.t('commandSets.noSteps', 'Add a library command or free-text step.');
    },

    renderSteps() {
        const container = document.getElementById('commandSetSteps');
        if (!container) return;
        container.replaceChildren();
        this.draftSteps.forEach((step, index) => {
            const row = document.createElement('div');
            row.className = `command-set-step command-set-step-${step.type}`;
            row.dataset.stepIndex = index;
            row.draggable = true;

            const header = document.createElement('div');
            header.className = 'command-set-step-header';
            const label = document.createElement('strong');
            label.textContent = `${step.type === 'library'
                ? (this.commandById(step.command_id)?.name || this.t('commandSets.missingCommand', 'Missing command'))
                : step.type === 'argv' ? this.t('commandSets.stepTypeArgv', 'Arguments') : this.t('commandSets.freeText', 'Free text')}`;
            const controls = document.createElement('div');
            controls.className = 'command-set-step-controls';
            [['up', '↑'], ['down', '↓'], ['remove', '×']].forEach(([action, text]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = action === 'remove' ? 'btn btn-secondary btn-sm' : 'btn-icon';
                button.dataset.stepAction = action;
                button.dataset.stepIndex = index;
                button.textContent = action === 'remove' ? this.t('commandSets.removeStep', 'Remove step') : text;
                button.setAttribute('aria-label', this.t(`commandSets.${action}Step`, `${action} step`));
                button.title = button.getAttribute?.('aria-label') || this.t(`commandSets.${action}Step`, `${action} step`);
                if (action === 'up') button.disabled = index === 0;
                if (action === 'down') button.disabled = index === this.draftSteps.length - 1;
                controls.appendChild(button);
            });
            const number = document.createElement('span');
            number.className = 'command-set-step-number';
            number.textContent = `${index + 1}. `;
            const grip = document.createElement('span');
            grip.className = 'material-icons command-set-step-grip';
            grip.textContent = 'drag_indicator';
            grip.title = this.t('commandSets.moveHandle', 'Drag to reorder');
            grip.setAttribute('aria-hidden', 'true');
            const type = document.createElement('span');
            type.className = 'command-set-step-type';
            type.textContent = this.t(`commandSets.stepType${step.type === 'argv' ? 'Argv' : step.type === 'library' ? 'Library' : 'Inline'}`,
                step.type === 'argv' ? 'Arguments' : step.type === 'library' ? 'Library command' : 'Free text');
            header.append(grip, number, label);
            if (step.type === 'library') header.append(type);
            header.append(controls);
            row.appendChild(header);

            if (step.type === 'argv') {
                label.textContent = this.t('commandSets.stepTypeArgv', 'Arguments');
                const argumentsGroup = document.createElement('div');
                argumentsGroup.className = 'command-set-argument-fields';
                if (!step.argvError) (step.argv || []).forEach((value, argumentIndex) => {
                    const fieldLabel = document.createElement('label');
                    fieldLabel.className = 'command-set-argument-field';
                    const fieldName = document.createElement('span');
                    fieldName.textContent = this.t('commandSets.argumentLabel', 'Argument {number}')
                        .replace('{number}', String(argumentIndex + 1));
                    const argument = document.createElement('input');
                    argument.type = 'text';
                    argument.className = 'form-control';
                    argument.value = value;
                    argument.maxLength = 4096;
                    argument.dataset.stepIndex = index;
                    argument.dataset.argumentIndex = argumentIndex;
                    argument.dataset.stepField = 'argument';
                    fieldLabel.append(fieldName, argument);
                    const remove = document.createElement('button');
                    remove.type = 'button';
                    remove.className = 'btn btn-secondary btn-sm';
                    remove.dataset.stepAction = 'remove-argument';
                    remove.dataset.stepIndex = index;
                    remove.dataset.argumentIndex = argumentIndex;
                    remove.disabled = step.argv.length <= 1;
                    remove.textContent = this.t('commandSets.removeArgument', 'Remove argument');
                    fieldLabel.append(remove);
                    argumentsGroup.append(fieldLabel);
                });
                const add = document.createElement('button');
                add.type = 'button';
                add.className = 'btn btn-secondary btn-sm';
                add.textContent = this.t('commandSets.addArgument', 'Add argument');
                add.dataset.stepAction = 'add-argument';
                add.dataset.stepIndex = index;
                add.disabled = Boolean(step.argvError);
                argumentsGroup.append(add);
                row.append(argumentsGroup);
                const raw = document.createElement('details');
                raw.className = 'command-set-raw-arguments';
                raw.open = true;
                const rawLabel = document.createElement('summary');
                rawLabel.textContent = this.t('commandSets.rawArguments', 'Advanced: JSON arguments');
                raw.append(rawLabel);
                const input = document.createElement('textarea');
                input.className = 'form-control';
                input.rows = 3;
                input.maxLength = 4096;
                input.dataset.stepField = 'argv';
                input.dataset.stepIndex = index;
                input.setAttribute('aria-label', label.textContent);
                input.value = step.argvText ?? JSON.stringify(step.argv);
                raw.append(input);
                row.append(raw);
                if (step.argvError) {
                    const error = document.createElement('p');
                    error.className = 'command-set-argument-error';
                    error.setAttribute('role', 'alert');
                    error.textContent = this.t('commandParameters.invalidArguments', 'Argument steps require a JSON array of strings.');
                    row.append(error);
                }
            } else if (step.type === 'inline') {
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
                parameters.setAttribute('aria-label', this.t('commands.parameters', 'Parameters'));
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
        this.renderDraftPreview();
    },

    handleStepAction(event) {
        const button = event.target.closest('[data-step-action]');
        if (!button) return;
        const index = Number(button.dataset.stepIndex);
        const step = this.draftSteps[index];
        if (step?.type === 'argv' && !step.argvError) {
            if (button.dataset.stepAction === 'add-argument') step.argv.push('');
            if (button.dataset.stepAction === 'remove-argument' && step.argv.length > 1) {
                const argumentIndex = Number(button.dataset.argumentIndex);
                if (Number.isInteger(argumentIndex) && argumentIndex >= 0) step.argv.splice(argumentIndex, 1);
            }
            if (['add-argument', 'remove-argument'].includes(button.dataset.stepAction)) {
                step.argvText = JSON.stringify(step.argv);
                this.renderSteps();
            }
        }
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
        if (field === 'argument' && step.type === 'argv' && !step.argvError) {
            const argumentIndex = Number(event.target.dataset.argumentIndex);
            if (!Number.isInteger(argumentIndex) || argumentIndex < 0 || argumentIndex >= step.argv.length) return;
            step.argv[argumentIndex] = event.target.value;
            step.argvText = JSON.stringify(step.argv);
            const raw = event.target.closest?.('.command-set-step')?.querySelector('[data-step-field="argv"]');
            if (raw) raw.value = step.argvText;
        }
        if (field === 'argv') {
            step.argvText = event.target.value;
            try {
                const parsed = JSON.parse(step.argvText);
                if (!Array.isArray(parsed) || !parsed.length || !parsed.every(value => typeof value === 'string')) throw new Error('Invalid arguments');
                step.argv = parsed;
                step.argvError = false;
            } catch {
                step.argvError = true;
            }
            if (event.type === 'change') this.renderSteps();
        }
        if (field === 'command') step.command = event.target.value;
        if (field === 'parameters_override') step.parameters_override = event.target.value;
        if (field === 'use-default-parameters') {
            if (event.target.checked) delete step.parameters_override;
            else step.parameters_override = '';
            this.renderSteps();
        }
        this.renderDraftPreview();
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
        const version = this.draftVersion;
        library.showAddCommandForm({
            command: step.command,
            onSaved: command => {
                if (version !== this.draftVersion || !this.draftActive) return;
                const currentIndex = this.draftSteps.indexOf(step);
                if (currentIndex < 0) return;
                this.draftSteps[currentIndex] = { type: 'library', command_id: command.id };
                this.renderSteps();
                this.openModal();
            },
        });
    },

    emitWithAck(event, payload, onSuccess, onFailure, acceptsAck = () => true) {
        if (!window.socket) return;
        window.socket.emit(event, payload, acknowledgement => {
            if (!acceptsAck()) return;
            if (!acknowledgement?.success) {
                onFailure?.(acknowledgement);
                window.showNotification?.(
                    acknowledgement?.error || this.t('common.error', 'Operation failed'), 'error',
                );
                return;
            }
            onSuccess?.(acknowledgement);
        });
    },

    setSavePending(pending) {
        this.pendingSave = pending;
        const button = document.getElementById('saveCommandSetBtn');
        if (button) {
            button.disabled = pending;
            button.setAttribute('aria-busy', String(pending));
        }
    },

    resetSaveState() {
        if (this.saveTimer !== null) clearTimeout(this.saveTimer);
        this.saveTimer = null;
        this.saveOutcomeUnknown = false;
        this.saveAttempt++;
        this.setSavePending(false);
    },

    save() {
        if (this.pendingSave || !window.socket) return;
        if (this.saveOutcomeUnknown) {
            const version = this.draftVersion;
            const attempt = this.saveAttempt;
            const snapshot = this.draftSnapshot();
            return this.confirmDialog({
                title: this.t('common.saveUnknownTitle', 'Save outcome unknown'),
                message: this.t('common.saveUnknownHint', 'The previous save may have succeeded. Check the saved list before trying again. Saving again may create a duplicate.'),
                confirmLabel: this.t('common.saveAgain', 'Save again'),
                cancelLabel: this.t('commandSets.keepEditing', 'Keep editing'),
            }).then(confirmed => {
                if (!confirmed || version !== this.draftVersion || attempt !== this.saveAttempt
                        || snapshot !== this.draftSnapshot() || this.pendingSave) return;
                this.saveOutcomeUnknown = false;
                return this.save();
            });
        }
        if (this.draftSteps.some(step => step.argvError)) {
            window.showNotification?.(this.t('commandParameters.invalidArguments', 'Argument steps require a JSON array of strings.'), 'error');
            return;
        }
        const names = document.getElementById('commandSetParameterNames')?.value || '';
        const payload = {
            name: document.getElementById('commandSetNameInput')?.value.trim(),
            description: document.getElementById('commandSetDescriptionInput')?.value.trim() || '',
            use_sudo: document.getElementById('commandSetUseSudoInput')?.checked === true,
            parameters: names.split(',').map(name => name.trim()).filter(Boolean).map(name => ({name})),
            steps: this.draftSteps.map(step => step.type === 'argv'
                ? { type: 'argv', argv: step.argv } : { ...step }),
        };
        if (this.editingId) payload.id = this.editingId;
        const event = this.convertingProfileId ? 'convert_legacy_command_set' : 'save_command_set';
        const isLegacyConversion = Boolean(this.convertingProfileId);
        if (this.convertingProfileId) payload.profile_id = this.convertingProfileId;
        const version = this.draftVersion;
        const snapshot = this.draftSnapshot();
        const returnToConnection = this.returnToConnection;
        const attempt = ++this.saveAttempt;
        const acceptsAck = () => attempt === this.saveAttempt && version === this.draftVersion;
        this.setSavePending(true);
        this.saveTimer = setTimeout(() => {
            if (!acceptsAck()) return;
            this.saveAttempt++;
            this.saveTimer = null;
            this.setSavePending(false);
            this.saveOutcomeUnknown = true;
            this.load();
            window.showNotification?.(this.t('common.saveUnknownHint', 'The previous save may have succeeded. Check the saved list before trying again. Saving again may create a duplicate.'), 'warning');
        }, 10000);
        this.emitWithAck(event, payload, acknowledgement => {
            clearTimeout(this.saveTimer);
            this.saveTimer = null;
            const saved = acknowledgement.command_set;
            if (saved) {
                const remaining = this.commandSets.filter(item => item.id !== saved.id);
                this.setCommandSets([...remaining, saved]);
                if (version === this.draftVersion && returnToConnection && !saved.parameters?.length) this.selectForConnection(saved.id);
            }
            if (isLegacyConversion && typeof ProfileManager !== 'undefined') {
                ProfileManager.upsertProfile(acknowledgement.profile);
                if (version === this.draftVersion) ProfileManager.clearLegacyCommands();
            }
            this.load();
            if (version === this.draftVersion) {
                this.setSavePending(false);
                if (snapshot === this.draftSnapshot()) {
                    this.draftActive = false;
                    if (returnToConnection) this.close({saved: true});
                    else this.showManagementList();
                } else if (saved) {
                    this.editingId = saved.id;
                    this.convertingProfileId = null;
                    this.draftBaseline = snapshot;
                }
            }
            window.showNotification?.(this.t('commandSets.saved', 'Command set saved'), 'success');
        }, () => {
            clearTimeout(this.saveTimer);
            this.saveTimer = null;
            if (version === this.draftVersion) this.setSavePending(false);
        }, acceptsAck);
    },

    duplicate(id) {
        this.emitWithAck('duplicate_command_set', { command_set_id: id });
    },

    async delete(id) {
        const commandSet = this.getById(id);
        if (!commandSet || !await this.confirmDialog({
            title: this.t('common.delete', 'Delete'),
            message: this.t('commandSets.confirmDelete', 'Delete "{name}"?').replace('{name}', () => commandSet.name),
            confirmLabel: this.t('common.delete', 'Delete'),
        })) return;
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
