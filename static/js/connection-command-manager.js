(function (root, factory) {
    const manager = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = manager;
    }
    if (root && root.document) {
        root.ConnectionCommandManager = manager;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    const manager = {
        mode: 'none',
        freeText: '',
        selectedCommandId: '',
        parametersOverride: null,
        selectedCommandSetId: '',

        t(key, fallback) {
            if (root?.i18n) {
                const value = root.i18n.t(key);
                if (value && value !== key) return value;
            }
            return fallback;
        },

        init() {
            const document = root.document;
            if (!document) return;

            document.querySelectorAll('[data-command-mode]').forEach(button => {
                button.addEventListener('click', () => this.setMode(button.dataset.commandMode));
            });
            document.getElementById('commandSetSelect')?.addEventListener('change', event => {
                this.selectedCommandSetId = event.target.value || '';
                root.CommandSetManager?.selectForConnection(this.selectedCommandSetId);
                this.render();
            });
            document.getElementById('connectionCommandSelect')?.addEventListener('change', event => {
                this.selectedCommandId = event.target.value || '';
                this.parametersOverride = null;
                this.render();
            });
            document.getElementById('connectionCommandParameters')?.addEventListener('input', event => {
                this.parametersOverride = event.target.value;
                this.renderPreview();
            });
            document.getElementById('startupCommandsInput')?.addEventListener('input', event => {
                this.freeText = event.target.value;
                this.renderPreview();
            });
            document.getElementById('manageCommandSetsBtn')?.addEventListener('click', () => {
                root.CommandSetManager?.openManagement();
            });
            document.getElementById('editSelectedCommandSetBtn')?.addEventListener('click', () => {
                if (this.selectedCommandSetId) {
                    root.CommandSetManager?.openBuilder(this.selectedCommandSetId, true);
                }
            });
            document.getElementById('editSelectedCommandBtn')?.addEventListener('click', () => {
                if (this.selectedCommandId) {
                    root.CommandLibrary?.openEditor(
                        this.selectedCommandId, 'connectionModal'
                    );
                }
            });
            root.addEventListener?.('languageChanged', () => this.render());
            this.render();
        },

        inferProfileMode(profile) {
            if (profile?.startup_mode) return profile.startup_mode;
            if (profile?.command_set_id) return 'command_set';
            if (profile?.command_id) return 'command';
            if (profile?.startup_commands) return 'free_text';
            return 'none';
        },

        setMode(mode, shouldRender = true) {
            const valid = ['none', 'command_set', 'command', 'free_text'];
            this.mode = valid.includes(mode) ? mode : 'none';
            if (shouldRender) this.render();
        },

        applyProfile(profile) {
            this.mode = this.inferProfileMode(profile);
            this.freeText = profile?.startup_commands || '';
            this.selectedCommandId = profile?.command_id || '';
            this.parametersOverride = Object.prototype.hasOwnProperty.call(
                profile || {}, 'parameters_override'
            ) ? profile.parameters_override : null;
            this.selectedCommandSetId = profile?.command_set_id || '';
            root.CommandSetManager?.selectForConnection(this.selectedCommandSetId);
            this.render();
        },

        clear() {
            this.mode = 'none';
            this.freeText = '';
            this.selectedCommandId = '';
            this.parametersOverride = null;
            this.selectedCommandSetId = '';
            root.CommandSetManager?.selectForConnection('');
            this.render();
        },

        getPayload() {
            if (this.mode === 'free_text') {
                return {
                    startup_mode: 'free_text',
                    startup_commands: this.freeText,
                };
            }
            if (this.mode === 'command') {
                const payload = {
                    startup_mode: 'command',
                    command_id: this.selectedCommandId,
                };
                if (this.parametersOverride !== null) {
                    payload.parameters_override = this.parametersOverride;
                }
                return payload;
            }
            if (this.mode === 'command_set') {
                return {
                    startup_mode: 'command_set',
                    command_set_id: this.selectedCommandSetId,
                };
            }
            return { startup_mode: 'none' };
        },

        commands() {
            return Array.isArray(root.CommandLibrary?.commands)
                ? root.CommandLibrary.commands
                : [];
        },

        commandSets() {
            return Array.isArray(root.CommandSetManager?.commandSets)
                ? root.CommandSetManager.commandSets
                : [];
        },

        selectedCommand() {
            return this.commands().find(command => command.id === this.selectedCommandId) || null;
        },

        selectedCommandSet() {
            return this.commandSets().find(commandSet => (
                commandSet.id === this.selectedCommandSetId
            )) || null;
        },

        renderOptions() {
            const document = root.document;
            if (!document) return;

            const commandSelect = document.getElementById('connectionCommandSelect');
            if (commandSelect) {
                commandSelect.replaceChildren();
                const placeholder = document.createElement('option');
                placeholder.value = '';
                placeholder.textContent = this.t('commandModes.selectCommand', 'Select a Command');
                commandSelect.appendChild(placeholder);
                this.commands().forEach(command => {
                    const option = document.createElement('option');
                    option.value = command.id;
                    option.textContent = command.name;
                    commandSelect.appendChild(option);
                });
                commandSelect.value = this.selectedCommandId;
            }

            const commandSetSelect = document.getElementById('commandSetSelect');
            if (commandSetSelect) {
                commandSetSelect.value = this.selectedCommandSetId;
            }
        },

        render() {
            const document = root.document;
            if (!document) return;
            this.renderOptions();

            document.querySelectorAll('[data-command-mode]').forEach(button => {
                const active = button.dataset.commandMode === this.mode;
                button.classList.toggle('active', active);
                button.setAttribute('aria-pressed', String(active));
            });
            const panels = {
                command_set: 'connectionCommandSetPanel',
                command: 'connectionSingleCommandPanel',
                free_text: 'connectionFreeTextPanel',
            };
            Object.entries(panels).forEach(([mode, id]) => {
                document.getElementById(id)?.classList.toggle('hidden', this.mode !== mode);
            });

            const freeText = document.getElementById('startupCommandsInput');
            if (freeText && freeText.value !== this.freeText) freeText.value = this.freeText;
            const parameters = document.getElementById('connectionCommandParameters');
            const command = this.selectedCommand();
            if (parameters) {
                const value = this.parametersOverride === null
                    ? (command?.parameters || '')
                    : this.parametersOverride;
                if (parameters.value !== value) parameters.value = value;
                parameters.placeholder = command?.parameters || '';
                parameters.disabled = !command;
            }

            document.getElementById('editSelectedCommandBtn')?.toggleAttribute(
                'disabled', !command
            );
            document.getElementById('editSelectedCommandSetBtn')?.toggleAttribute(
                'disabled', !this.selectedCommandSet()
            );
            this.renderPreview();
        },

        renderPreview() {
            const document = root.document;
            if (!document) return;
            const preview = document.getElementById('connectionCommandPreview');
            if (!preview) return;

            let text = '';
            let error = false;
            if (this.mode === 'none') {
                text = this.t('commandSets.noSelectionHint', 'No commands will run after connecting.');
            } else if (this.mode === 'free_text') {
                text = this.freeText || this.t('commandModes.emptyFreeText', 'Enter commands to preview them.');
            } else if (this.mode === 'command') {
                const command = this.selectedCommand();
                if (!command) {
                    text = this.t('commandModes.missingCommand', 'Select an available Command.');
                    error = Boolean(this.selectedCommandId);
                } else {
                    const parameters = this.parametersOverride === null
                        ? (command.parameters || '')
                        : this.parametersOverride;
                    text = command.command + (parameters ? ` ${parameters}` : '');
                }
            } else {
                const commandSet = this.selectedCommandSet();
                if (!commandSet) {
                    text = this.t('commandSets.missingSetHint', 'Select an available Command Set.');
                    error = Boolean(this.selectedCommandSetId);
                } else if (commandSet.resolution_error) {
                    text = commandSet.resolution_error;
                    error = true;
                } else {
                    text = commandSet.resolved_command || commandSet.steps
                        .map(step => root.CommandSetManager?.stepSummary(step) || '')
                        .join(' && ');
                }
            }

            preview.textContent = text;
            preview.classList.toggle('empty', this.mode === 'none' || !text);
            preview.classList.toggle('error', error);
        },

        onDataChanged() {
            this.render();
            root.ProfileManager?.renderEditorSelects();
        },
    };

    return manager;
}));
