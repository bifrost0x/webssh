const CommandLibrary = {
    commands: [],
    filteredCommands: [],
    currentOs: 'all',
    currentSource: 'all',
    currentImpact: 'recommended',
    searchQuery: '',
    editingCommandId: null,
    selectedCommandId: null,
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
    sourceCommands: [],
    translations: {},

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
        window.addEventListener?.('languageChanged', () => this.applyLanguage());
    },

    /** Built-in commands ship in English; their names and descriptions are translated from a per-language table. */
    async loadTranslations(language) {
        if (!language || language === 'en' || !/^[a-z]{2}$/.test(language)) return null;
        if (!(language in this.translations)) {
            const appRoot = (document.querySelector?.('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
            this.translations[language] = fetch(`${appRoot}/static/i18n/commands/${language}.json`, {credentials: 'same-origin', cache: 'no-cache'})
                .then(response => (response.ok ? response.json() : null))
                .catch(() => null);
        }
        return this.translations[language];
    },

    localize(commands, table) {
        return commands.map(command => {
            const entry = command.isSystem && table ? table[command.id] : null;
            if (!entry || typeof entry.name !== 'string' || typeof entry.description !== 'string') return command;
            return {...command, name: entry.name, description: entry.description, sourceName: command.name, sourceDescription: command.description};
        });
    },

    async applyLanguage() {
        const source = this.sourceCommands;
        const language = window.i18n?.getLanguage?.() || 'en';
        const table = await this.loadTranslations(language);
        // A newer list or language may have arrived while the table loaded.
        if (source !== this.sourceCommands || language !== (window.i18n?.getLanguage?.() || 'en')) return;
        this.publish(this.localize(source, table));
    },

    setupEventListeners() {
        this.setupLibraryLayout();
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

    setupLibraryLayout() {
        const toolbar = document.querySelector?.('#commandLibraryPanel .command-toolbar');
        if (!toolbar?.insertBefore) return;
        if (!document.getElementById('commandSourceFilter')) {
            const label = document.createElement('label');
            label.className = 'command-source-filter';
            const text = document.createElement('span');
            text.textContent = window.i18n?.t('commands.source') || 'Source';
            text.setAttribute('data-i18n', 'commands.source');
            const select = document.createElement('select');
            select.id = 'commandSourceFilter';
            select.className = 'form-control';
            [['all', 'commands.sourceAll', 'All sources'], ['system', 'commands.sourceSystem', 'System'], ['personal', 'commands.sourcePersonal', 'Personal']]
                .forEach(([value, key, fallback]) => {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = window.i18n?.t(key) || fallback;
                    option.setAttribute('data-i18n', key);
                    select.append(option);
                });
            select.value = this.currentSource;
            select.addEventListener('change', () => {
                this.currentSource = select.value;
                this.searchCommands(this.searchQuery);
            });
            label.append(text, select);
            toolbar.insertBefore(label, toolbar.querySelector('.management-panel-actions'));
        }
        if (!document.getElementById('commandImpactFilter')) {
            const label = document.createElement('label');
            label.className = 'command-source-filter';
            const text = document.createElement('span');
            text.textContent = window.i18n?.t('commandSafety.browse') || 'Browse';
            text.setAttribute('data-i18n', 'commandSafety.browse');
            const select = document.createElement('select');
            select.id = 'commandImpactFilter';
            select.className = 'form-control';
            for (const value of ['recommended', 'all']) {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = window.i18n?.t(`commandSafety.${value}`) || value;
                option.setAttribute('data-i18n', `commandSafety.${value}`);
                select.append(option);
            }
            select.value = this.currentImpact;
            select.addEventListener('change', () => {
                this.currentImpact = select.value;
                this.searchCommands(this.searchQuery);
            });
            label.append(text, select);
            toolbar.insertBefore(label, toolbar.querySelector('.management-panel-actions'));
        }
        const header = document.querySelector('#commandLibraryPanel .commands-table-header');
        if (header) {
            header.replaceChildren();
            [
                ['star_border', 'material-icons', null],
                [window.i18n?.t('commands.name') || 'Name', '', 'commands.name'],
                [window.i18n?.t('commands.preview') || 'Preview', '', 'commands.preview'],
                [window.i18n?.t('commands.operatingSystems') || 'Operating systems', '', 'commands.operatingSystems'],
                [window.i18n?.t('commands.source') || 'Source', '', 'commands.source'],
                [window.i18n?.t('common.actions') || 'Actions', '', 'common.actions'],
            ].forEach(([text, className, key]) => {
                const cell = document.createElement('span');
                cell.textContent = text;
                cell.className = className;
                if (key) cell.setAttribute('data-i18n', key);
                header.append(cell);
            });
        }
    },

    loadCommands() {
        if (window.socket) {
            window.socket.emit('list_commands', {
                os_filter: null
            });
        }
    },

    setCommands(commands) {
        this.sourceCommands = Array.isArray(commands) ? commands : [];
        this.publish(this.localize(this.sourceCommands, null));
        const language = window.i18n?.getLanguage?.() || 'en';
        if (language !== 'en') this.applyLanguage();
    },

    publish(commands) {
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
        const commands = this.commands.filter(command => (this.currentOs === 'all'
            || (command.os || ['all']).some(os => os.toLowerCase() === 'all' || os.toLowerCase() === this.currentOs.toLowerCase()))
            && (this.currentSource === 'all' || (command.isSystem ? 'system' : 'personal') === this.currentSource));
        if (!query) {
            this.filteredCommands = commands.filter(command => this.currentImpact === 'all'
                || !command.isSystem || this.commandSafety(command)?.impact === 'read-only');
        } else {
            const lowerQuery = query.toLowerCase();
            this.filteredCommands = commands.filter(cmd => {
                const matchesEnglish = (
                    cmd.name.toLowerCase().includes(lowerQuery) ||
                    `${cmd.command} ${cmd.parameters || ''}`.toLowerCase().includes(lowerQuery) ||
                    cmd.parameters.toLowerCase().includes(lowerQuery) ||
                    cmd.description.toLowerCase().includes(lowerQuery) ||
                    String(cmd.sourceName || '').toLowerCase().includes(lowerQuery) ||
                    String(cmd.sourceDescription || '').toLowerCase().includes(lowerQuery)
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
        if (!this.filteredCommands.some(command => command.id === this.selectedCommandId)) {
            this.selectedCommandId = null;
        }
        this.renderCommandDetails();

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
        const wrapper = container.closest('.commands-table-wrapper');
        if (wrapper) wrapper.onscroll = () => {
            if (wrapper.scrollTop + wrapper.clientHeight >= wrapper.scrollHeight - 40) this.renderNextChunk();
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
            row.dataset.commandId = cmd.id;
            row.classList.toggle('is-selected', cmd.id === this.selectedCommandId);
            if (cmd.isSystem) {
                row.classList.add('system-command');
            }

            row.innerHTML = `
                <div class="command-cell command-star"></div>
                <div class="command-cell command-name">
                    <button type="button" class="command-inspect-button" data-cmd-id="${this.escapeHtml(cmd.id)}" aria-controls="commandLibraryDetails" aria-expanded="${cmd.id === this.selectedCommandId}">${this.escapeHtml(cmd.name)}</button>
                    <div class="command-desc">${this.escapeHtml(cmd.description)}</div>
                    <span class="command-impact-label">${this.escapeHtml(this.impactLabel(cmd))}</span>
                </div>
                <div class="command-cell command-text">
                    <code>${this.escapeHtml(cmd.command + (cmd.parameters ? ` ${cmd.parameters}` : ''))}</code>
                </div>
                <div class="command-cell command-os-badges">
                    ${cmd.os.map(os => `<span class="os-badge">${this.escapeHtml(os)}</span>`).join('')}
                </div>
                <div class="command-cell command-source-label">
                    <span class="material-icons" aria-hidden="true">${cmd.isSystem ? 'lock' : 'person'}</span>
                    <span>${this.escapeHtml(window.i18n?.t(cmd.isSystem ? 'commands.sourceSystem' : 'commands.sourcePersonal') || (cmd.isSystem ? 'System' : 'Personal'))}</span>
                </div>
                <div class="command-cell command-actions">
                    ${cmd.isSystem ? `
                        <button type="button" class="btn-icon cmd-copy" data-cmd-id="${this.escapeHtml(cmd.id)}" title="${this.escapeHtml(window.SessionCommandLauncher.t('commands.copyToMine', 'Add to my commands'))}" aria-label="${this.escapeHtml(window.SessionCommandLauncher.t('commands.copyToMine', 'Add to my commands'))}"><span class="material-icons" aria-hidden="true">content_copy</span></button>
                    ` : `
                        <button type="button" class="btn-icon cmd-edit" data-cmd-id="${this.escapeHtml(cmd.id)}" title="${this.escapeHtml(window.SessionCommandLauncher.t('commands.edit', 'Edit'))}" aria-label="${this.escapeHtml(window.SessionCommandLauncher.t('commands.edit', 'Edit'))}"><span class="material-icons" aria-hidden="true">edit</span></button>
                    `}
                    <details class="command-row-menu"><summary class="btn-icon" aria-label="${this.escapeHtml(window.i18n?.t('common.actions') || 'Actions')}"><span class="material-icons" aria-hidden="true">more_horiz</span></summary><div class="command-row-menu-items" popover="auto">
                        <button type="button" class="btn btn-secondary cmd-details" data-cmd-id="${this.escapeHtml(cmd.id)}">${this.escapeHtml(window.i18n?.t('commands.details') || 'Command details')}</button>
                        ${cmd.isSystem ? '' : `<button type="button" class="btn btn-secondary cmd-delete" data-cmd-id="${this.escapeHtml(cmd.id)}">${this.escapeHtml(window.i18n?.t('commands.delete') || 'Delete')}</button>`}
                    </div></details>
                </div>
            `;

            row.classList.add('command-kind-command');
            const favorite = window.CommandWorkspace?.favoriteButton?.('command', cmd.id);
            if (favorite) row.querySelector('.command-star')?.append(favorite);
            const menu = row.querySelector('.command-row-menu');
            const menuItems = row.querySelector('.command-row-menu-items');
            if (menu && menuItems?.showPopover) {
                menu.addEventListener('toggle', () => {
                    if (!menu.open) { menuItems.hidePopover(); return; }
                    menuItems.showPopover();
                    const anchor = menu.getBoundingClientRect();
                    menuItems.style.left = `${Math.max(8, anchor.right - menuItems.offsetWidth)}px`;
                    menuItems.style.top = `${Math.max(8, Math.min(anchor.bottom + 4, window.innerHeight - menuItems.offsetHeight - 8))}px`;
                });
                menuItems.addEventListener('toggle', event => {
                    if (event.newState === 'closed') menu.open = false;
                });
            }
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
                const row = event.target.closest('.command-row[data-command-id]');
                if (!row || !container.contains(row)
                    || event.target.closest('button, a, input, select, textarea, summary, details')) return;
                const selection = window.getSelection?.();
                if (selection?.type === 'Range' && selection.containsNode(row, true)) return;
                this.selectCommand(row.dataset.commandId);
                return;
            }
            const cmdId = btn.dataset.cmdId;
            const menu = btn.closest('.command-row-menu');
            if (menu) menu.open = false;
            if (btn.classList.contains('cmd-copy')) {
                this.copyCommand(cmdId);
            } else if (btn.classList.contains('cmd-edit')) {
                this.editCommand(cmdId);
            } else if (btn.classList.contains('cmd-delete')) {
                this.deleteCommand(cmdId);
            } else if (btn.classList.contains('command-inspect-button') || btn.classList.contains('cmd-details')) {
                this.selectCommand(cmdId);
            }
        };
    },

    commandSafety(command) {
        const safety = command.safety;
        return command.isSystem && safety && safety.command === command.command
            && safety.parameters === (command.parameters || '')
            && ['read-only', 'changes-system', 'deletes-data', 'network-load'].includes(safety.impact)
            ? safety : null;
    },

    impactLabel(command) {
        const impact = this.commandSafety(command)?.impact || 'unknown';
        return window.i18n?.t(`commandSafety.${impact}`) || impact;
    },

    commandSourceLabel(command) {
        const key = command.isSystem ? 'commands.systemSource' : 'commands.personalSource';
        return window.i18n?.t(key) || (command.isSystem ? 'System · fixed template' : 'Personal');
    },

    selectCommand(commandId) {
        if (!this.commands.some(command => command.id === commandId)) return;
        this.selectedCommandId = commandId;
        document.getElementById('commandsList')?.querySelectorAll('[data-command-id]').forEach(row => {
            const selected = row.dataset.commandId === commandId;
            row.classList.toggle('is-selected', selected);
            row.querySelector('.command-inspect-button')?.setAttribute('aria-expanded', String(selected));
        });
        this.renderCommandDetails();
        document.getElementById('commandLibraryDetails')?.focus({preventScroll: true});
    },

    renderCommandDetails() {
        const panel = document.getElementById('commandLibraryPanel');
        if (!panel?.append) return;
        const command = this.commands.find(item => item.id === this.selectedCommandId);
        panel.classList.toggle('has-command-details', Boolean(command));
        let details = document.getElementById('commandLibraryDetails');
        if (!command) {
            details?.remove();
            return;
        }
        if (!details) {
            details = document.createElement('aside');
            details.id = 'commandLibraryDetails';
            details.className = 'command-library-details';
            details.tabIndex = -1;
            details.setAttribute('aria-label', window.i18n?.t('commands.details') || 'Command details');
            panel.append(details);
        }
        details.replaceChildren();
        const header = document.createElement('div');
        header.className = 'management-inspector-heading';
        const title = document.createElement('h3');
        title.textContent = command.name;
        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn-icon inspector-return';
        const closeIcon = document.createElement('span');
        closeIcon.className = 'material-icons inspector-return-close';
        closeIcon.setAttribute('aria-hidden', 'true');
        closeIcon.textContent = 'close';
        const arrow = document.createElement('span');
        arrow.className = 'material-icons inspector-return-arrow';
        arrow.setAttribute('aria-hidden', 'true');
        arrow.textContent = 'arrow_back';
        const label = document.createElement('span');
        label.className = 'inspector-return-label';
        label.textContent = window.i18n?.t('common.backToList') || 'Back to list';
        close.append(closeIcon, arrow, label);
        close.setAttribute('aria-label', label.textContent);
        close.onclick = () => {
            this.selectedCommandId = null;
            this.renderCommandDetails();
            document.getElementById('commandsList')?.querySelectorAll('[data-command-id]').forEach(row => {
                row.classList.remove('is-selected');
                const button = row.querySelector('.command-inspect-button');
                button?.setAttribute('aria-expanded', 'false');
                if (row.dataset.commandId === command.id) button?.focus({preventScroll: true});
            });
        };
        header.append(title, close);
        details.append(header);
        const safety = this.commandSafety(command);
        const field = (key, fallback, value, code = false) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'command-detail-field';
            const label = document.createElement('h4');
            label.textContent = window.i18n?.t(key) || fallback;
            const content = document.createElement(code ? 'pre' : 'p');
            content.textContent = value || '—';
            wrapper.append(label, content);
            return wrapper;
        };
        details.append(field('commands.command', 'Command', [command.command, command.parameters].filter(Boolean).join(' '), true));
        const metadata = document.createElement('div');
        metadata.className = 'command-detail-metadata';
        const impact = document.createElement('span');
        impact.className = 'command-impact-label';
        impact.dataset.impact = safety?.impact || 'unknown';
        impact.textContent = this.impactLabel(command);
        const source = document.createElement('span');
        source.className = 'command-source-label';
        source.textContent = this.commandSourceLabel(command);
        metadata.append(impact, source);
        details.append(metadata);
        const description = document.createElement('p');
        description.className = 'command-detail-description';
        description.textContent = command.description || '—';
        details.append(description);
        const prerequisites = document.createElement('p');
        prerequisites.className = 'command-detail-prerequisites';
        prerequisites.textContent = safety
            ? `${window.i18n?.t('commandSafety.requires') || 'Required on target'}: ${safety.tool} · ${(command.os || ['all']).join(', ')}`
            : `${window.i18n?.t('commands.operatingSystems') || 'Operating systems'}: ${(command.os || ['all']).join(', ')}`;
        details.append(prerequisites);
        const guidance = document.createElement('details');
        guidance.className = 'command-detail-guidance';
        const summary = document.createElement('summary');
        summary.textContent = window.i18n?.t('commandSafety.guidance') || 'Usage and template details';
        guidance.append(summary);
        if (safety) {
            for (const key of ['prerequisites', 'scope']) {
                const note = document.createElement('p');
                note.className = 'command-template-hint';
                note.textContent = window.i18n?.t(`commandSafety.${key}`) || (key === 'scope'
                    ? 'Impact describes this exact template, not a safety guarantee. Changed arguments, interactive actions and sudo can change the effect.'
                    : 'Check the installed tool, shell, permissions and arguments before use.');
                guidance.append(note);
            }
        }
        if (command.parameters) {
            guidance.append(field('commands.command', 'Command', command.command, true));
            guidance.append(field('commands.parameters', 'Parameters', command.parameters, true));
        }
        if (command.isSystem && command.parameters) {
            const notice = document.createElement('p');
            notice.className = 'command-template-hint';
            notice.textContent = window.i18n?.t('commands.templateHint') || 'Library defaults, not values detected on this host. Review arguments before insertion.';
            details.append(notice);
        }
        const actions = document.createElement('div');
        actions.className = 'management-inspector-actions';
        const action = (key, fallback, callback, primary = false) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = `btn ${primary ? 'btn-primary' : 'btn-secondary'}`;
            button.textContent = window.i18n?.t(key) || fallback;
            button.onclick = callback;
            actions.append(button);
        };
        if (command.isSystem) action('commands.copyToMine', 'Add to my commands', () => this.copyCommand(command.id), true);
        else {
            action('commands.edit', 'Edit', () => this.editCommand(command.id), true);
            action('commands.delete', 'Delete', () => this.deleteCommand(command.id));
        }
        const favorite = window.CommandWorkspace?.favoriteButton?.('command', command.id);
        if (favorite) actions.append(favorite);
        details.append(actions);
        const hint = document.createElement('p');
        hint.className = 'command-execution-hint';
        const hintIcon = document.createElement('span');
        hintIcon.className = 'material-icons';
        hintIcon.setAttribute('aria-hidden', 'true');
        hintIcon.textContent = 'info';
        const hintText = document.createElement('span');
        hintText.setAttribute('data-i18n', 'commands.executionHint');
        hintText.textContent = window.i18n?.t('commands.executionHint') || 'Run commands from the command tool in a session.';
        hint.append(hintIcon, hintText);
        guidance.append(hint);
        details.append(guidance);
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

    hasUnsavedChanges() {
        return document.getElementById('commandFormModal')?.classList.contains('show')
            && this.formBaseline !== null && this.formSnapshot() !== this.formBaseline;
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
        return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
};

window.CommandLibrary = CommandLibrary;
