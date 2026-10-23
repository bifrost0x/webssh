(function (root, factory) {
    const launcher = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = launcher;
    }
    if (root && root.document) {
        root.SessionCommandLauncher = launcher;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    function hasLineBreak(value) {
        return /[\r\n]/.test(value);
    }

    function prefixWithSudo(value) {
        const stripped = value.trimStart();
        const sudoBoundary = stripped.charAt(4);
        const alreadyPrefixed = stripped === 'sudo'
            || (
                stripped.startsWith('sudo')
                && ' \t;&|()<>'.includes(sudoBoundary)
            );
        if (!stripped || alreadyPrefixed) return value;
        const leading = value.slice(0, value.length - stripped.length);
        return `${leading}sudo ${stripped}`;
    }

    function insertTextFor(entry, useSudo) {
        return useSudo === true ? entry?.sudoInsertText : entry?.insertText;
    }

    function getSessionManager() {
        return typeof SessionManager !== 'undefined'
            ? SessionManager
            : root.SessionManager;
    }

    function getCommandLibrary() {
        return typeof CommandLibrary !== 'undefined'
            ? CommandLibrary
            : root.CommandLibrary;
    }

    function getTerminalManager() {
        return typeof TerminalManager !== 'undefined'
            ? TerminalManager
            : root.TerminalManager;
    }

    function commandEntry(command) {
        const base = typeof command?.command === 'string' ? command.command : '';
        const parameters = typeof command?.parameters === 'string' ? command.parameters : '';
        const insertText = base + (parameters ? ` ${parameters}` : '');
        const available = Boolean(insertText.trim()) && !hasLineBreak(insertText);
        return {
            command: base,
            parameters,
            type: 'command',
            id: command?.id || '',
            name: command?.name || base || '',
            description: command?.description || '',
            preview: insertText,
            insertText,
            sudoInsertText: prefixWithSudo(insertText),
            available,
            unavailableReason: available ? null : (hasLineBreak(insertText) ? 'multiline' : 'empty'),
        };
    }

    function commandSetEntry(commandSet) {
        const resolved = typeof commandSet?.resolved_command === 'string'
            ? commandSet.resolved_command
            : '';
        let unavailableReason = null;
        if (commandSet?.resolution_error) unavailableReason = 'unresolved';
        else if (hasLineBreak(resolved)) unavailableReason = 'multiline';
        else if (!resolved.trim()) unavailableReason = 'empty';
        return {
            type: 'set',
            parameters: Array.isArray(commandSet?.parameters) ? commandSet.parameters : [],
            id: commandSet?.id || '',
            name: commandSet?.name || '',
            description: commandSet?.description || '',
            preview: resolved || commandSet?.resolution_error || '',
            insertText: resolved,
            sudoInsertText: typeof commandSet?.sudo_resolved_command === 'string'
                ? commandSet.sudo_resolved_command
                : '',
            available: unavailableReason === null,
            unavailableReason,
        };
    }

    function buildLauncherEntries(commands, commandSets, query = '') {
        const entries = [
            ...(Array.isArray(commandSets) ? commandSets : []).map(commandSetEntry),
            ...(Array.isArray(commands) ? commands : []).map(commandEntry),
        ];
        const needle = String(query || '').trim().toLocaleLowerCase();
        if (!needle) return entries;
        return entries.filter(entry => (
            `${entry.name} ${entry.description} ${entry.preview}`
                .toLocaleLowerCase()
                .includes(needle)
        ));
    }

    function sessionLabel(session, fallback) {
        if (!session) return fallback;
        if (session.displayName) return session.displayName;
        if (session.name) return session.name;
        if (session.username && session.host) return `${session.username}@${session.host}`;
        return fallback;
    }

    function createSessionCommandController(dependencies = {}) {
        const previews = new WeakSet();
        let previewEpoch = 0;
        const snapshot = id => JSON.stringify((dependencies.getCommandSets?.() || []).find(item => item.id === id));
        const active = id => !dependencies.getActiveSession || dependencies.getActiveSession() === id;
        return {
            invalidatePreviews() { previewEpoch++; },
            entries(query = '') {
                return buildLauncherEntries(
                    dependencies.getCommands?.() || [],
                    dependencies.getCommandSets?.() || [],
                    query
                );
            },

            async preview(sessionId, id, values, useSudo = false) {
                const session = dependencies.getSession?.(sessionId);
                const before = snapshot(id);
                const epoch = previewEpoch;
                const entry = this.entries().find(item => item.type === 'set' && item.id === id);
                if (!session?.connected || !active(sessionId) || !entry?.parameters.length) {
                    return { ok: false };
                }
                let response;
                try {
                    response = await dependencies.resolveParameters?.(id, values, useSudo);
                } catch {
                    return { ok: false };
                }
                if (!response?.success || typeof response.resolved_command !== 'string'
                        || !response.resolved_command.trim() || response.resolved_command.length > 4096
                        || /[\x00-\x1f\x7f-\x9f]/.test(response.resolved_command)
                        || dependencies.getSession?.(sessionId) !== session || !session.connected
                        || !active(sessionId) || before !== snapshot(id) || epoch !== previewEpoch) {
                    return { ok: false, error: response?.error };
                }
                const preview = Object.freeze({ sessionId, id, session, before, useSudo, epoch, command: response.resolved_command });
                previews.add(preview);
                return { ok: true, preview };
            },

            async insert(sessionId, type, id, options = {}) {
                const session = dependencies.getSession?.(sessionId);
                if (!session || !session.connected || !active(sessionId)) {
                    return { ok: false, reason: 'session-unavailable' };
                }
                let entry = this.entries().find(candidate => (
                    candidate.type === type && candidate.id === id
                ));
                if (entry?.type === 'command' && options.parameters !== undefined) {
                    if (typeof options.parameters !== 'string' || options.parameters.length > 4096) {
                        return { ok: false, reason: 'entry-unavailable' };
                    }
                    entry = commandEntry({ ...entry, parameters: options.parameters });
                }
                let insertText = insertTextFor(entry, options.useSudo);
                if (entry?.type === 'set' && entry.parameters.length) {
                    const reviewed = options.preview;
                    if (!reviewed || !previews.has(reviewed) || reviewed.session !== session
                            || reviewed.sessionId !== sessionId || reviewed.id !== id
                            || reviewed.before !== snapshot(id) || reviewed.epoch !== previewEpoch) {
                        return { ok: false, reason: 'preview-required' };
                    }
                    previews.delete(reviewed);
                    insertText = reviewed.command;
                    entry = { ...entry, available: true };
                }
                if (!entry || !entry.available || !insertText || hasLineBreak(insertText)) {
                    return { ok: false, reason: entry?.unavailableReason || 'entry-unavailable' };
                }

                try {
                    if (!dependencies.emitInput || await dependencies.emitInput(sessionId, insertText) === false) {
                        return { ok: false, reason: 'send-failed' };
                    }
                } catch {
                    return { ok: false, reason: 'send-failed' };
                }
                dependencies.focusSession?.(sessionId);
                const label = sessionLabel(session, sessionId);
                const message = dependencies.insertedMessage
                    ? dependencies.insertedMessage(label)
                    : `Inserted into ${label}`;
                dependencies.notify?.(message, 'success');
                return { ok: true };
            },
        };
    }

    const launcher = {
        buildLauncherEntries,
        createSessionCommandController,
        controller: null,
        sessionId: null,
        searchQuery: '',
        trigger: null,
        panel: null,
        mount: null,
        popup: null,
        activeSessionId: null,
        initialized: false,
        useSudo: false,
        parameterDrafts: new Map(),
        expandedParameters: new Set(),
        resultsScrollTop: 0,
        favorites: new Set(),
        recent: [],
        activeSection: 'library',
        preferencesScope: null,

        ensurePreferences() {
            if (this.preferencesScope !== this.preferenceKey()) {
                this.loadPreferences();
                this.parameterDrafts.clear();
                this.expandedParameters.clear();
                this.controller?.invalidatePreviews();
            }
        },

        sectionEntries(entries) {
            this.ensurePreferences();
            return entries.filter(entry => this.activeSection === 'favorites'
                ? this.favorites.has(this.entryKey(entry))
                : entry.type === (this.activeSection === 'sets' ? 'set' : 'command'));
        },

        preferenceKey() {
            const scope = String(root.document?.body?.dataset?.connectionHistoryScope || 'local');
            return `webssh:session-commands:${scope}`;
        },

        entryKey(entry) {
            return `${entry?.type || ''}:${entry?.id || ''}`;
        },

        loadPreferences() {
            this.preferencesScope = this.preferenceKey();
            try {
                const saved = JSON.parse(root.localStorage?.getItem(this.preferenceKey()) || '{}');
                this.favorites = new Set(Array.isArray(saved.favorites) ? saved.favorites.slice(0, 100) : []);
                this.recent = Array.isArray(saved.recent) ? saved.recent.slice(0, 12) : [];
            } catch {
                this.favorites = new Set();
                this.recent = [];
            }
        },

        savePreferences() {
            try {
                root.localStorage?.setItem(this.preferenceKey(), JSON.stringify({
                    favorites: Array.from(this.favorites).slice(0, 100),
                    recent: this.recent.slice(0, 12),
                }));
            } catch {
                // Storage can be unavailable in hardened or private browser contexts.
            }
        },

        rememberUse(entry) {
            this.ensurePreferences();
            const key = this.entryKey(entry);
            this.recent = [key, ...this.recent.filter(candidate => candidate !== key)].slice(0, 12);
            this.savePreferences();
        },

        toggleFavorite(entry) {
            this.ensurePreferences();
            if (!['command', 'set'].includes(entry?.type) || typeof entry?.id !== 'string' || !entry.id) return;
            const key = this.entryKey(entry);
            if (this.favorites.has(key)) this.favorites.delete(key);
            else if (this.favorites.size < 100) this.favorites.add(key);
            this.savePreferences();
            if (root.CustomEvent) root.dispatchEvent?.(new root.CustomEvent('command-favorites-change'));
            this.render();
        },

        t(key, fallback) {
            const translated = root.i18n?.t(key);
            return translated && translated !== key ? translated : fallback;
        },

        init() {
            const document = root.document;
            if (!document || this.initialized) return;
            this.initialized = true;
            this.loadPreferences();
            this.trigger = document.getElementById('contextCommandsTab');
            this.panel = document.getElementById('sessionCommandsPanel');
            this.mount = document.getElementById('sessionCommandsMount');
            if (!this.trigger || !this.panel || !this.mount) return;
            this.controller = createSessionCommandController({
                getSession: sessionId => getSessionManager()?.getSession(sessionId),
                getActiveSession: () => getSessionManager()?.getActiveSession(),
                getCommands: () => getCommandLibrary()?.commands || [],
                getCommandSets: () => root.CommandSetManager?.commandSets || [],
                resolveParameters: (id, values, useSudo) => new Promise(resolve => {
                    if (!root.socket?.connected) { resolve({ success: false }); return; }
                    root.socket.timeout(10000).emit('resolve_command_set_parameters', {
                        command_set_id: id, values, use_sudo: useSudo,
                    }, (error, response) => resolve(error ? { success: false } : response));
                }),
                emitInput: (sessionId, data) => root.SSHInput
                    ? root.SSHInput.send(sessionId, data)
                    : root.socket?.emit('ssh_input', {
                        session_id: sessionId,
                        data,
                    }),
                focusSession: sessionId => getTerminalManager()?.terminals?.[sessionId]?.focus(),
                notify: (message, type) => root.showNotification?.(message, type),
                insertedMessage: label => this.t(
                    'sessionCommands.inserted',
                    'Command inserted into {session}. Press Enter to run it.'
                ).replace('{session}', label),
            });

            root.addEventListener?.('session-workspace-change', () => this.sync());
            root.socket?.on?.('disconnect', () => this.sync());
            root.socket?.on?.('connected', () => this.sync());
            root.addEventListener?.('session-removed', event => {
                if (event.detail?.sessionId === this.sessionId) this.close(false);
                root.setTimeout?.(() => this.sync(), 0);
            });
            root.addEventListener?.('languageChanged', () => this.sync());
            root.socket?.on?.('commands_list', () => root.setTimeout?.(() => this.render(), 0));
            root.socket?.on?.('command_sets_list', () => root.setTimeout?.(() => this.render(), 0));
            document.addEventListener('workspace-context-change', event => {
                const active = event.detail?.activeContext === 'commands';
                this.setDrawerOpen(active);
                if (active) this.open(this.activeSessionId);
            });
            document.addEventListener('session-command-request-close', () => {
                if (root.workspaceLayoutController?.getState?.().activeContext === 'commands') {
                    root.workspaceLayoutController.closeContext('programmatic');
                }
            });
            this.sync();
            if (root.workspaceLayoutController?.getState?.().activeContext === 'commands') {
                this.setDrawerOpen(true);
                this.open(this.activeSessionId);
            }
        },

        sync() {
            this.controller?.invalidatePreviews();
            const sessionManager = getSessionManager();
            const sessionId = sessionManager?.getActiveSession?.();
            const session = sessionId ? sessionManager.getSession(sessionId) : null;
            const connected = Boolean(root.socket?.connected !== false && sessionId && session?.connected);
            this.activeSessionId = connected ? sessionId : null;
            this.trigger.disabled = false;
            if (this.popup) {
                this.sessionId = this.activeSessionId;
                this.render();
            }
        },

        setDrawerOpen(open) {
            const normalized = Boolean(open);
            this.panel.hidden = !normalized;
            this.panel.setAttribute('aria-hidden', String(!normalized));
        },

        open(sessionId) {
            const session = getSessionManager()?.getSession(sessionId);
            this.sessionId = session?.connected ? sessionId : null;
            this.setDrawerOpen(true);
            if (this.popup) { this.render(); return; }

            const popup = root.document.createElement('section');
            popup.className = 'session-command-popover';
            popup.setAttribute('role', 'region');
            popup.setAttribute('aria-label', this.t('sessionCommands.title', 'Insert Commands'));
            this.mount.replaceChildren(popup);
            this.popup = popup;
            this.render();
            root.setTimeout?.(() => popup.querySelector('input')?.focus(), 0);
        },

        close(restoreFocus = false) {
            this.resultsScrollTop = this.popup?.querySelector('.session-command-results')?.scrollTop || this.resultsScrollTop;
            this.popup?.remove();
            this.mount?.replaceChildren();
            this.popup = null;
            this.sessionId = null;
            if (this.panel) this.setDrawerOpen(false);
            if (restoreFocus) this.trigger?.focus();
        },

        render() {
            this.ensurePreferences();
            if (!this.popup) return;
            const document = root.document;
            const popup = this.popup;
            const session = getSessionManager()?.getSession(this.sessionId);
            const canInsert = Boolean(root.socket?.connected !== false && session?.connected);
            const oldList = popup.querySelector('.session-command-results');
            if (oldList) this.resultsScrollTop = oldList.scrollTop || 0;
            const focused = document.activeElement;
            const focusKey = focused?.dataset?.commandParameter;
            const searchFocused = focused?.className === 'session-command-search';
            const selection = focused ? [focused.selectionStart, focused.selectionEnd] : null;
            popup.replaceChildren();

            const tabs = document.createElement('div');
            tabs.className = 'session-command-tabs';
            tabs.setAttribute('role', 'tablist');
            const sections = [
                ['library', 'sessionCommands.library', 'Library', 'command-kind-command'],
                ['favorites', 'sessionCommands.favorites', 'Favorites', 'command-favorite'],
                ['sets', 'sessionCommands.sets', 'Command sets', 'command-kind-set'],
            ];
            sections.forEach(([name, key, fallback, kind], index) => {
                const tab = document.createElement('button');
                tab.type = 'button';
                tab.className = `session-command-tab ${kind}`;
                tab.id = `session-command-tab-${name}`;
                tab.setAttribute('role', 'tab');
                tab.setAttribute('aria-controls', 'session-command-results');
                tab.setAttribute('aria-selected', String(this.activeSection === name));
                tab.tabIndex = this.activeSection === name ? 0 : -1;
                tab.classList.toggle('active', this.activeSection === name);
                tab.textContent = this.t(key, fallback);
                const select = section => { this.activeSection = section; this.searchQuery = ''; this.resultsScrollTop = 0; this.controller?.invalidatePreviews(); this.render(); };
                tab.addEventListener('click', () => select(name));
                tab.addEventListener('keydown', event => {
                    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
                    event.preventDefault();
                    const next = event.key === 'Home' ? 0 : event.key === 'End' ? 2 : (index + (event.key === 'ArrowRight' ? 1 : -1) + 3) % 3;
                    select(sections[next][0]);
                    document.getElementById(`session-command-tab-${sections[next][0]}`)?.focus();
                });
                tabs.append(tab);
            });
            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'session-command-search';
            search.placeholder = this.t(
                `sessionCommands.search${this.activeSection === 'sets' ? 'Sets' : this.activeSection === 'favorites' ? 'Favorites' : 'Library'}`,
                this.activeSection === 'sets' ? 'Search command sets...' : this.activeSection === 'favorites' ? 'Search favorites...' : 'Search library...'
            );
            search.setAttribute('aria-label', search.placeholder);
            search.value = this.searchQuery;
            search.addEventListener('input', event => {
                this.searchQuery = event.target.value;
                const results = this.popup.querySelector('.session-command-results');
                if (results) results.scrollTop = 0;
                this.resultsScrollTop = 0;
                this.render();
                const nextSearch = this.popup?.querySelector('.session-command-search');
                nextSearch?.focus();
                nextSearch?.setSelectionRange(this.searchQuery.length, this.searchQuery.length);
            });

            const sudoOption = document.createElement('label');
            sudoOption.className = 'session-command-sudo-option';
            const sudoInput = document.createElement('input');
            sudoInput.type = 'checkbox';
            sudoInput.className = 'session-command-sudo-input';
            sudoInput.checked = this.useSudo;
            sudoInput.addEventListener('change', event => {
                this.useSudo = event.target.checked === true;
                this.render();
                this.popup?.querySelector('.session-command-sudo-input')?.focus();
            });
            const sudoText = document.createElement('span');
            sudoText.textContent = this.t(
                'sessionCommands.useSudo',
                'Insert with sudo'
            );
            sudoOption.append(sudoInput, sudoText);

            const list = document.createElement('div');
            list.className = 'session-command-results';
            list.id = 'session-command-results';
            list.setAttribute('role', 'tabpanel');
            list.setAttribute('aria-labelledby', `session-command-tab-${this.activeSection}`);
            const entries = this.sectionEntries(this.controller.entries(this.searchQuery));
            if (!entries.length) {
                const empty = document.createElement('p');
                empty.className = 'session-command-empty';
                empty.textContent = this.searchQuery.trim()
                    ? this.t('sessionCommands.noResults', 'No matching entries.')
                    : this.activeSection === 'favorites'
                        ? this.t('empty.favorites', 'No favorites yet. Use the star on a command or command set to keep it here.')
                        : this.activeSection === 'sets'
                            ? this.t('commandSets.empty', 'No command sets saved.')
                            : this.t('commands.noCommands', 'No commands found');
                list.appendChild(empty);
            } else {
                const byKey = new Map(entries.map(entry => [this.entryKey(entry), entry]));
                const recentEntries = this.recent.map(key => byKey.get(key)).filter(Boolean);
                const recentKeys = new Set(recentEntries.map(entry => this.entryKey(entry)));
                if (!this.searchQuery && recentEntries.length) this.renderGroup(list, recentEntries, null, this.t('sessionCommands.recent', 'Recently used'), canInsert);
                this.renderGroup(list, this.searchQuery ? entries : entries.filter(entry => !recentKeys.has(this.entryKey(entry))), null,
                    this.t(this.activeSection === 'favorites' ? 'sessionCommands.favorites' : this.activeSection === 'sets' ? 'sessionCommands.sets' : 'sessionCommands.library', this.activeSection === 'favorites' ? 'Favorites' : this.activeSection === 'sets' ? 'Command sets' : 'Library'), canInsert);
            }

            const footer = document.createElement('footer');
            footer.className = 'session-command-popover-footer';
            const hint = document.createElement('span');
            hint.textContent = this.t(
                'sessionCommands.footer',
                'Inserted visibly. Press Enter in the terminal to run.'
            );
            const manage = document.createElement('button');
            manage.type = 'button';
            manage.className = 'btn btn-secondary btn-small';
            manage.textContent = this.t('sessionCommands.manage', 'Manage Commands');
            manage.addEventListener('click', () => {
                root.CommandSetManager?.openManagement();
            });
            footer.append(hint, manage);
            popup.append(tabs, search, sudoOption, list, footer);
            list.scrollTop = this.resultsScrollTop;
            list.addEventListener('scroll', () => { this.resultsScrollTop = list.scrollTop; });
            const nextFocus = searchFocused ? search : Array.from(
                popup.querySelectorAll?.('[data-command-parameter]') || []
            ).find(input => input.dataset.commandParameter === focusKey);
            if (nextFocus) {
                nextFocus.focus({ preventScroll: true });
                if (selection) nextFocus.setSelectionRange?.(...selection);
            }
        },

        renderGroup(parent, entries, type, label, canInsert = false) {
            const matching = type ? entries.filter(entry => entry.type === type) : entries;
            if (!matching.length) return;
            const document = root.document;
            const section = document.createElement('section');
            section.className = 'session-command-group';
            const heading = document.createElement('h4');
            heading.textContent = label;
            section.appendChild(heading);

            matching.forEach(savedEntry => {
                let entry = savedEntry;
                const parameterized = entry.type === 'set' && entry.parameters.length > 0;
                const boundSessionId = this.sessionId;
                if (entry.type === 'command' && this.parameterDrafts.has(entry.id)) {
                    entry = commandEntry({ ...entry, parameters: this.parameterDrafts.get(entry.id) });
                }
                const insertText = insertTextFor(entry, this.useSudo);
                const available = canInsert && entry.available
                    && Boolean(insertText)
                    && !hasLineBreak(insertText);
                const row = document.createElement('article');
                row.className = `session-command-item command-kind-${entry.type === 'set' ? 'set' : 'command'}`;
                if (!available) row.classList.add('unavailable');
                const details = document.createElement('div');
                details.className = 'session-command-item-details';
                const name = document.createElement('strong');
                name.textContent = entry.name;
                const description = document.createElement('span');
                description.textContent = entry.description;
                const preview = document.createElement('code');
                if (parameterized) preview.className = 'command-parameter-preview';
                preview.textContent = parameterized
                    ? this.t('commandParameters.reviewHint', 'Resolve a preview, then insert it. Press Enter in the terminal to run.')
                    : (insertText || entry.preview);
                const badge = document.createElement('span');
                badge.className = `command-kind-badge command-kind-${entry.type}`;
                badge.textContent = this.t(entry.type === 'set' ? 'commands.commandSet' : 'commands.command', entry.type === 'set' ? 'Command set' : 'Command');
                details.append(name, badge);
                if (entry.description) details.append(description);
                if (entry.preview || parameterized) details.append(preview);

                const insert = document.createElement('button');
                insert.type = 'button';
                insert.className = 'btn btn-primary btn-small';
                insert.textContent = this.t('sessionCommands.insert', 'Insert');
                let currentAvailable = available;
                let inserting = false;
                let parameterPreview = null;
                insert.disabled = !available;
                if (!available && !parameterized) {
                    const reason = entry.unavailableReason === 'multiline'
                        ? this.t(
                            'sessionCommands.multilineUnavailable',
                            'Multiline entries cannot be inserted safely.'
                        )
                        : (!canInsert
                            ? this.t(
                                'sessionCommands.noActiveSession',
                                'Connect an SSH session to enable insertion.'
                            )
                            : this.t('sessionCommands.unavailable', 'Entry is unavailable.'));
                    insert.setAttribute('title', reason);
                    const reasonText = document.createElement('small');
                    reasonText.textContent = reason;
                    details.append(reasonText);
                }
                if (parameterized) {
                    const values = Object.create(null);
                    let revision = 0;
                    const form = document.createElement('div');
                    form.className = 'session-command-parameters';
                    entry.parameters.forEach(parameter => {
                        const label = document.createElement('label');
                        label.textContent = parameter.name;
                        const input = document.createElement('input');
                        input.type = 'text';
                        input.className = 'form-control';
                        input.maxLength = 1024;
                        input.setAttribute('aria-label', parameter.name);
                        input.autocomplete = 'off';
                        values[parameter.name] = '';
                        input.addEventListener('input', () => {
                            values[parameter.name] = input.value;
                            revision++;
                            parameterPreview = null;
                            currentAvailable = false;
                            insert.disabled = true;
                            preview.textContent = this.t('commandParameters.reviewHint', 'Resolve a preview, then insert it. Press Enter in the terminal to run.');
                        });
                        label.append(input);
                        form.append(label);
                    });
                    const resolve = document.createElement('button');
                    resolve.type = 'button';
                    resolve.className = 'btn btn-secondary btn-small';
                    resolve.textContent = this.t('commandParameters.resolve', 'Resolve preview');
                    resolve.disabled = !canInsert;
                    resolve.addEventListener('click', async () => {
                        if (resolve.disabled) return;
                        resolve.disabled = true;
                        parameterPreview = null;
                        currentAvailable = false;
                        insert.disabled = true;
                        const requestedRevision = revision;
                        const result = await this.controller.preview(boundSessionId, entry.id, {...values}, this.useSudo);
                        resolve.disabled = !canInsert;
                        if (requestedRevision !== revision || this.sessionId !== boundSessionId
                                || document.contains?.(row) === false) return;
                        if (result.ok) {
                            parameterPreview = result.preview;
                            preview.textContent = result.preview.command;
                            currentAvailable = true;
                            insert.disabled = false;
                        } else {
                            preview.textContent = result.error || this.t('commandParameters.previewFailed', 'The preview is unavailable. Check the parameters and selected session.');
                        }
                    });
                    form.append(resolve);
                    details.append(form);
                } else if (entry.type === 'command') {
                    const editor = document.createElement('details');
                    editor.className = 'session-command-parameters';
                    editor.open = this.expandedParameters.has(entry.id);
                    const summary = document.createElement('summary');
                    summary.textContent = this.t('sessionCommands.editParameters', 'Parameters for this insertion');
                    editor.addEventListener('toggle', () => {
                        if (editor.open) this.expandedParameters.add(entry.id);
                        else this.expandedParameters.delete(entry.id);
                    });
                    const input = document.createElement('input');
                    input.type = 'text';
                    input.maxLength = 4096;
                    input.dataset.commandParameter = entry.id;
                    input.setAttribute('aria-label', summary.textContent);
                    input.value = entry.parameters;
                    const updatePreview = () => {
                        const updated = commandEntry({ ...savedEntry, parameters: input.value });
                        preview.textContent = insertTextFor(updated, this.useSudo);
                        currentAvailable = canInsert && updated.available;
                        insert.disabled = inserting || !currentAvailable;
                    };
                    input.addEventListener('input', () => {
                        this.parameterDrafts.set(entry.id, input.value);
                        updatePreview();
                    });
                    const reset = document.createElement('button');
                    reset.type = 'button';
                    reset.className = 'btn btn-secondary btn-small';
                    reset.textContent = this.t('sessionCommands.resetParameters', 'Restore saved parameters');
                    reset.addEventListener('click', () => {
                        this.parameterDrafts.delete(entry.id);
                        input.value = savedEntry.parameters;
                        updatePreview();
                    });
                    editor.append(summary, input, reset);
                    details.appendChild(editor);
                }
                insert.addEventListener('click', async () => {
                    if (insert.disabled || inserting) return;
                    inserting = true;
                    insert.disabled = true;
                    const result = await this.controller.insert(
                        boundSessionId,
                        entry.type,
                        entry.id,
                        { useSudo: this.useSudo, preview: parameterPreview, parameters: entry.type === 'command' ? this.parameterDrafts.get(entry.id) : undefined }
                    );
                    inserting = false;
                    if (parameterized) {
                        parameterPreview = null;
                        currentAvailable = false;
                    }
                    insert.disabled = !currentAvailable;
                    if (!result.ok) {
                        root.showNotification?.(
                            this.t(
                                'sessionCommands.sessionUnavailable',
                                'The selected session or entry is no longer available.'
                            ),
                            'error'
                        );
                        this.sync();
                    } else {
                        this.rememberUse(entry);
                    }
                });
                const actions = document.createElement('div');
                actions.className = 'session-command-item-actions';
                const favorite = document.createElement('button');
                favorite.type = 'button';
                favorite.className = 'btn btn-secondary btn-small session-command-favorite command-favorite';
                const isFavorite = this.favorites.has(this.entryKey(entry));
                favorite.textContent = isFavorite ? '★' : '☆';
                favorite.setAttribute('aria-pressed', String(isFavorite));
                const favoriteLabel = this.t(
                    isFavorite ? 'sessionCommands.removeFavorite' : 'sessionCommands.addFavorite',
                    isFavorite ? 'Remove from favorites' : 'Add to favorites',
                );
                favorite.setAttribute('aria-label', favoriteLabel);
                favorite.title = favoriteLabel;
                favorite.addEventListener('click', () => this.toggleFavorite(entry));
                actions.append(favorite, insert);
                row.append(details, actions);
                section.appendChild(row);
            });
            parent.appendChild(section);
        },
    };

    return launcher;
}));
