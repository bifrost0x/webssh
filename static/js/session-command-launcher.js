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
            type: 'command',
            id: command?.id || '',
            name: command?.name || base || '',
            description: command?.description || '',
            preview: insertText,
            insertText,
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
            id: commandSet?.id || '',
            name: commandSet?.name || '',
            description: commandSet?.description || '',
            preview: resolved || commandSet?.resolution_error || '',
            insertText: resolved,
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
        return {
            entries(query = '') {
                return buildLauncherEntries(
                    dependencies.getCommands?.() || [],
                    dependencies.getCommandSets?.() || [],
                    query
                );
            },

            insert(sessionId, type, id) {
                const session = dependencies.getSession?.(sessionId);
                if (!session || !session.connected) {
                    return { ok: false, reason: 'session-unavailable' };
                }
                const entry = this.entries().find(candidate => (
                    candidate.type === type && candidate.id === id
                ));
                if (!entry || !entry.available || hasLineBreak(entry.insertText)) {
                    return { ok: false, reason: entry?.unavailableReason || 'entry-unavailable' };
                }

                dependencies.emitInput?.(sessionId, entry.insertText);
                dependencies.close?.();
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
        popup: null,
        initialized: false,

        t(key, fallback) {
            const translated = root.i18n?.t(key);
            return translated && translated !== key ? translated : fallback;
        },

        init() {
            const document = root.document;
            if (!document || this.initialized) return;
            this.initialized = true;
            this.controller = createSessionCommandController({
                getSession: sessionId => getSessionManager()?.getSession(sessionId),
                getCommands: () => getCommandLibrary()?.commands || [],
                getCommandSets: () => root.CommandSetManager?.commandSets || [],
                emitInput: (sessionId, data) => root.socket?.emit('ssh_input', {
                    session_id: sessionId,
                    data,
                }),
                close: () => this.close(),
                focusSession: sessionId => getTerminalManager()?.terminals?.[sessionId]?.focus(),
                notify: (message, type) => root.showNotification?.(message, type),
                insertedMessage: label => this.t(
                    'sessionCommands.inserted',
                    'Command inserted into {session}. Press Enter to run it.'
                ).replace('{session}', label),
            });

            root.addEventListener?.('session-workspace-change', () => this.sync());
            root.addEventListener?.('session-removed', event => {
                if (event.detail?.sessionId === this.sessionId) this.close(false);
                root.setTimeout?.(() => this.sync(), 0);
            });
            root.addEventListener?.('languageChanged', () => this.sync());
            root.socket?.on?.('commands_list', () => root.setTimeout?.(() => this.render(), 0));
            root.socket?.on?.('command_sets_list', () => root.setTimeout?.(() => this.render(), 0));
            document.addEventListener('click', event => {
                if (this.popup && !event.target.closest('.session-command-launcher')) {
                    this.close(false);
                }
            });
            document.addEventListener('keydown', event => {
                if (event.key === 'Escape' && this.popup) {
                    event.preventDefault();
                    this.close(true);
                }
            });
            this.sync();
        },

        sync() {
            const document = root.document;
            if (!document) return;
            this.close(false);
            document.querySelectorAll('.session-command-launcher').forEach(node => node.remove());

            const sessionManager = getSessionManager();
            const paneIndex = sessionManager?.getActivePaneIndex?.();
            const sessionId = sessionManager?.paneAssignments?.[paneIndex];
            const session = sessionId ? sessionManager.getSession(sessionId) : null;
            if (!sessionId || !session?.connected) return;

            const pane = document.querySelector(
                `.terminal-pane[data-pane-index="${paneIndex}"]`
            );
            if (!pane) return;

            const container = document.createElement('div');
            container.className = 'session-command-launcher';
            container.addEventListener('click', event => event.stopPropagation());

            const trigger = document.createElement('button');
            trigger.type = 'button';
            trigger.className = 'session-command-trigger';
            trigger.setAttribute('aria-haspopup', 'dialog');
            trigger.setAttribute('aria-expanded', 'false');
            const label = this.t('sessionCommands.open', 'Insert Commands');
            trigger.setAttribute('aria-label', label);
            trigger.setAttribute('title', label);

            const icon = document.createElement('span');
            icon.className = 'material-icons';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = 'terminal';
            const text = document.createElement('span');
            text.textContent = this.t('sessionCommands.button', 'Commands');
            trigger.append(icon, text);
            trigger.addEventListener('click', () => {
                if (this.popup) this.close(true);
                else this.open(sessionId, container, trigger);
            });

            container.appendChild(trigger);
            pane.appendChild(container);
            this.trigger = trigger;
        },

        open(sessionId, container, trigger) {
            const session = getSessionManager()?.getSession(sessionId);
            if (!session?.connected) return;
            this.sessionId = sessionId;
            this.searchQuery = '';
            this.trigger = trigger;
            trigger.setAttribute('aria-expanded', 'true');

            const popup = root.document.createElement('section');
            popup.className = 'session-command-popover';
            popup.setAttribute('role', 'dialog');
            popup.setAttribute('aria-modal', 'false');
            popup.setAttribute('aria-label', this.t('sessionCommands.title', 'Insert Commands'));
            container.appendChild(popup);
            this.popup = popup;
            this.render();
            root.setTimeout?.(() => popup.querySelector('input')?.focus(), 0);
        },

        close(restoreFocus = false) {
            const trigger = this.trigger;
            this.popup?.remove();
            this.popup = null;
            this.sessionId = null;
            this.searchQuery = '';
            trigger?.setAttribute('aria-expanded', 'false');
            if (restoreFocus) trigger?.focus();
        },

        render() {
            if (!this.popup || !this.sessionId) return;
            const document = root.document;
            const popup = this.popup;
            const session = getSessionManager()?.getSession(this.sessionId);
            if (!session?.connected) {
                this.close(false);
                return;
            }
            popup.replaceChildren();

            const header = document.createElement('header');
            header.className = 'session-command-popover-header';
            const headingWrap = document.createElement('div');
            const heading = document.createElement('h3');
            heading.textContent = this.t('sessionCommands.title', 'Insert Commands');
            const target = document.createElement('p');
            target.textContent = this.t(
                'sessionCommands.target',
                'Target: {session}'
            ).replace('{session}', sessionLabel(session, this.sessionId));
            headingWrap.append(heading, target);
            const close = document.createElement('button');
            close.type = 'button';
            close.className = 'session-command-close';
            close.setAttribute('aria-label', this.t('common.close', 'Close'));
            const closeIcon = document.createElement('span');
            closeIcon.className = 'material-icons';
            closeIcon.setAttribute('aria-hidden', 'true');
            closeIcon.textContent = 'close';
            close.appendChild(closeIcon);
            close.addEventListener('click', () => this.close(true));
            header.append(headingWrap, close);

            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'session-command-search';
            search.placeholder = this.t(
                'sessionCommands.searchPlaceholder',
                'Search Commands and Command Sets...'
            );
            search.setAttribute('aria-label', search.placeholder);
            search.value = this.searchQuery;
            search.addEventListener('input', event => {
                this.searchQuery = event.target.value;
                this.render();
                const nextSearch = this.popup?.querySelector('.session-command-search');
                nextSearch?.focus();
                nextSearch?.setSelectionRange(this.searchQuery.length, this.searchQuery.length);
            });

            const list = document.createElement('div');
            list.className = 'session-command-results';
            const entries = this.controller.entries(this.searchQuery);
            if (!entries.length) {
                const empty = document.createElement('p');
                empty.className = 'session-command-empty';
                empty.textContent = this.t('sessionCommands.noResults', 'No matching entries.');
                list.appendChild(empty);
            } else {
                this.renderGroup(list, entries, 'set', this.t('sessionCommands.sets', 'Command Sets'));
                this.renderGroup(list, entries, 'command', this.t('sessionCommands.commands', 'Commands'));
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
                this.close(false);
                root.CommandSetManager?.openManagement();
            });
            footer.append(hint, manage);
            popup.append(header, search, list, footer);
        },

        renderGroup(parent, entries, type, label) {
            const matching = entries.filter(entry => entry.type === type);
            if (!matching.length) return;
            const document = root.document;
            const section = document.createElement('section');
            section.className = 'session-command-group';
            const heading = document.createElement('h4');
            heading.textContent = label;
            section.appendChild(heading);

            matching.forEach(entry => {
                const row = document.createElement('article');
                row.className = 'session-command-item';
                if (!entry.available) row.classList.add('unavailable');
                const details = document.createElement('div');
                details.className = 'session-command-item-details';
                const name = document.createElement('strong');
                name.textContent = entry.name;
                const description = document.createElement('span');
                description.textContent = entry.description;
                const preview = document.createElement('code');
                preview.textContent = entry.preview;
                details.append(name);
                if (entry.description) details.append(description);
                if (entry.preview) details.append(preview);

                const insert = document.createElement('button');
                insert.type = 'button';
                insert.className = 'btn btn-primary btn-small';
                insert.textContent = this.t('sessionCommands.insert', 'Insert');
                insert.disabled = !entry.available;
                if (!entry.available) {
                    const reason = entry.unavailableReason === 'multiline'
                        ? this.t(
                            'sessionCommands.multilineUnavailable',
                            'Multiline entries cannot be inserted safely.'
                        )
                        : this.t('sessionCommands.unavailable', 'Entry is unavailable.');
                    insert.setAttribute('title', reason);
                    const reasonText = document.createElement('small');
                    reasonText.textContent = reason;
                    details.append(reasonText);
                }
                insert.addEventListener('click', () => {
                    const result = this.controller.insert(
                        this.sessionId,
                        entry.type,
                        entry.id
                    );
                    if (!result.ok) {
                        root.showNotification?.(
                            this.t(
                                'sessionCommands.sessionUnavailable',
                                'The selected session or entry is no longer available.'
                            ),
                            'error'
                        );
                        this.sync();
                    }
                });
                row.append(details, insert);
                section.appendChild(row);
            });
            parent.appendChild(section);
        },
    };

    return launcher;
}));
