/* Shared command library, favorites and reusable command sets. */
window.CommandWorkspace = {
    activeSection: 'library',
    sections: [
        ['library', 'commandLibraryTab', 'commandLibraryPanel'],
        ['favorites', 'commandFavoritesTab', 'commandFavoritesPanel'],
        ['sets', 'commandSetsTab', 'commandSetsPanel'],
    ],
    storageKey() { return `webssh.commandSection.${document.body.dataset.connectionHistoryScope || 'local'}`; },
    t(key, fallback) { return window.SessionCommandLauncher?.t(key, fallback) || fallback; },
    init() {
        this.sections.forEach(([name, tabId], index) => {
            const tab = document.getElementById(tabId);
            tab?.addEventListener('click', () => this.select(name, true));
            tab?.addEventListener('keydown', async event => {
                if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
                event.preventDefault();
                const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? 2
                    : (index + (event.key === 'ArrowRight' ? 1 : -1) + 3) % 3;
                const [next, nextTab] = this.sections[nextIndex];
                if (await this.select(next)) document.getElementById(nextTab)?.focus();
            });
        });
        const modal = document.getElementById('commandWorkspaceModal');
        document.getElementById('closeCommandWorkspaceModal')?.addEventListener('click', () => this.requestClose());
        modal?.addEventListener('click', event => { if (event.target === modal) this.requestClose(); });
        document.addEventListener('keydown', event => {
            if (event.key !== 'Escape' || event.defaultPrevented || !modal?.classList.contains('show')
                    || modal.classList.contains('primary-workspace-view') || document.querySelector('dialog[open]')) return;
            const activeModal = window.ModalManager?.activeModal;
            if (activeModal && activeModal !== modal) return;
            event.preventDefault();
            event.stopImmediatePropagation();
            this.requestClose();
        }, true);
        document.getElementById('commandFavoritesSearch')?.addEventListener('input', () => this.renderFavorites());
        window.addEventListener('command-favorites-change', () => { this.syncFavoriteButtons(); this.renderFavorites(); });
        window.addEventListener('languageChanged', () => { this.syncFavoriteButtons(); this.renderFavorites(); });
        window.socket?.on?.('commands_list', () => setTimeout(() => this.renderFavorites(), 0));
        window.socket?.on?.('command_sets_list', () => setTimeout(() => this.renderFavorites(), 0));
        window.SessionCommandLauncher?.ensurePreferences();
        try {
            const stored = window.localStorage.getItem(this.storageKey());
            if (this.sections.some(([name]) => name === stored)) this.activeSection = stored;
        } catch { /* Storage is optional. */ }
        this.select(this.activeSection);
    },
    open(section = this.activeSection, options = {}) {
        this.select(section);
        const modal = document.getElementById('commandWorkspaceModal');
        if (!modal) return;
        if (options.primary !== false && window.primaryWorkspaceController?.open('commands', modal)) return;
        window.primaryWorkspaceController?.release(modal);
        if (window.ModalManager) window.ModalManager.open(modal);
        else modal.classList.add('show');
    },
    select(section, focusContent = false) {
        const next = this.sections.some(([name]) => name === section) ? section : 'library';
        if (this.activeSection === 'sets' && next !== 'sets' && window.CommandSetManager?.hasUnsavedChanges?.()) {
            if (this.selectPending) return this.selectPending;
            this.selectPending = Promise.resolve(window.CommandSetManager.confirmDiscard()).then(confirmed => {
                if (!confirmed) return false;
                return this.applySelection(next, focusContent);
            }).finally(() => { this.selectPending = null; });
            return this.selectPending;
        }
        return this.applySelection(next, focusContent);
    },
    applySelection(next, focusContent) {
        this.activeSection = next;
        try { window.localStorage.setItem(this.storageKey(), next); } catch { /* Storage is optional. */ }
        this.sections.forEach(([name, tabId, panelId]) => {
            const active = name === next, tab = document.getElementById(tabId);
            tab?.classList.toggle('active', active);
            tab?.setAttribute('aria-selected', String(active));
            if (tab) tab.tabIndex = active ? 0 : -1;
            document.getElementById(panelId)?.classList.toggle('hidden', !active);
        });
        if (next === 'favorites') this.renderFavorites();
        if (focusContent) {
            const id = {library: 'commandSearchInput', favorites: 'commandFavoritesSearch', sets: 'commandSetManagementSearch'}[next];
            setTimeout(() => document.getElementById(id)?.focus(), 0);
        }
        return true;
    },
    favoriteButton(type, id) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-secondary btn-small session-command-favorite command-favorite';
        button.dataset.favoriteType = type;
        button.dataset.favoriteId = id;
        this.updateFavoriteButton(button);
        button.addEventListener('click', () => window.SessionCommandLauncher?.toggleFavorite({type, id}));
        return button;
    },
    updateFavoriteButton(button) {
        const store = window.SessionCommandLauncher;
        store?.ensurePreferences();
        const active = store?.favorites.has(store.entryKey({type: button.dataset.favoriteType, id: button.dataset.favoriteId})) || false;
        button.textContent = active ? '★' : '☆';
        button.setAttribute('aria-pressed', String(active));
        button.classList.toggle('active', active);
        const label = this.t(active ? 'sessionCommands.removeFavorite' : 'sessionCommands.addFavorite', active ? 'Remove from favorites' : 'Add to favorites');
        button.setAttribute('aria-label', label);
        button.title = label;
    },
    syncFavoriteButtons() {
        document.querySelectorAll('[data-favorite-type]').forEach(button => this.updateFavoriteButton(button));
    },
    renderFavorites() {
        const list = document.getElementById('commandFavoritesList'), store = window.SessionCommandLauncher;
        if (!list || !store) return;
        const previousButtons = Array.from(list.querySelectorAll('button'));
        const focusedIndex = previousButtons.indexOf(document.activeElement);
        const focusedButton = previousButtons[focusedIndex];
        const restoreFocus = () => {
            if (!focusedButton) return;
            const buttons = Array.from(list.querySelectorAll('button'));
            const same = buttons.find(button => button.dataset.favoriteType === focusedButton.dataset.favoriteType
                && button.dataset.favoriteId === focusedButton.dataset.favoriteId
                && button.dataset.commandEntryType === focusedButton.dataset.commandEntryType
                && button.dataset.commandEntryId === focusedButton.dataset.commandEntryId);
            const sameAction = button => Boolean(button.dataset.favoriteType) === Boolean(focusedButton.dataset.favoriteType);
            const previousPeers = previousButtons.filter(sameAction);
            const peers = buttons.filter(sameAction);
            const next = peers[Math.min(previousPeers.indexOf(focusedButton), peers.length - 1)];
            (same || next || document.getElementById('commandFavoritesSearch'))?.focus({preventScroll: true});
        };
        store.ensurePreferences();
        const query = document.getElementById('commandFavoritesSearch')?.value || '';
        const commands = window.CommandLibrary?.commands || [];
        const sets = window.CommandSetManager?.commandSets || [];
        const entries = store.buildLauncherEntries(commands, sets, query).filter(entry => store.favorites.has(store.entryKey(entry)));
        list.replaceChildren();
        const count = document.getElementById('commandFavoritesCount');
        if (count) count.textContent = String(store.buildLauncherEntries(commands, sets).filter(entry => store.favorites.has(store.entryKey(entry))).length);
        if (!entries.length) {
            const empty = document.createElement('p');
            empty.className = 'command-favorites-empty';
            empty.textContent = query.trim()
                ? this.t('sessionCommands.noResults', 'No matching entries.')
                : this.t('empty.favorites', 'No favorites yet. Use the star on a command or command set to keep it here.');
            list.append(empty);
        }
        entries.forEach(entry => {
            const card = document.createElement('article');
            card.className = `command-card command-favorite command-kind-${entry.type === 'set' ? 'set' : 'command'}`;
            const title = document.createElement('h3'); title.textContent = entry.name;
            const badge = document.createElement('span'); badge.className = `command-kind-badge command-kind-${entry.type}`;
            badge.textContent = this.t(entry.type === 'set' ? 'commands.commandSet' : 'commands.command', entry.type === 'set' ? 'Command set' : 'Command');
            card.append(title, badge, this.favoriteButton(entry.type, entry.id));
            if (entry.description) { const description = document.createElement('p'); description.textContent = entry.description; card.append(description); }
            const preview = document.createElement('code'); preview.textContent = entry.preview; card.append(preview);
            if (entry.type === 'set') {
                const steps = document.createElement('span');
                steps.textContent = this.t('commandSets.stepCount', '{count} steps').replace('{count}', String(sets.find(item => item.id === entry.id)?.steps?.length || 0));
                card.append(steps);
            }
            const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'btn btn-secondary btn-small';
            edit.dataset.commandEntryType = entry.type;
            edit.dataset.commandEntryId = entry.id;
            const system = entry.type === 'command' && commands.find(item => item.id === entry.id)?.isSystem;
            edit.textContent = this.t(system ? 'commandLibrary.ownCopy' : 'common.edit', system ? 'Own copy' : 'Edit');
            edit.addEventListener('click', async () => {
                if (entry.type === 'set') {
                    if (await this.select('sets')) await window.CommandSetManager?.openBuilder(entry.id);
                } else if (await this.select('library')) window.CommandLibrary?.openEditor(entry.id);
            });
            card.append(edit); list.append(card);
        });
        restoreFocus();
    },
    requestClose() {
        if (this.activeSection === 'sets') window.CommandSetManager?.close();
        else window.CommandLibrary?.closeLibrary();
    },
    close() {
        const modal = document.getElementById('commandWorkspaceModal');
        if (!modal) return;
        if (window.primaryWorkspaceController?.close(modal)) return;
        if (window.ModalManager) window.ModalManager.close(modal);
        else modal.classList.remove('show');
    },
};
