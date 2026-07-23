/* Shared shell for the command library and reusable command sets. */
window.CommandWorkspace = {
    activeSection: 'sets',

    init() {
        const libraryTab = document.getElementById('commandLibraryTab');
        const setsTab = document.getElementById('commandSetsTab');
        const modal = document.getElementById('commandWorkspaceModal');

        libraryTab?.addEventListener('click', () => this.select('library', true));
        setsTab?.addEventListener('click', () => this.select('sets', true));
        document.getElementById('closeCommandWorkspaceModal')?.addEventListener('click', () => {
            this.requestClose();
        });
        modal?.addEventListener('click', event => {
            if (event.target === modal) this.requestClose();
        });
        [libraryTab, setsTab].forEach(tab => tab?.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
            event.preventDefault();
            this.select(this.activeSection === 'library' ? 'sets' : 'library', true);
        }));

        this.select('sets');
    },

    open(section = 'sets') {
        this.select(section);
        const modal = document.getElementById('commandWorkspaceModal');
        if (!modal) return;
        if (window.ModalManager) window.ModalManager.open(modal);
        else modal.classList.add('show');
    },

    select(section, focusContent = false) {
        const next = section === 'sets' ? 'sets' : 'library';
        this.activeSection = next;

        const pairs = [
            ['library', 'commandLibraryTab', 'commandLibraryPanel'],
            ['sets', 'commandSetsTab', 'commandSetsPanel'],
        ];
        pairs.forEach(([name, tabId, panelId]) => {
            const active = name === next;
            const tab = document.getElementById(tabId);
            const panel = document.getElementById(panelId);
            tab?.classList.toggle('active', active);
            tab?.setAttribute('aria-selected', String(active));
            if (tab) tab.tabIndex = active ? 0 : -1;
            panel?.classList.toggle('hidden', !active);
        });

        if (focusContent) {
            const target = next === 'library'
                ? document.getElementById('commandSearchInput')
                : document.getElementById('newCommandSetBtn');
            setTimeout(() => target?.focus(), 0);
        }
    },

    requestClose() {
        if (this.activeSection === 'sets') window.CommandSetManager?.close();
        else window.CommandLibrary?.closeLibrary();
    },

    close() {
        const modal = document.getElementById('commandWorkspaceModal');
        if (!modal) return;
        if (window.ModalManager) window.ModalManager.close(modal);
        else modal.classList.remove('show');
    },
};
