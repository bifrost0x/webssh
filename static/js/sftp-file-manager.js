
class SFTPFileManager {
    constructor() {
        this.socket = window.socket;
        this.modal = null;
        this.isOpen = false;
        this.displayMode = 'closed';
        this.embeddedContainer = null;

        this.initializeWorkspaceState();

        this.availableSessions = [];
        this.quickConnections = [];

        this.transferQueue = [];
        this.activeTransfers = new Map();
        this.isTransferring = false;
        this.uploadBatches = new Map();
        this.uploadRefreshes = new Map();
        this.s2sTerminalWaiters = new Map();
        this.s2sEarlyTerminals = new Map();
        this.transferConnectionHolds = new Map();
        this.pendingQuickDisconnects = new Set();

        this.conflictAction = null;
        this.applyToAll = false;

        this.contextMenu = null;

        this.draggedItems = [];
        this.dragSource = null;
        this.requestSequence = 0;

        this.init();
    }

    createEmptyPaneState() {
        return {
            type: null,
            sessionId: null,
            connectionId: null,
            path: '/',
            files: [],
            selected: new Set(),
            lastSelected: -1,
            hostInfo: null,
            loading: false,
            loadingTimeout: null,
            error: null,
            homePath: null,
            pendingHomeRequestId: null,
            pendingDirectoryRequestId: null,
            pendingDirectoryPath: null,
            autoHomeEligible: false
        };
    }

    initializeWorkspaceState() {
        const WorkspaceState = window.FileWorkspaceState;
        if (typeof WorkspaceState !== 'function') {
            throw new Error('FileWorkspaceState must be loaded before SFTPFileManager');
        }
        this.workspace = new WorkspaceState(() => this.createEmptyPaneState());
        this.workspaceEmptyPanes = {
            left: this.createEmptyPaneState(),
            right: this.createEmptyPaneState(),
        };
        this.panes = this.workspaceEmptyPanes;
        this.standalonePanes = this.panes;
        this.embeddedPanes = null;
        this.activePane = 'left';
    }

    syncPaneFromWorkspace(pane) {
        const tab = this.workspace.getActiveTab(pane);
        this.panes[pane] = tab?.paneState || this.workspaceEmptyPanes[pane];
        this.standalonePanes = this.panes;
        return this.panes[pane];
    }

    enterEmbeddedPaneState() {
        if (this.embeddedPanes) return this.embeddedPanes;
        this.standalonePanes = this.panes;
        this.embeddedPanes = {
            left: this.createEmptyPaneState(),
            right: this.createEmptyPaneState(),
        };
        this.panes = this.embeddedPanes;
        return this.embeddedPanes;
    }

    restoreStandalonePaneState() {
        if (!this.embeddedPanes) return this.panes;
        this.panes = this.standalonePanes;
        this.embeddedPanes = null;
        ['left', 'right'].forEach(pane => this.syncPaneFromWorkspace(pane));
        return this.panes;
    }

    setWorkspaceLayout(layout) {
        const previousLayout = this.workspace.layout;
        this.workspace.setLayout(layout);
        if (layout === 'split' && previousLayout === 'single' && this.displayMode === 'modal') {
            const sourcePane = this.workspace.activePane;
            const targetPane = sourcePane === 'left' ? 'right' : 'left';
            const sourceTabs = this.workspace.getTabs(sourcePane);
            if (!this.workspace.getActiveTab(targetPane) && sourceTabs.length > 1) {
                const activeTab = this.workspace.getActiveTab(sourcePane);
                this.workspace.moveTab(sourcePane, targetPane, activeTab.id);
                this.syncPaneFromWorkspace(sourcePane);
                this.syncPaneFromWorkspace(targetPane);
                this.updatePathInput(sourcePane, this.panes[sourcePane].path || '/');
                this.updatePathInput(targetPane, this.panes[targetPane].path || '/');
                this.updatePaneBadge(sourcePane);
                this.updatePaneBadge(targetPane);
                this.renderPane(sourcePane);
                this.renderPane(targetPane);
                this.setActivePane(targetPane);
            } else if (!this.workspace.getActiveTab(targetPane)) {
                this.openSourceLauncher(targetPane);
            }
        }
        this.renderWorkspaceChrome();
        return layout;
    }

    buildSourceCatalog() {
        const active = (this.availableSessions || [])
            .filter(session => session.connected !== false)
            .map(session => ({
                key: `ssh:${session.id}`,
                type: 'ssh',
                label: session.displayName || session.name || `${session.username}@${session.host}`,
                endpoint: `${session.host}:${session.port || 22}`,
                protocol: 'SFTP',
                status: this.t('fm.workspace.connected', 'Connected'),
                security: this.t('fm.workspace.hostKeyTrusted', 'SSH host key trusted'),
                sessionId: session.id,
            }));
        const saved = (this.qcProfiles || []).map(profile => ({
            key: `profile:${profile.id}`,
            type: 'profile',
            label: profile.name || `${profile.username}@${profile.host}`,
            endpoint: `${profile.username}@${profile.host}:${profile.port || 22}`,
            protocol: 'SFTP',
            status: this.t('fm.workspace.available', 'Available'),
            security: this.t('fm.workspace.authenticationRequired', 'Authentication required'),
            profileId: profile.id,
        }));
        const quick = (this.quickConnections || []).map(connection => ({
            key: `qc:${connection.connectionId}`,
            type: 'ssh',
            label: `${connection.username}@${connection.host}`,
            endpoint: `${connection.host}:${connection.port || 22}`,
            protocol: 'SFTP',
            status: this.t('fm.workspace.connected', 'Connected'),
            security: this.t('fm.workspace.hostKeyTrusted', 'SSH host key trusted'),
            connectionId: connection.connectionId,
        }));
        return [
            { id: 'active', label: this.t('fm.workspace.activeSessions', 'Active SSH sessions'), items: active },
            { id: 'saved', label: this.t('fm.workspace.savedHosts', 'Saved SSH hosts'), items: saved },
            { id: 'quick', label: this.t('fm.workspace.quickConnections', 'SFTP quick connections'), items: quick },
        ];
    }

    async openWorkspaceSource(pane, source) {
        if (!source || source.disabled) return null;
        if (source.type === 'profile') {
            this.pendingQuickConnectPane = pane;
            this.openQuickConnect(source.profileId);
            return null;
        }

        const paneState = this.createEmptyPaneState();
        const tab = this.workspace.openTab(pane, source, paneState);
        this.syncPaneFromWorkspace(pane);
        this.workspace.setActivePane(pane);
        this.setActivePane(pane);
        this.closeSourceLauncher();
        this.renderWorkspaceChrome();
        await this.onSourceChange(pane, source.key);
        this.renderWorkspaceChrome();
        return tab;
    }

    loadWorkspaceProfiles() {
        if (!this.socket || this.workspaceProfilesPending) return;
        this.workspaceProfilesPending = true;
        this.socket.emit('list_profiles');
        this.socket.once('profiles_list', data => {
            this.workspaceProfilesPending = false;
            this.qcProfiles = data?.profiles || [];
            if (this.sourceLauncherPane) this.renderSourceLauncher();
        });
    }

    openSourceLauncher(pane = this.workspace.activePane) {
        if (this.displayMode === 'embedded') return false;
        this.sourceLauncherPane = pane;
        this.sourceLauncherReturnFocus = document.activeElement;
        this.loadWorkspaceProfiles();
        this.renderSourceLauncher('');

        const launcher = document.getElementById('fmSourceLauncher');
        launcher.classList.add('show');
        launcher.setAttribute('aria-hidden', 'false');
        const single = this.workspace.layout === 'single';
        const actionLabel = document.getElementById('fmSourceLauncherAction');
        const paneLabel = document.getElementById('fmSourceLauncherPane');
        actionLabel.textContent = single
            ? this.t('fm.workspace.openSource', 'Open source')
            : this.t('fm.workspace.openSourceIn', 'Open source in');
        paneLabel.hidden = single;
        paneLabel.textContent = single
            ? ''
            : pane === 'left'
                ? this.t('fm.workspace.leftPane', 'Left side')
                : this.t('fm.workspace.rightPane', 'Right side');
        const search = document.getElementById('fmSourceSearch');
        search.value = '';
        search.focus();
        return true;
    }

    closeSourceLauncher() {
        const launcher = document.getElementById('fmSourceLauncher');
        if (!launcher) return;
        launcher.classList.remove('show');
        launcher.setAttribute('aria-hidden', 'true');
        this.sourceLauncherPane = null;
        if (this.sourceLauncherReturnFocus?.isConnected) this.sourceLauncherReturnFocus.focus();
        this.sourceLauncherReturnFocus = null;
    }

    trapSourceLauncherFocus(event) {
        const launcher = document.getElementById('fmSourceLauncher');
        if (!launcher?.classList.contains('show')) return false;
        const focusable = Array.from(launcher.querySelectorAll(
            'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        )).filter(element => (
            element.getClientRects().length > 0
            && element.getAttribute('aria-hidden') !== 'true'
        ));
        if (focusable.length === 0) {
            event.preventDefault();
            return true;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        if (event.shiftKey && (active === first || !launcher.contains(active))) {
            event.preventDefault();
            last.focus();
            return true;
        }
        if (!event.shiftKey && (active === last || !launcher.contains(active))) {
            event.preventDefault();
            first.focus();
            return true;
        }
        return false;
    }

    renderSourceLauncher(query = document.getElementById('fmSourceSearch')?.value || '') {
        const container = document.getElementById('fmSourceGroups');
        if (!container) return;
        const normalizedQuery = query.trim().toLocaleLowerCase();
        const groups = this.buildSourceCatalog();
        const hasAvailableSources = groups.some(group => group.items.length > 0);
        this.sourceCatalogByKey = new Map();
        const renderedGroups = groups.map(group => {
            const items = group.items.filter(source => {
                this.sourceCatalogByKey.set(source.key, source);
                if (!normalizedQuery) return true;
                return [source.label, source.endpoint, source.protocol, source.status, source.security]
                    .some(value => String(value || '').toLocaleLowerCase().includes(normalizedQuery));
            });
            if (items.length === 0) return null;
            const rows = items.map(source => {
                const icon = source.type === 'profile' ? 'bookmark' : 'terminal';
                const disabled = source.disabled ? ' disabled aria-disabled="true"' : '';
                return `
                    <button type="button" class="fm-source-row${source.disabled ? ' is-disabled' : ''}" data-source-key="${this.escapeHtml(source.key)}"${disabled}>
                        <span class="material-icons fm-source-row-icon" aria-hidden="true">${icon}</span>
                        <span class="fm-source-row-main">
                            <strong>${this.escapeHtml(source.label)}</strong>
                            <small>${this.escapeHtml(source.endpoint || '')}</small>
                        </span>
                        <span class="fm-protocol-badge">${this.escapeHtml(source.protocol || '')}</span>
                        <span class="fm-source-row-status">
                            <strong>${this.escapeHtml(source.status || '')}</strong>
                            <small><span class="material-icons" aria-hidden="true">verified_user</span>${this.escapeHtml(source.security || '')}</small>
                        </span>
                    </button>`;
            }).join('');
            return { id: group.id, html: `<section class="fm-source-group" aria-labelledby="fm-source-group-${group.id}">
                <h4 id="fm-source-group-${group.id}"><span>${this.escapeHtml(group.label)}</span><span class="fm-source-group-count">${items.length}</span></h4>
                <div class="fm-source-group-items">${rows}</div>
            </section>` };
        }).filter(Boolean);
        container.innerHTML = renderedGroups.length > 0
            ? `<div class="fm-source-primary-groups">${renderedGroups.map(group => group.html).join('')}</div>`
            : hasAvailableSources
                ? `<div class="fm-source-no-results">${this.escapeHtml(this.t('fm.workspace.noSources', 'No matching sources'))}</div>`
                : `<div class="fm-source-no-sources">
                    <span class="material-icons" aria-hidden="true">link_off</span>
                    <strong>${this.escapeHtml(this.t('fm.workspace.noAvailableSources', 'No sources available'))}</strong>
                    <span>${this.escapeHtml(this.t('fm.workspace.noAvailableSourcesHint', 'Open an SSH session or create a new SFTP connection below.'))}</span>
                </div>`;
    }

    renderWorkspaceChrome() {
        if (!this.modal || this.displayMode === 'embedded') return;
        const single = this.workspace.layout === 'single';
        this.modal.classList.toggle('fm-workspace-single', single);
        this.modal.classList.toggle('fm-workspace-split', !single);
        this.modal.classList.toggle('fm-single-right', single && this.workspace.activePane === 'right');
        const singleButton = document.getElementById('fmLayoutSingle');
        const splitButton = document.getElementById('fmLayoutSplit');
        singleButton?.classList.toggle('active', single);
        splitButton?.classList.toggle('active', !single);
        singleButton?.setAttribute('aria-pressed', String(single));
        splitButton?.setAttribute('aria-pressed', String(!single));
        ['left', 'right'].forEach(pane => {
            this.renderSourceTabs(pane);
            this.renderSourceIdentity(pane);
            const sideLabel = pane === 'left'
                ? this.t('fm.workspace.leftPane', 'Left side')
                : this.t('fm.workspace.rightPane', 'Right side');
            const sourceButton = document.querySelector(`[data-source-target="${pane}"]`);
            sourceButton?.setAttribute(
                'aria-label',
                single
                    ? this.t('fm.workspace.openSource', 'Open source')
                    : `${this.t('fm.workspace.openSource', 'Open source')}: ${sideLabel}`,
            );
            const activeTab = this.workspace.getActiveTab(pane);
            const legacySelect = document.getElementById(`fm${this.capitalize(pane)}Source`);
            if (legacySelect) legacySelect.value = activeTab?.source.key || '';
        });
        this.updateWorkspaceActions();
    }

    renderSourceTabs(pane) {
        const container = document.getElementById(`fm${this.capitalize(pane)}Tabs`);
        if (!container) return;
        const activeTab = this.workspace.getActiveTab(pane);
        container.innerHTML = this.workspace.getTabs(pane).map(tab => `
            <div class="fm-source-tab${activeTab?.id === tab.id ? ' active' : ''}" role="tab" aria-selected="${activeTab?.id === tab.id}">
                <button type="button" class="fm-source-tab-activate" data-tab-id="${this.escapeHtml(tab.id)}">
                    <span class="fm-connection-dot" aria-hidden="true"></span>
                    <span class="fm-source-tab-label">${this.escapeHtml(tab.source.label || this.t('fm.workspace.untitledSource', 'Source'))}</span>
                    <span class="fm-source-tab-protocol">${this.escapeHtml(tab.source.protocol || '')}</span>
                </button>
                <button type="button" class="fm-source-tab-close" data-close-tab="${this.escapeHtml(tab.id)}" aria-label="${this.escapeHtml(this.t('fm.workspace.closeSource', 'Close source'))}">
                    <span class="material-icons" aria-hidden="true">close</span>
                </button>
            </div>`).join('');
    }

    renderSourceIdentity(pane) {
        const container = document.getElementById(`fm${this.capitalize(pane)}Identity`);
        if (!container) return;
        const tab = this.workspace.getActiveTab(pane);
        const paneLabel = pane === 'left'
            ? this.t('fm.workspace.leftPane', 'Left side')
            : this.t('fm.workspace.rightPane', 'Right side');
        const paneBadge = this.workspace.layout === 'split'
            ? `<span class="fm-pane-label">${this.escapeHtml(paneLabel)}</span>`
            : '';
        if (!tab) {
            container.innerHTML = `
                ${paneBadge}
                <span class="fm-source-identity-empty">${this.escapeHtml(this.t('fm.selectSourceAbove', 'Select a source above'))}</span>`;
            return;
        }
        container.innerHTML = `
            ${paneBadge}
            <span class="fm-source-identity-name">${this.escapeHtml(tab.source.label || '')}</span>
            <span class="fm-protocol-badge">${this.escapeHtml(tab.source.protocol || '')}</span>
            <span class="fm-source-identity-endpoint">${this.escapeHtml(tab.source.endpoint || '')}</span>
            <span class="fm-source-identity-security"><span class="material-icons" aria-hidden="true">verified_user</span>${this.escapeHtml(tab.source.security || '')}</span>`;
    }

    activateSourceTab(pane, tabId) {
        const tab = this.workspace.activateTab(pane, tabId);
        if (!tab) return null;
        this.syncPaneFromWorkspace(pane);
        this.setActivePane(pane);
        this.updatePathInput(pane, tab.paneState.path || '/');
        this.updatePaneBadge(pane);
        this.renderPane(pane);
        this.renderWorkspaceChrome();
        return tab;
    }

    closeSourceTab(pane, tabId) {
        const result = this.workspace.closeTab(pane, tabId);
        if (!result.closed) return null;
        this.releaseQuickConnectionIfUnused(result.closed.source);
        this.syncPaneFromWorkspace(pane);
        this.updatePathInput(pane, this.panes[pane].path || '/');
        this.updatePaneBadge(pane);
        this.renderPane(pane);
        this.renderWorkspaceChrome();
        if (!result.active && this.workspace.layout === 'single') this.openSourceLauncher(pane);
        return result.closed;
    }

    releaseQuickConnectionIfUnused(source) {
        const connectionId = source?.connectionId;
        if (!connectionId) return false;

        const stillInUse = ['left', 'right'].some(pane => (
            this.workspace.getTabs(pane).some(tab => tab.source.connectionId === connectionId)
        ));
        if (stillInUse) return false;

        if (this.hasOutstandingTransferForConnection(connectionId)) {
            if (!this.pendingQuickDisconnects) this.pendingQuickDisconnects = new Set();
            this.pendingQuickDisconnects.add(connectionId);
            return false;
        }

        this.pendingQuickDisconnects?.delete(connectionId);
        this.quickConnections = (this.quickConnections || []).filter(
            connection => connection.connectionId !== connectionId
        );
        this.socket.emit('quick_disconnect', { connection_id: connectionId });
        this.updateSessionLists();
        return true;
    }

    getTransferConnectionIds(transfer = {}) {
        const ids = Array.isArray(transfer.connectionIds)
            ? transfer.connectionIds
            : [transfer.sessionId, transfer.sourceSessionId, transfer.targetSessionId];
        return [...new Set(ids.filter(Boolean))];
    }

    retainTransferConnections(connectionIds) {
        if (!this.transferConnectionHolds) this.transferConnectionHolds = new Map();
        [...new Set((connectionIds || []).filter(Boolean))].forEach(connectionId => {
            const current = this.transferConnectionHolds.get(connectionId) || 0;
            this.transferConnectionHolds.set(connectionId, current + 1);
        });
    }

    releaseTransferConnections(connectionIds) {
        if (!this.transferConnectionHolds) return;
        [...new Set((connectionIds || []).filter(Boolean))].forEach(connectionId => {
            const remaining = (this.transferConnectionHolds.get(connectionId) || 0) - 1;
            if (remaining > 0) this.transferConnectionHolds.set(connectionId, remaining);
            else this.transferConnectionHolds.delete(connectionId);
        });
    }

    hasOutstandingTransferForConnection(connectionId) {
        if ((this.transferConnectionHolds?.get(connectionId) || 0) > 0) return true;
        return (this.transferQueue || []).some(transfer => (
            ['pending', 'active'].includes(transfer.status)
            && this.getTransferConnectionIds(transfer).includes(connectionId)
        ));
    }

    flushPendingQuickDisconnects() {
        Array.from(this.pendingQuickDisconnects || []).forEach(connectionId => {
            this.releaseQuickConnectionIfUnused({ connectionId: connectionId });
        });
    }

    previewSelected() {
        const state = this.panes[this.activePane];
        if (!state || state.selected.size !== 1) return false;
        const index = Array.from(state.selected)[0];
        const file = state.files[index];
        if (!file || file.is_dir) return false;
        this.handleItemDblClick(this.activePane, index);
        return true;
    }

    canTransferBetweenPanes(sourcePane, targetPane) {
        if (!this.workspace || this.workspace.layout !== 'split') return false;
        if (!this.workspace.getActiveTab(sourcePane) || !this.workspace.getActiveTab(targetPane)) return false;

        const source = this.panes[sourcePane];
        const target = this.panes[targetPane];
        const sourceId = source?.sessionId || source?.connectionId;
        const targetId = target?.sessionId || target?.connectionId;
        return source?.type === 'ssh'
            && target?.type === 'ssh'
            && !source.loading
            && !target.loading
            && !source.autoHomeEligible
            && !target.autoHomeEligible
            && !source.error
            && !target.error
            && Boolean(sourceId)
            && Boolean(targetId)
            && sourceId !== targetId
            && typeof source.path === 'string'
            && typeof target.path === 'string';
    }

    updateWorkspaceActions() {
        if (this.displayMode !== 'modal' || !this.workspace) return;
        const state = this.panes[this.activePane];
        const selectedCount = state?.selected?.size || 0;
        const selectedFile = selectedCount === 1 ? state.files[Array.from(state.selected)[0]] : null;
        const hasSource = Boolean(state?.type);
        const targetPane = this.activePane === 'left' ? 'right' : 'left';
        const transferAvailable = this.canTransferBetweenPanes(this.activePane, targetPane) && selectedCount > 0;
        const setDisabled = (id, disabled) => {
            const element = document.getElementById(id);
            if (element) element.disabled = disabled;
        };
        setDisabled('fmNewFolder', !hasSource);
        setDisabled('fmEmbeddedUpload', state?.type !== 'ssh');
        setDisabled('fmDownload', !hasSource || selectedCount === 0);
        setDisabled('fmPreview', !selectedFile || selectedFile.is_dir);
        setDisabled('fmRename', selectedCount !== 1);
        setDisabled('fmDelete', selectedCount === 0);
        setDisabled('fmTransfer', !transferAvailable);
        setDisabled('fmTransferRight', !(this.canTransferBetweenPanes('left', 'right') && this.panes.left.selected.size > 0));
        setDisabled('fmTransferLeft', !(this.canTransferBetweenPanes('right', 'left') && this.panes.right.selected.size > 0));
        ['left', 'right'].forEach(pane => {
            const paneState = this.panes[pane];
            const paneSelection = paneState?.selected?.size || 0;
            const onlyFile = paneSelection === 1
                ? paneState.files[Array.from(paneState.selected)[0]]
                : null;
            document.querySelectorAll(`[data-pane-toolbar="${pane}"] [data-pane-action]`).forEach(button => {
                const action = button.dataset.paneAction;
                const disabled = {
                    newfolder: !paneState?.type,
                    upload: paneState?.type !== 'ssh',
                    download: !paneState?.type || paneSelection === 0,
                    preview: !onlyFile || onlyFile.is_dir,
                    rename: paneSelection !== 1,
                    delete: paneSelection === 0,
                }[action];
                button.disabled = Boolean(disabled);
            });
            const selectAll = document.querySelector(`[data-pane-select-all="${pane}"]`);
            if (selectAll) {
                selectAll.disabled = !paneState?.type || paneState.files.length === 0;
                selectAll.checked = paneState.files.length > 0 && paneSelection === paneState.files.length;
                selectAll.indeterminate = paneSelection > 0 && paneSelection < paneState.files.length;
            }
        });
        const hint = document.getElementById('fmTransferHint');
        if (hint) {
            const transferSelection = (
                this.canTransferBetweenPanes('left', 'right')
                || this.canTransferBetweenPanes('right', 'left')
            )
                ? Math.max(this.panes.left.selected.size, this.panes.right.selected.size)
                : 0;
            hint.textContent = transferSelection > 0
                ? `${transferSelection} ${this.t('fm.selected', 'selected')}`
                : this.t('fm.workspace.selectFiles', 'Select files');
        }
    }

    init() {
        this.createModal();
        this.setupSocketListeners();
        this.setupKeyboardShortcuts();
    }

    createModal() {
        const modal = document.createElement('div');
        modal.id = 'sftpFileManager';
        modal.className = 'modal modal-xlarge';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'fmModalTitle');
        modal.setAttribute('aria-hidden', 'true');
        modal.innerHTML = `
            <div class="modal-content fm-modal-fullwidth">
                <div class="modal-header fm-workspace-header">
                    <h2 id="fmModalTitle">
                        <span class="fm-workspace-title-icon"><span class="material-icons" aria-hidden="true">folder_open</span></span>
                        <span class="fm-workspace-title-copy">
                            <span class="fm-workspace-brand">WebSSH</span>
                            <span data-i18n="fm.title">File Manager</span>
                        </span>
                    </h2>
                    <div class="fm-workspace-controls">
                        <div class="fm-layout-switch" role="group" aria-label="File Manager layout" data-i18n-aria-label="fm.workspace.layout">
                            <button type="button" class="fm-layout-btn active" id="fmLayoutSingle" data-layout="single" aria-pressed="true" aria-label="1 pane" data-i18n-aria-label="fm.workspace.onePane">
                                <span class="material-icons" aria-hidden="true">crop_7_5</span>
                                <span data-i18n="fm.workspace.onePane">1 pane</span>
                            </button>
                            <button type="button" class="fm-layout-btn" id="fmLayoutSplit" data-layout="split" aria-pressed="false" aria-label="2 panes" data-i18n-aria-label="fm.workspace.twoPanes">
                                <span class="material-icons" aria-hidden="true">view_column</span>
                                <span data-i18n="fm.workspace.twoPanes">2 panes</span>
                            </button>
                        </div>
                    </div>
                    <button type="button" class="fm-workspace-close" id="fmClose" aria-label="Close" data-i18n-aria-label="common.close">
                        <span class="material-icons" aria-hidden="true">close</span>
                    </button>
                </div>
                <div class="modal-body">
                    <!-- Toolbar -->
                    <div class="fm-toolbar">
                        <div class="fm-toolbar-left">
                            <button class="btn btn-secondary btn-sm" id="fmRefresh" data-i18n-title="fm.refresh">
                                <span class="material-icons">refresh</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmNewFolder" data-i18n-title="fm.newFolder">
                                <span class="material-icons">create_new_folder</span>
                                <span class="btn-text" data-i18n="fm.newFolder">New Folder</span>
                            </button>
                        </div>
                        <div class="fm-toolbar-center">
                            <button class="btn btn-primary btn-sm" id="fmTransfer" data-i18n-title="fm.transfer">
                                <span class="material-icons">swap_horiz</span>
                                <span class="btn-text" data-i18n="fm.transfer">Transfer</span>
                            </button>
                        </div>
                        <div class="fm-toolbar-right">
                            <button class="btn btn-secondary btn-sm fm-embedded-upload" id="fmEmbeddedUpload" data-i18n-title="fm.upload" aria-label="Upload" data-i18n-aria-label="fm.upload">
                                <span class="material-icons" aria-hidden="true">upload</span>
                                <span class="btn-text" data-i18n="fm.upload">Upload</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmDownload" data-i18n-title="fm.download">
                                <span class="material-icons">download</span>
                                <span class="btn-text" data-i18n="fm.download">Download</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmPreview" data-i18n-title="fm.preview">
                                <span class="material-icons">preview</span>
                                <span class="btn-text" data-i18n="fm.preview">Preview</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmRename" data-i18n-title="fm.rename">
                                <span class="material-icons">drive_file_rename_outline</span>
                                <span class="btn-text" data-i18n="fm.rename">Rename</span>
                            </button>
                            <button class="btn btn-danger btn-sm" id="fmDelete" data-i18n-title="fm.delete">
                                <span class="material-icons">delete</span>
                                <span class="btn-text" data-i18n="fm.delete">Delete</span>
                            </button>
                        </div>
                    </div>

                    <!-- Mobile Pane Tabs -->
                    <div class="fm-pane-tabs" id="fmPaneTabs" role="tablist" aria-label="File Manager panes" data-i18n-aria-label="fm.workspace.layout">
                        <button class="fm-pane-tab active" data-pane="left" role="tab" aria-selected="true">
                            <span class="material-icons" aria-hidden="true">vertical_split</span>
                            <span data-i18n="fm.workspace.leftPane">Left side</span>
                        </button>
                        <button class="fm-pane-tab" data-pane="right" role="tab" aria-selected="false">
                            <span class="material-icons" aria-hidden="true">vertical_split</span>
                            <span data-i18n="fm.workspace.rightPane">Right side</span>
                        </button>
                    </div>

                    <!-- Dual Pane -->
                    <div class="fm-panes">
                        <!-- Left Pane -->
                        <div class="fm-pane active" id="fmLeftPane" data-pane="left">
                            <div class="fm-pane-header">
                                <div class="fm-source-tabs" id="fmLeftTabs" role="tablist" aria-label="Left side sources"></div>
                                <button type="button" class="fm-source-tab-add" data-source-target="left" aria-label="Open source" title="Open source">
                                    <span class="material-icons" aria-hidden="true">add</span>
                                </button>
                                <select class="fm-source-select form-control fm-legacy-source-select" id="fmLeftSource" tabindex="-1" aria-hidden="true">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmLeftSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ Quick Connect...</option>
                                </select>
                            </div>
                            <div class="fm-source-identity" id="fmLeftIdentity"></div>
                            <div class="fm-pane-nav">
                                <button class="fm-nav-btn" id="fmLeftUp" data-i18n-title="fm.goUp">
                                    <span class="material-icons">arrow_upward</span>
                                </button>
                                <button class="fm-nav-btn" id="fmLeftHome" data-i18n-title="fm.goHome">
                                    <span class="material-icons">home</span>
                                </button>
                                <div class="fm-breadcrumb" id="fmLeftBreadcrumb">
                                    <input type="text" class="fm-path-input" id="fmLeftPath" value="/" placeholder="/path">
                                </div>
                                <button class="fm-nav-btn" id="fmLeftRefresh" data-i18n-title="fm.refresh">
                                    <span class="material-icons">refresh</span>
                                </button>
                            </div>
                            <div class="fm-pane-toolbar" data-pane-toolbar="left">
                                <button type="button" data-pane-action="newfolder"><span class="material-icons">create_new_folder</span><span data-i18n="fm.newFolder">New Folder</span></button>
                                <button type="button" data-pane-action="upload"><span class="material-icons">upload</span><span data-i18n="fm.upload">Upload</span></button>
                                <button type="button" data-pane-action="download"><span class="material-icons">download</span><span data-i18n="fm.download">Download</span></button>
                                <button type="button" data-pane-action="preview"><span class="material-icons">preview</span><span data-i18n="fm.preview">Preview</span></button>
                                <button type="button" data-pane-action="rename"><span class="material-icons">drive_file_rename_outline</span><span data-i18n="fm.rename">Rename</span></button>
                                <button type="button" class="is-danger" data-pane-action="delete"><span class="material-icons">delete</span><span data-i18n="fm.delete">Delete</span></button>
                            </div>
                            <div class="fm-file-list-header">
                                <input type="checkbox" data-pane-select-all="left" aria-label="Select all files" data-i18n-aria-label="fm.workspace.selectAll">
                                <span data-i18n="fm.name">Name</span>
                                <span data-i18n="fm.size">Size</span>
                                <span data-i18n="fm.modified">Modified</span>
                                <span data-i18n="fm.permissions">Permissions</span>
                            </div>
                            <div class="fm-file-list" id="fmLeftList">
                                <div class="fm-empty">
                                    <span class="material-icons fm-empty-icon">folder_open</span>
                                    <div class="fm-empty-text" data-i18n="fm.selectSourceAbove">Select a source above</div>
                                </div>
                            </div>
                            <div class="fm-pane-footer">
                                <span class="fm-host-badge" id="fmLeftBadge"></span>
                                <div class="fm-pane-status">
                                    <span id="fmLeftCount">0 items</span>
                                    <span id="fmLeftSelected"></span>
                                </div>
                            </div>
                        </div>

                        <div class="fm-transfer-rail" aria-label="Transfer between panes" data-i18n-aria-label="fm.workspace.transferBetween">
                            <span class="fm-transfer-hint" id="fmTransferHint" data-i18n="fm.workspace.selectFiles">Select files</span>
                            <button type="button" class="fm-transfer-direction" id="fmTransferRight" aria-label="Transfer left to right" title="Transfer left to right">
                                <span class="material-icons" aria-hidden="true">arrow_forward</span>
                            </button>
                            <button type="button" class="fm-transfer-direction" id="fmTransferLeft" aria-label="Transfer right to left" title="Transfer right to left">
                                <span class="material-icons" aria-hidden="true">arrow_back</span>
                            </button>
                        </div>

                        <!-- Right Pane -->
                        <div class="fm-pane" id="fmRightPane" data-pane="right">
                            <div class="fm-pane-header">
                                <div class="fm-source-tabs" id="fmRightTabs" role="tablist" aria-label="Right side sources"></div>
                                <button type="button" class="fm-source-tab-add" data-source-target="right" aria-label="Open source" title="Open source">
                                    <span class="material-icons" aria-hidden="true">add</span>
                                </button>
                                <select class="fm-source-select form-control fm-legacy-source-select" id="fmRightSource" tabindex="-1" aria-hidden="true">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmRightSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ Quick Connect...</option>
                                </select>
                            </div>
                            <div class="fm-source-identity" id="fmRightIdentity"></div>
                            <div class="fm-pane-nav">
                                <button class="fm-nav-btn" id="fmRightUp" data-i18n-title="fm.goUp">
                                    <span class="material-icons">arrow_upward</span>
                                </button>
                                <button class="fm-nav-btn" id="fmRightHome" data-i18n-title="fm.goHome">
                                    <span class="material-icons">home</span>
                                </button>
                                <div class="fm-breadcrumb" id="fmRightBreadcrumb">
                                    <input type="text" class="fm-path-input" id="fmRightPath" value="/" placeholder="/path">
                                </div>
                                <button class="fm-nav-btn" id="fmRightRefresh" data-i18n-title="fm.refresh">
                                    <span class="material-icons">refresh</span>
                                </button>
                            </div>
                            <div class="fm-pane-toolbar" data-pane-toolbar="right">
                                <button type="button" data-pane-action="newfolder"><span class="material-icons">create_new_folder</span><span data-i18n="fm.newFolder">New Folder</span></button>
                                <button type="button" data-pane-action="upload"><span class="material-icons">upload</span><span data-i18n="fm.upload">Upload</span></button>
                                <button type="button" data-pane-action="download"><span class="material-icons">download</span><span data-i18n="fm.download">Download</span></button>
                                <button type="button" data-pane-action="preview"><span class="material-icons">preview</span><span data-i18n="fm.preview">Preview</span></button>
                                <button type="button" data-pane-action="rename"><span class="material-icons">drive_file_rename_outline</span><span data-i18n="fm.rename">Rename</span></button>
                                <button type="button" class="is-danger" data-pane-action="delete"><span class="material-icons">delete</span><span data-i18n="fm.delete">Delete</span></button>
                            </div>
                            <div class="fm-file-list-header">
                                <input type="checkbox" data-pane-select-all="right" aria-label="Select all files" data-i18n-aria-label="fm.workspace.selectAll">
                                <span data-i18n="fm.name">Name</span>
                                <span data-i18n="fm.size">Size</span>
                                <span data-i18n="fm.modified">Modified</span>
                                <span data-i18n="fm.permissions">Permissions</span>
                            </div>
                            <div class="fm-file-list" id="fmRightList">
                                <div class="fm-empty">
                                    <span class="material-icons fm-empty-icon">folder_open</span>
                                    <div class="fm-empty-text" data-i18n="fm.selectSourceAbove">Select a source above</div>
                                </div>
                            </div>
                            <div class="fm-pane-footer">
                                <span class="fm-host-badge" id="fmRightBadge"></span>
                                <div class="fm-pane-status">
                                    <span id="fmRightCount">0 items</span>
                                    <span id="fmRightSelected"></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Transfer Queue -->
                    <div class="fm-queue collapsed" id="fmQueue">
                        <button type="button" class="fm-queue-header" id="fmQueueHeader" aria-expanded="false" aria-controls="fmQueueList">
                            <span class="fm-queue-title">
                                <span class="material-icons">sync</span>
                                <span data-i18n="fm.transfers">Transfers</span> <span class="fm-queue-badge" id="fmQueueBadge">0</span>
                            </span>
                            <span class="fm-queue-toggle material-icons" id="fmQueueToggle">expand_more</span>
                        </button>
                        <div class="fm-queue-list" id="fmQueueList"></div>
                    </div>

                    <!-- Mobile Upload Button -->
                    <div class="fm-mobile-upload" id="fmMobileUpload">
                        <span class="material-icons">cloud_upload</span>
                        <span>Tap to upload files</span>
                        <input type="file" id="fmMobileUploadInput" multiple hidden>
                    </div>
                </div>

                <div class="fm-source-launcher" id="fmSourceLauncher" role="dialog" aria-modal="true" aria-labelledby="fmSourceLauncherTitle" aria-hidden="true">
                    <div class="fm-source-launcher-panel">
                        <div class="fm-source-launcher-header">
                            <div>
                                <h3 id="fmSourceLauncherTitle"><span id="fmSourceLauncherAction" data-i18n="fm.workspace.openSourceIn">Open source in</span> <span id="fmSourceLauncherPane">Left side</span></h3>
                                <p data-i18n="fm.workspace.sourceHint">Choose an active SSH session or a saved host.</p>
                            </div>
                            <button type="button" class="fm-source-launcher-close" id="fmSourceLauncherClose" aria-label="Close" data-i18n-aria-label="common.close">
                                <span class="material-icons" aria-hidden="true">close</span>
                            </button>
                        </div>
                        <label class="fm-source-search">
                            <span class="material-icons" aria-hidden="true">search</span>
                            <input type="search" id="fmSourceSearch" autocomplete="off" placeholder="Search sources" data-i18n-placeholder="fm.workspace.searchSources">
                        </label>
                        <div class="fm-source-groups" id="fmSourceGroups"></div>
                        <div class="fm-source-launcher-actions">
                            <button type="button" class="btn btn-secondary" id="fmNewSftpSource">
                                <span class="material-icons" aria-hidden="true">add</span>
                                <span><strong data-i18n="fm.workspace.newSftp">New SFTP connection</strong><small data-i18n="fm.workspace.sftpOverSsh">SFTP over SSH</small></span>
                            </button>
                            <button type="button" class="btn btn-secondary" id="fmNewSmbSource" disabled aria-disabled="true">
                                <span class="material-icons" aria-hidden="true">add</span>
                                <span><strong data-i18n="fm.workspace.newSmb">New SMB share</strong><small><span data-i18n="fm.workspace.comingSoon">Coming soon</span></small></span>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Mobile Action Sheet -->
                <div class="fm-action-sheet" id="fmActionSheet">
                    <div class="fm-action-sheet-item" data-action="open">
                        <span class="material-icons">folder_open</span>
                        <span>Open</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="download">
                        <span class="material-icons">download</span>
                        <span>Download</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="transfer">
                        <span class="material-icons">swap_horiz</span>
                        <span>Transfer</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="rename">
                        <span class="material-icons">edit</span>
                        <span>Rename</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="newfolder">
                        <span class="material-icons">create_new_folder</span>
                        <span>New Folder</span>
                    </div>
                    <div class="fm-action-sheet-item danger" data-action="delete">
                        <span class="material-icons">delete</span>
                        <span>Delete</span>
                    </div>
                    <div class="fm-action-sheet-cancel fm-action-sheet-item" data-action="cancel">
                        <span class="material-icons">close</span>
                        <span>Cancel</span>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        this.modal = modal;
        this.modalContent = modal.querySelector('.modal-content');
        this.modalBody = modal.querySelector('.modal-body');
        this.actionSheet = modal.querySelector('.fm-action-sheet');

        this.createQuickConnectModal();

        this.setupEventListeners();
    }

    createQuickConnectModal() {
        const qcModal = document.createElement('div');
        qcModal.id = 'fmQuickConnectModal';
        qcModal.className = 'modal modal-small';
        qcModal.setAttribute('role', 'dialog');
        qcModal.setAttribute('aria-modal', 'true');
        qcModal.setAttribute('aria-labelledby', 'fmQcModalTitle');
        qcModal.setAttribute('aria-hidden', 'true');
        qcModal.innerHTML = `
            <div class="modal-content fm-qc-modal">
                <div class="modal-header">
                    <h2 id="fmQcModalTitle" data-i18n="fm.qc.title">Connect to Server</h2>
                    <button type="button" class="close" id="fmQcClose" aria-label="Close" data-i18n-aria-label="common.close">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="fmQcForm">
                        <!-- Profile Selector -->
                        <div class="form-group">
                            <label for="fmQcProfile" data-i18n="fm.qc.savedProfiles">Saved Connections</label>
                            <select id="fmQcProfile" class="form-control">
                                <option value="" data-i18n="fm.qc.enterManually">-- Enter manually --</option>
                            </select>
                        </div>

                        <div class="fm-qc-divider">
                            <span data-i18n="fm.qc.orEnterDetails">or enter connection details</span>
                        </div>

                        <div class="form-row">
                            <div class="form-group flex-2">
                                <label for="fmQcHost" data-i18n="fm.qc.host">Host</label>
                                <input type="text" id="fmQcHost" class="form-control" placeholder="hostname or IP" required>
                            </div>
                            <div class="form-group flex-1">
                                <label for="fmQcPort" data-i18n="fm.qc.port">Port</label>
                                <input type="number" id="fmQcPort" class="form-control" value="22" min="1" max="65535">
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="fmQcUsername" data-i18n="fm.qc.username">Username</label>
                            <input type="text" id="fmQcUsername" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label data-i18n="fm.qc.authentication">Authentication</label>
                            <div class="auth-type-selector">
                                <label class="radio-label">
                                    <input type="radio" name="fmQcAuth" value="password" checked>
                                    <span data-i18n="fm.qc.password">Password</span>
                                </label>
                                <label class="radio-label">
                                    <input type="radio" name="fmQcAuth" value="key">
                                    <span data-i18n="fm.qc.sshKey">SSH Key</span>
                                </label>
                            </div>
                        </div>

                        <div class="form-group" id="fmQcPasswordGroup">
                            <label for="fmQcPassword" data-i18n="fm.qc.password">Password</label>
                            <div class="input-wrapper with-toggle">
                                <input type="password" id="fmQcPassword" class="form-control" placeholder="Enter password">
                                <button type="button" class="password-toggle" id="fmQcPwToggle" aria-label="Toggle password visibility">
                                    <span class="material-icons">visibility</span>
                                </button>
                            </div>
                        </div>

                        <div class="form-group hidden" id="fmQcKeyGroup">
                            <label for="fmQcKeySelect" data-i18n="fm.qc.sshKey">SSH Key</label>
                            <select id="fmQcKeySelect" class="form-control">
                                <option value="" data-i18n="fm.qc.selectKey">-- Select Key --</option>
                            </select>
                        </div>

                        <div class="form-actions">
                            <button type="button" class="btn btn-secondary" id="fmQcCancel" data-i18n="common.cancel">Cancel</button>
                            <button type="submit" class="btn btn-primary" id="fmQcConnectBtn">
                                <span class="btn-label" data-i18n="fm.qc.connect">Connect</span>
                                <span class="btn-spinner hidden"></span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        document.body.appendChild(qcModal);
        this.qcModal = qcModal;
        this.pendingQuickConnectPane = null;

        document.getElementById('fmQcClose').addEventListener('click', () => this.closeQuickConnect());
        document.getElementById('fmQcCancel').addEventListener('click', () => this.closeQuickConnect());
        qcModal.addEventListener('click', (e) => {
            if (e.target === qcModal) this.closeQuickConnect();
        });

        document.getElementById('fmQcProfile').addEventListener('change', (e) => {
            this.onProfileSelect(e.target.value);
        });

        document.getElementById('fmQcPwToggle').addEventListener('click', () => {
            const pwInput = document.getElementById('fmQcPassword');
            const icon = document.querySelector('#fmQcPwToggle .material-icons');
            if (pwInput.type === 'password') {
                pwInput.type = 'text';
                icon.textContent = 'visibility_off';
            } else {
                pwInput.type = 'password';
                icon.textContent = 'visibility';
            }
        });

        qcModal.querySelectorAll('input[name="fmQcAuth"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                document.getElementById('fmQcPasswordGroup').classList.toggle('hidden', e.target.value !== 'password');
                document.getElementById('fmQcKeyGroup').classList.toggle('hidden', e.target.value !== 'key');
            });
        });

        document.getElementById('fmQcForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitQuickConnect();
        });
    }

    setupEventListeners() {
        document.getElementById('fmClose').addEventListener('click', () => this.close());
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.close();
        });

        document.getElementById('fmRefresh').addEventListener('click', () => this.refreshBothPanes());
        document.getElementById('fmNewFolder').addEventListener('click', () => this.createNewFolder());
        document.getElementById('fmTransfer').addEventListener('click', () => this.executeTransfer());
        document.getElementById('fmDownload').addEventListener('click', () => this.downloadSelected());
        document.getElementById('fmPreview').addEventListener('click', () => this.previewSelected());
        document.getElementById('fmRename').addEventListener('click', () => this.renameSelected());
        document.getElementById('fmDelete').addEventListener('click', () => this.deleteSelected());
        document.getElementById('fmLayoutSingle').addEventListener('click', () => this.setWorkspaceLayout('single'));
        document.getElementById('fmLayoutSplit').addEventListener('click', () => this.setWorkspaceLayout('split'));
        document.querySelectorAll('[data-source-target]').forEach(button => {
            button.addEventListener('click', () => this.openSourceLauncher(button.dataset.sourceTarget));
        });
        document.getElementById('fmTransferRight').addEventListener('click', () => {
            this.setActivePane('left');
            this.executeTransfer();
        });
        document.getElementById('fmTransferLeft').addEventListener('click', () => {
            this.setActivePane('right');
            this.executeTransfer();
        });
        document.querySelector('.fm-panes').addEventListener('click', event => {
            const actionButton = event.target.closest('[data-pane-action]');
            if (!actionButton || actionButton.disabled) return;
            const pane = actionButton.closest('[data-pane-toolbar]')?.dataset.paneToolbar;
            if (!pane) return;
            this.setActivePane(pane);
            const actions = {
                newfolder: () => this.createNewFolder(),
                upload: () => document.getElementById('fmMobileUploadInput')?.click(),
                download: () => this.downloadSelected(),
                preview: () => this.previewSelected(),
                rename: () => this.renameSelected(),
                delete: () => this.deleteSelected(),
            };
            actions[actionButton.dataset.paneAction]?.();
        });
        document.querySelectorAll('[data-pane-select-all]').forEach(checkbox => {
            checkbox.addEventListener('click', event => event.stopPropagation());
            checkbox.addEventListener('change', () => {
                const pane = checkbox.dataset.paneSelectAll;
                const checked = checkbox.checked;
                this.setPaneSelection(pane, checked);
            });
        });

        document.getElementById('fmSourceLauncherClose').addEventListener('click', () => this.closeSourceLauncher());
        document.getElementById('fmSourceLauncher').addEventListener('click', event => {
            if (event.target.id === 'fmSourceLauncher') this.closeSourceLauncher();
        });
        document.getElementById('fmSourceSearch').addEventListener('input', event => {
            this.renderSourceLauncher(event.target.value);
        });
        document.getElementById('fmSourceGroups').addEventListener('click', event => {
            const sourceButton = event.target.closest('[data-source-key]');
            if (!sourceButton || sourceButton.disabled) return;
            const source = this.sourceCatalogByKey?.get(sourceButton.dataset.sourceKey);
            if (source) this.openWorkspaceSource(this.sourceLauncherPane, source);
        });
        document.getElementById('fmNewSftpSource').addEventListener('click', () => {
            this.pendingQuickConnectPane = this.sourceLauncherPane;
            this.closeSourceLauncher();
            this.openQuickConnect();
        });

        ['left', 'right'].forEach(pane => {
            document.getElementById(`fm${this.capitalize(pane)}Tabs`).addEventListener('click', event => {
                const closeButton = event.target.closest('[data-close-tab]');
                if (closeButton) {
                    event.stopPropagation();
                    this.closeSourceTab(pane, closeButton.dataset.closeTab);
                    return;
                }
                const tabButton = event.target.closest('[data-tab-id]');
                if (tabButton) this.activateSourceTab(pane, tabButton.dataset.tabId);
            });
        });

        document.getElementById('fmLeftSource').addEventListener('change', (e) => this.onSourceChange('left', e.target.value));
        document.getElementById('fmLeftUp').addEventListener('click', () => this.navigatePaneUp('left'));
        document.getElementById('fmLeftHome').addEventListener('click', () => this.navigatePaneHome('left'));
        document.getElementById('fmLeftRefresh').addEventListener('click', () => this.refreshPane('left'));
        document.getElementById('fmLeftPath').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.navigatePaneTo('left', e.target.value);
        });
        document.getElementById('fmLeftPane').addEventListener('click', (e) => {
            if (!e.target.closest('.fm-file-item') && !e.target.closest('.fm-pane-header') && !e.target.closest('.fm-pane-nav')) {
                this.setActivePane('left');
            }
        });

        document.getElementById('fmRightSource').addEventListener('change', (e) => this.onSourceChange('right', e.target.value));
        document.getElementById('fmRightUp').addEventListener('click', () => this.navigatePaneUp('right'));
        document.getElementById('fmRightHome').addEventListener('click', () => this.navigatePaneHome('right'));
        document.getElementById('fmRightRefresh').addEventListener('click', () => this.refreshPane('right'));
        document.getElementById('fmRightPath').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.navigatePaneTo('right', e.target.value);
        });
        document.getElementById('fmRightPane').addEventListener('click', (e) => {
            if (!e.target.closest('.fm-file-item') && !e.target.closest('.fm-pane-header') && !e.target.closest('.fm-pane-nav')) {
                this.setActivePane('right');
            }
        });

        this.setupDropZones();

        document.getElementById('fmQueueHeader').addEventListener('click', () => this.toggleQueue());
        document.getElementById('fmQueueList').addEventListener('click', (event) => {
            const button = event.target.closest('[data-transfer-cancel]');
            if (!button) return;
            this.cancelQueuedTransfer(button.dataset.transferCancel);
        });

        document.addEventListener('click', () => this.closeContextMenu());

        document.querySelectorAll('.fm-pane-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const pane = e.currentTarget.dataset.pane;
                this.setActivePane(pane);
                this.updateMobilePaneTabs(pane);
            });
        });

        const mobileUpload = document.getElementById('fmMobileUpload');
        const mobileUploadInput = document.getElementById('fmMobileUploadInput');
        const embeddedUpload = document.getElementById('fmEmbeddedUpload');
        if (mobileUpload && mobileUploadInput) {
            mobileUpload.addEventListener('click', () => mobileUploadInput.click());
            mobileUploadInput.addEventListener('change', (e) => this.handleMobileUpload(e));
            embeddedUpload?.addEventListener('click', () => mobileUploadInput.click());
        }

        document.querySelectorAll('.fm-action-sheet-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const action = e.currentTarget.dataset.action;
                this.handleActionSheetAction(action);
            });
        });

        this.setupLongPress();
    }

    setupDropZones() {
        ['left', 'right'].forEach(pane => {
            const paneEl = document.getElementById(`fm${this.capitalize(pane)}Pane`);

            paneEl.addEventListener('dragenter', (e) => {
                if (window.dragDropManager && e.dataTransfer?.types?.includes('Files')) {
                    window.dragDropManager.dragCounter = 0;
                    window.dragDropManager.hideOverlay();
                }
            });

            paneEl.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (this.dragSource && this.dragSource !== pane) {
                    paneEl.classList.add('drop-target');
                }
                if (e.dataTransfer?.types?.includes('Files')) {
                    paneEl.classList.add('drop-target');
                }
            });

            paneEl.addEventListener('dragleave', (e) => {
                if (!paneEl.contains(e.relatedTarget)) {
                    paneEl.classList.remove('drop-target');
                }
            });

            paneEl.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                paneEl.classList.remove('drop-target');
                this.handleDrop(e, pane);

                if (window.dragDropManager) {
                    window.dragDropManager.dragCounter = 0;
                    window.dragDropManager.hideOverlay();
                }
            });
        });
    }

    setupSocketListeners() {
        if (!this.socket) return;

        this.socket.on('directory_listing', (data) => {
            this.getPaneStateEntries().forEach(({ pane, state, visible }) => {
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id) &&
                    state.pendingDirectoryRequestId === data.request_id &&
                    state.pendingDirectoryPath === data.path) {
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.files = data.files || [];
                    state.path = data.path;
                    state.loading = false;
                    state.error = null;
                    state.pendingDirectoryRequestId = null;
                    state.pendingDirectoryPath = null;
                    if (visible) {
                        this.updatePathInput(pane, data.path);
                        this.renderPane(pane);
                    }
                }
            });
        });

        this.socket.on('home_directory', (data) => {
            if (!this.isOpen) return;
            this.getPaneStateEntries().forEach(({ pane, state, visible }) => {
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id) &&
                    state.pendingHomeRequestId === data.request_id) {
                    state.pendingHomeRequestId = null;
                    state.homePath = data.path;
                    if (state.autoHomeEligible && state.path === '/') {
                        state.autoHomeEligible = false;
                        if (visible) this.navigatePaneTo(pane, data.path);
                        else this.requestDirectoryForState(pane, state, data.path);
                    }
                }
            });
        });

        this.socket.on('directory_created', (data) => {
            if (this.uploadBatches?.size > 0) return;
            this.showNotification(`${this.t('fm.folderCreated', 'Folder created')}: ${data.path}`, 'success');
            this.refreshBothPanes();
        });

        this.socket.on('file_renamed', () => {
            this.showNotification(this.t('fm.renamedSuccess', 'Renamed successfully'), 'success');
            this.refreshBothPanes();
        });

        this.socket.on('item_deleted', (data) => {
            this.showNotification(`${this.t('fm.deleted', 'Deleted')}: ${data.path}`, 'success');
            this.refreshBothPanes();
        });

        this.socket.on('s2s_transfer_started', () => {
            this.showNotification(this.t('fm.transferStarted', 'Server-to-server transfer started'), 'info');
        });

        this.socket.on('s2s_transfer_progress', (data) => {
            this.updateTransferProgress(data);
        });

        this.socket.on('s2s_transfer_complete', (data) => {
            this.showNotification(`${this.t('fm.transferComplete', 'Transfer complete')}: ${data.filename}`, 'success');
            this.refreshBothPanes();
            this.completeS2STransfer(data);
        });

        this.socket.on('s2s_transfer_error', (data) => {
            this.showNotification(`${this.t('fm.transferFailed', 'Transfer failed')}: ${data.error}`, 'error');
            this.failS2STransfer(data);
        });

        this.socket.on('quick_connect_success', (data) => {
            this.handleQuickConnectSuccess(data);
        });

        this.socket.on('quick_connect_error', (data) => {
            this.showNotification(`${this.t('fm.qc.connectionFailed', 'Connection failed')}: ${data.error}`, 'error');
            const btn = document.getElementById('fmQcConnectBtn');
            if (btn) {
                btn.disabled = false;
                btn.querySelector('.btn-label').textContent = this.t('fm.qc.connect', 'Connect');
                btn.querySelector('.btn-spinner')?.classList.add('hidden');
            }
        });

        this.socket.on('error', (data) => {
            if (!this.handlesSocketError(data)) return;
            const errorMsg = data.error || data.message || 'Unknown error';
            this.getPaneStateEntries().forEach(({ pane, state, visible }) => {
                if (state.loading && state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id) &&
                    state.pendingDirectoryRequestId === data.request_id &&
                    state.pendingDirectoryPath === data.path) {
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.loading = false;
                    state.error = errorMsg;
                    state.pendingDirectoryRequestId = null;
                    state.pendingDirectoryPath = null;
                    if (visible) this.renderPane(pane);
                    if (this.isOpen !== false) this.showNotification(errorMsg, 'error');
                }
            });
        });

        this.socket.on('file_exists_result', (data) => {
            if (this.pendingConflictCheck) {
                this.pendingConflictCheck(data);
                this.pendingConflictCheck = null;
            }
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', e => this.handleKeyboardShortcut(e));
    }

    handlesSocketError(data) {
        if (data?.operation !== 'list_directory') return false;
        return this.getPaneStateEntries().some(({ state }) => {
            return state.type === 'ssh'
                && (state.sessionId === data.session_id || state.connectionId === data.session_id)
                && state.pendingDirectoryRequestId === data.request_id
                && state.pendingDirectoryPath === data.path;
        });
    }

    getPaneStateEntries() {
        if (this.displayMode === 'embedded' || !this.workspace) {
            return ['left', 'right']
                .filter(pane => this.panes?.[pane])
                .map(pane => ({
                    pane,
                    state: this.panes[pane],
                    visible: this.isOpen !== false && this.displayMode !== 'closed',
                }));
        }
        return ['left', 'right'].flatMap(pane => {
            const activeTab = this.workspace.getActiveTab(pane);
            return this.workspace.getTabs(pane).map(tab => ({
                pane,
                state: tab.paneState,
                visible: this.isOpen
                    && this.displayMode === 'modal'
                    && activeTab?.id === tab.id,
            }));
        });
    }

    handleKeyboardShortcut(e) {
        if (!this.isOpen) return;

        if (e.key === 'Escape') {
            this.closeContextMenu();
            if (this.sourceLauncherPane) {
                e.preventDefault();
                this.closeSourceLauncher();
                return;
            }
            if (!this.hasOpenDialogs()) {
                if (this.displayMode === 'embedded') {
                    window.dispatchEvent?.(new CustomEvent('session-sftp-request-close'));
                    if (this.displayMode === 'embedded') this.closeEmbedded();
                } else {
                    this.close();
                }
            }
        }

        if (e.key === 'Tab' && this.sourceLauncherPane && this.trapSourceLauncherFocus(e)) {
            return;
        }

        const interactiveTarget = e.target?.closest?.(
            'input, textarea, select, button, a[href], [contenteditable="true"], [role="button"], [role="checkbox"]',
        );
        if (interactiveTarget) return;

        if (
            e.key === 'Tab'
            && this.displayMode !== 'embedded'
            && this.workspace.layout === 'split'
            && !e.target.matches('input, textarea, select')
        ) {
            e.preventDefault();
            this.setActivePane(this.activePane === 'left' ? 'right' : 'left');
        }

        if (e.ctrlKey && e.key.toLocaleLowerCase() === 'k' && this.displayMode === 'modal') {
            e.preventDefault();
            this.openSourceLauncher(this.workspace.activePane);
        }

        if (e.ctrlKey && e.key === 'a' && !e.target.matches('input, textarea')) {
            e.preventDefault();
            this.selectAll();
        }

        if (e.key === 'Delete' && !e.target.matches('input, textarea')) {
            e.preventDefault();
            this.deleteSelected();
        }

        if (e.key === 'F5') {
            e.preventDefault();
            if (this.displayMode === 'embedded') this.refreshPane(this.activePane);
            else this.executeTransfer();
        }

        if (e.key === 'F7') {
            e.preventDefault();
            this.createNewFolder();
        }

        if (e.key === 'F2') {
            e.preventDefault();
            this.renameSelected();
        }

        if (e.key === 'Enter' && !e.target.matches('input, textarea')) {
            e.preventDefault();
            const state = this.panes[this.activePane];
            if (state.selected.size === 1) {
                const index = Array.from(state.selected)[0];
                this.handleItemDblClick(this.activePane, index);
            }
        }
    }

    open() {
        if (this.displayMode === 'embedded') {
            window.dispatchEvent?.(new CustomEvent('session-sftp-request-close'));
            if (this.displayMode === 'embedded') this.closeEmbedded();
        }
        this.isOpen = true;
        this.displayMode = 'modal';
        this.modal.classList.add('fm-workspace-mode');
        if (this.isMobile()) this.modal.classList.add('fm-mobile-mode');
        else this.modal.classList.remove('fm-mobile-mode');
        if (window.ModalManager) {
            window.ModalManager.open(this.modal);
        } else {
            this.modal.classList.add('show');
            this.modal.setAttribute('aria-hidden', 'false');
        }
        this.applyTranslations();
        this.updateSessionLists();
        this.loadWorkspaceProfiles();
        ['left', 'right'].forEach(pane => {
            this.syncPaneFromWorkspace(pane);
            this.updatePathInput(pane, this.panes[pane].path || '/');
            this.updatePaneBadge(pane);
            this.renderPane(pane);
        });
        this.setActivePane(this.workspace.activePane || 'left');
        this.renderWorkspaceChrome();
        if (!this.workspace.getActiveTab(this.workspace.activePane)) {
            this.openSourceLauncher(this.workspace.activePane);
        }
    }

    close() {
        if (this.displayMode === 'embedded') {
            this.closeEmbedded();
            return;
        }
        this.isOpen = false;
        this.displayMode = 'closed';
        this.closeSourceLauncher();
        if (window.ModalManager) {
            window.ModalManager.close(this.modal);
        } else {
            this.modal.classList.remove('show');
            this.modal.setAttribute('aria-hidden', 'true');
        }
        this.closeContextMenu();

        if (window.dragDropManager) {
            window.dragDropManager.reset();
        }

        ['left', 'right'].forEach(pane => {
            const paneEl = document.getElementById(`fm${this.capitalize(pane)}Pane`);
            if (paneEl) {
                paneEl.classList.remove('drop-target');
            }
        });

        if (this.uploadProgressNotification) {
            this.uploadProgressNotification.remove();
            this.uploadProgressNotification = null;
        }
    }

    async openEmbedded(container, sessionId, session = {}) {
        if (!container || !sessionId) return false;
        if (this.displayMode === 'modal') this.close();

        this.enterEmbeddedPaneState();
        this.isOpen = true;
        this.displayMode = 'embedded';
        this.modal?.classList.remove('fm-workspace-mode', 'fm-workspace-single', 'fm-workspace-split', 'fm-single-right');
        this.embeddedContainer = container;
        this.modalBody.classList.add('fm-embedded-mode');
        this.applyTranslations();
        container.replaceChildren(this.modalBody);
        this.updateSessionLists();

        const sessionRecord = {
            ...session,
            id: sessionId,
            connected: session.connected !== false,
        };
        const index = this.availableSessions.findIndex(item => item.id === sessionId);
        if (index >= 0) this.availableSessions[index] = sessionRecord;
        else this.availableSessions.push(sessionRecord);

        this.setActivePane('left');
        await this.onSourceChange('left', `ssh:${sessionId}`);
        return true;
    }

    async followEmbedded(sessionId, session = {}) {
        if (this.displayMode !== 'embedded' || !sessionId) return false;
        if (this.panes.left.sessionId === sessionId) {
            this.panes.left.hostInfo = {
                host: session.host,
                username: session.username,
                port: session.port,
            };
            this.updatePaneBadge('left');
            return true;
        }
        return this.openEmbedded(this.embeddedContainer, sessionId, session);
    }

    closeEmbedded() {
        if (this.displayMode !== 'embedded') return;
        this.closeContextMenu();
        this.resetPane('left');
        this.modalBody.classList.remove('fm-embedded-mode');
        this.modalContent.insertBefore(this.modalBody, this.actionSheet);
        this.embeddedContainer = null;
        this.displayMode = 'closed';
        this.isOpen = false;
        this.restoreStandalonePaneState();
    }

    isEmbeddedOpen() {
        return this.displayMode === 'embedded';
    }

    handleEmbeddedDisconnect(sessionId) {
        if (
            this.displayMode === 'embedded'
            && this.panes.left.sessionId === sessionId
        ) {
            this.resetPane('left');
        }
    }

    handleSessionDisconnected(sessionId) {
        if (this.displayMode !== 'embedded' && this.workspace) {
            ['left', 'right'].forEach(pane => {
                const matchingTabs = this.workspace.getTabs(pane).filter(tab => {
                    const state = tab.paneState;
                    return state.type === 'ssh'
                        && (state.sessionId === sessionId || state.connectionId === sessionId);
                });
                matchingTabs.forEach(tab => this.workspace.closeTab(pane, tab.id));
                this.syncPaneFromWorkspace(pane);
                if (this.isOpen && this.displayMode === 'modal') {
                    this.updatePathInput(pane, this.panes[pane].path || '/');
                    this.updatePaneBadge(pane);
                    this.renderPane(pane);
                }
            });
            if (this.isOpen && this.displayMode === 'modal') {
                this.updateSessionLists();
                this.renderWorkspaceChrome();
            }
            return;
        }
        this.getPaneStateEntries().forEach(({ pane, state, visible }) => {
            if (state.type === 'ssh' &&
                (state.sessionId === sessionId || state.connectionId === sessionId)) {
                if (visible) this.resetPane(pane);
                else Object.assign(state, this.createEmptyPaneState());
            }
        });
        this.updateSessionLists();
        this.renderWorkspaceChrome();
    }

    hasOpenDialogs() {
        return document.querySelector('.fm-conflict-dialog') !== null ||
               this.qcModal.classList.contains('show') ||
               document.getElementById('fmSourceLauncher')?.classList.contains('show');
    }

    updateSessionLists() {
        const sessions = typeof SessionManager !== 'undefined' ? SessionManager.getAllSessions() : [];
        this.availableSessions = sessions.filter(s => s.connected);

        ['Left', 'Right'].forEach(side => {
            const group = document.getElementById(`fm${side}Sessions`);
            group.innerHTML = '';

            this.availableSessions.forEach(session => {
                const option = document.createElement('option');
                option.value = `ssh:${session.id}`;
                option.textContent = `${session.username}@${session.host}`;
                group.appendChild(option);
            });

            this.quickConnections.forEach(qc => {
                const option = document.createElement('option');
                option.value = `qc:${qc.connectionId}`;
                option.textContent = `${qc.username}@${qc.host} (quick)`;
                group.appendChild(option);
            });
        });
    }

    async onSourceChange(pane, value) {
        const state = this.panes[pane];

        if (value === 'quick-connect') {
            this.pendingQuickConnectPane = pane;
            this.openQuickConnect();
            const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
            if (select) {
                select.value = state.type === 'ssh' ? `ssh:${state.sessionId || state.connectionId}` : '';
            }
            return;
        }

        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
        }
        Object.keys(state).forEach(key => delete state[key]);
        Object.assign(state, this.createEmptyPaneState());
        state.loading = true;
        this.renderPane(pane);

        if (!value) {
            state.type = null;
            state.sessionId = null;
            state.connectionId = null;
            state.loading = false;
            this.renderPane(pane);
            this.updatePaneBadge(pane);
            return;
        }

        if (value.startsWith('ssh:')) {
            const sessionId = value.substring(4);
            state.type = 'ssh';
            state.sessionId = sessionId;
            state.connectionId = null;
            state.autoHomeEligible = true;

            const session = this.availableSessions.find(s => s.id === sessionId);
            if (session) {
                state.hostInfo = { host: session.host, username: session.username, port: session.port };
            }

            this.requestHomeDirectory(pane, sessionId);
            this.requestDirectory(pane, '/');
            this.updatePaneBadge(pane);

            this.setLoadingTimeout(pane);

        } else if (value.startsWith('qc:')) {
            const connectionId = value.substring(3);
            const qc = this.quickConnections.find(c => c.connectionId === connectionId);

            state.type = 'ssh';
            state.sessionId = null;
            state.connectionId = connectionId;
            state.autoHomeEligible = true;

            if (qc) {
                state.hostInfo = { host: qc.host, username: qc.username, port: qc.port };
            }

            this.requestHomeDirectory(pane, connectionId);
            this.requestDirectory(pane, '/');
            this.updatePaneBadge(pane);

            this.setLoadingTimeout(pane);
        }
    }

    nextRequestId(pane, operation) {
        this.requestSequence = (this.requestSequence || 0) + 1;
        return `${pane}:${operation}:${this.requestSequence}`;
    }

    requestHomeDirectory(pane, sessionId) {
        const state = this.panes[pane];
        const requestId = this.nextRequestId(pane, 'home');
        state.pendingHomeRequestId = requestId;
        this.socket.emit('get_home_directory', { session_id: sessionId, request_id: requestId });
        return requestId;
    }

    requestDirectory(pane, path) {
        const state = this.panes[pane];
        return this.requestDirectoryForState(pane, state, path);
    }

    requestDirectoryForState(pane, state, path) {
        state.selected?.clear();
        state.path = path;
        state.loading = true;
        const requestId = this.nextRequestId(pane, 'directory');
        state.pendingDirectoryRequestId = requestId;
        state.pendingDirectoryPath = path;
        this.socket.emit('list_directory', {
            session_id: state.sessionId || state.connectionId,
            remote_path: path,
            request_id: requestId,
        });
        return requestId;
    }

    setLoadingTimeout(pane, timeout = 10000) {
        const state = this.panes[pane];

        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
        }

        state.loadingTimeout = setTimeout(() => {
            if (state.loading) {
                state.loading = false;
                state.error = this.t('fm.connectionTimeout', 'Connection timeout - could not load directory');
                this.renderPane(pane);
                this.showNotification(this.t('fm.loadTimeout', 'Failed to load directory: timeout'), 'error');
            }
        }, timeout);
    }

    updatePaneBadge(pane) {
        const state = this.panes[pane];
        const badge = document.getElementById(`fm${this.capitalize(pane)}Badge`);

        if (!state.type) {
            badge.textContent = '';
            badge.className = 'fm-host-badge';
            return;
        }

        if (state.hostInfo) {
            badge.textContent = `${state.hostInfo.username}@${state.hostInfo.host}`;
            badge.className = 'fm-host-badge ssh';
        }
    }

    openQuickConnect(profileId = null) {
        this.pendingQuickConnectProfileId = profileId;
        if (this.socket) {
            this.socket.emit('list_profiles');
            this.socket.once('profiles_list', (data) => {
                const select = document.getElementById('fmQcProfile');
                select.innerHTML = '<option value="">-- Enter manually --</option>';
                this.qcProfiles = data.profiles || [];
                this.qcProfiles.forEach(profile => {
                    const option = document.createElement('option');
                    option.value = profile.id;
                    option.textContent = `${profile.name} (${profile.username}@${profile.host})`;
                    select.appendChild(option);
                });
                if (this.pendingQuickConnectProfileId != null) {
                    select.value = String(this.pendingQuickConnectProfileId);
                    this.onProfileSelect(this.pendingQuickConnectProfileId);
                }
            });

            this.socket.emit('list_keys');
            this.socket.once('keys_list', (data) => {
                const select = document.getElementById('fmQcKeySelect');
                select.innerHTML = '<option value="">-- Select Key --</option>';
                this.qcKeys = data.keys || [];
                this.qcKeys.forEach(key => {
                    const option = document.createElement('option');
                    option.value = key.id;
                    option.textContent = `${key.name} (${key.type || 'unknown'})`;
                    select.appendChild(option);
                });
                const selectedProfileId = document.getElementById('fmQcProfile').value
                    || this.pendingQuickConnectProfileId;
                if (selectedProfileId != null && selectedProfileId !== '') {
                    this.onProfileSelect(selectedProfileId);
                }
            });
        }

        if (window.ModalManager) {
            window.ModalManager.open(this.qcModal);
        } else {
            this.qcModal.classList.add('show');
            this.qcModal.setAttribute('aria-hidden', 'false');
        }
        document.getElementById('fmQcHost').focus();
    }

    onProfileSelect(profileId) {
        if (!profileId) {
            document.getElementById('fmQcHost').value = '';
            document.getElementById('fmQcPort').value = '22';
            document.getElementById('fmQcUsername').value = '';
            document.getElementById('fmQcPassword').value = '';
            return;
        }

        const profile = (this.qcProfiles || []).find(p => p.id == profileId);
        if (!profile) return;

        document.getElementById('fmQcHost').value = profile.host || '';
        document.getElementById('fmQcPort').value = profile.port || 22;
        document.getElementById('fmQcUsername').value = profile.username || '';

        const authType = profile.key_id ? 'key' : 'password';
        document.querySelector(`input[name="fmQcAuth"][value="${authType}"]`).checked = true;
        document.getElementById('fmQcPasswordGroup').classList.toggle('hidden', authType !== 'password');
        document.getElementById('fmQcKeyGroup').classList.toggle('hidden', authType !== 'key');

        if (profile.key_id) {
            document.getElementById('fmQcKeySelect').value = profile.key_id;
        }

        if (authType === 'password') {
            document.getElementById('fmQcPassword').focus();
        }
    }

    closeQuickConnect() {
        if (window.ModalManager) {
            window.ModalManager.close(this.qcModal);
            if (this.modal.classList.contains('show')) {
                window.ModalManager.activeModal = this.modal;
            }
        } else {
            this.qcModal.classList.remove('show');
            this.qcModal.setAttribute('aria-hidden', 'true');
        }
        this.pendingQuickConnectPane = null;
        this.pendingQuickConnectProfileId = null;
        document.getElementById('fmQcForm').reset();
        document.getElementById('fmQcProfile').value = '';
        document.getElementById('fmQcPasswordGroup').classList.remove('hidden');
        document.getElementById('fmQcKeyGroup').classList.add('hidden');
    }

    submitQuickConnect() {
        const host = document.getElementById('fmQcHost').value.trim();
        const port = parseInt(document.getElementById('fmQcPort').value) || 22;
        const username = document.getElementById('fmQcUsername').value.trim();
        const authType = document.querySelector('input[name="fmQcAuth"]:checked').value;
        const password = document.getElementById('fmQcPassword').value;
        const keyId = document.getElementById('fmQcKeySelect').value;

        if (!host || !username) {
            this.showNotification(this.t('fm.qc.hostRequired', 'Host and username are required'), 'warning');
            return;
        }

        if (authType === 'password' && !password) {
            this.showNotification(this.t('fm.qc.passwordRequired', 'Password is required'), 'warning');
            return;
        }

        if (authType === 'key' && !keyId) {
            this.showNotification(this.t('fm.qc.selectSshKey', 'Please select an SSH key'), 'warning');
            return;
        }

        const data = { host, port, username };
        if (authType === 'password') {
            data.password = password;
        } else {
            data.key_id = keyId;
        }

        this.socket.emit('quick_connect', data);
        this.showNotification(this.t('fm.connecting', 'Connecting...'), 'info');
    }

    handleQuickConnectSuccess(data) {
        this.showNotification(`${this.t('fm.connected', 'Connected')}: ${data.host}`, 'success');

        const qc = {
            connectionId: data.connection_id,
            host: data.host,
            port: data.port,
            username: data.username
        };
        this.quickConnections.push(qc);

        this.updateSessionLists();

        const pane = this.pendingQuickConnectPane;
        this.closeQuickConnect();
        if (pane && this.displayMode === 'modal') {
            this.openWorkspaceSource(pane, {
                key: `qc:${data.connection_id}`,
                type: 'ssh',
                label: `${data.username}@${data.host}`,
                endpoint: `${data.host}:${data.port || 22}`,
                protocol: 'SFTP',
                status: this.t('fm.workspace.connected', 'Connected'),
                security: this.t('fm.workspace.hostKeyTrusted', 'SSH host key trusted'),
                connectionId: data.connection_id,
            });
        } else if (pane) {
            this.onSourceChange(pane, `qc:${data.connection_id}`);
        }
    }

    async navigatePaneTo(pane, path) {
        const state = this.panes[pane];

        if (!state.type) {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
            return;
        }

        state.autoHomeEligible = false;
        state.selected.clear();
        state.loading = true;
        this.renderPane(pane);

        if (state.type === 'ssh') {
            this.requestDirectory(pane, path);
            this.setLoadingTimeout(pane);
        }
    }

    async navigatePaneUp(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'ssh') {
            if (state.path === '/') return;
            const parentPath = state.path.split('/').slice(0, -1).join('/') || '/';
            this.navigatePaneTo(pane, parentPath);
        }
    }

    navigatePaneHome(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'ssh') {
            const homePath = state.homePath || '/';
            this.navigatePaneTo(pane, homePath);
        }
    }

    async navigateIntoDir(pane, dirName) {
        const state = this.panes[pane];

        if (state.type === 'ssh') {
            const newPath = state.path === '/' ? '/' + dirName : state.path + '/' + dirName;
            this.navigatePaneTo(pane, newPath);
        }
    }

    async refreshPane(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            if (!sessionId) return;

            if (state.sessionId && typeof SessionManager !== 'undefined') {
                const sessions = SessionManager.getAllSessions();
                const sessionExists = sessions.some(s => s.id === state.sessionId && s.connected);
                if (!sessionExists) {
                    this.resetPane(pane);
                    return;
                }
            }

            state.autoHomeEligible = false;
            state.loading = true;
            this.renderPane(pane);
            this.requestDirectory(pane, state.path);
            this.setLoadingTimeout(pane);
        }
    }

    refreshBothPanes() {
        this.refreshPane('left');
        this.refreshPane('right');
    }

    resetPane(pane) {
        const state = this.panes[pane];
        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
        }
        Object.keys(state).forEach(key => delete state[key]);
        Object.assign(state, this.createEmptyPaneState());
        const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
        if (select) select.value = '';
        this.updatePathInput(pane, '/');
        this.updatePaneBadge(pane);
        this.renderPane(pane);
    }

    updatePathInput(pane, path) {
        document.getElementById(`fm${this.capitalize(pane)}Path`).value = path;
    }

    renderPane(pane) {
        const state = this.panes[pane];
        const container = document.getElementById(`fm${this.capitalize(pane)}List`);

        if (state.loading) {
            container.innerHTML = `
                <div class="fm-loading">
                    <div class="fm-loading-spinner"></div>
                    ${this.t('fm.loading', 'Loading...')}
                </div>
            `;
            this.updatePaneStatus(pane);
            return;
        }

        if (state.error) {
            container.innerHTML = `
                <div class="fm-error">
                    <span class="material-icons fm-error-icon">error_outline</span>
                    <div class="fm-error-text">${this.escapeHtml(state.error)}</div>
                    <button class="btn btn-secondary btn-sm fm-error-retry" data-pane="${pane}">
                        <span class="material-icons">refresh</span>
                        ${this.t('fm.retry', 'Retry')}
                    </button>
                </div>
            `;
            container.querySelector('.fm-error-retry')?.addEventListener('click', () => {
                state.error = null;
                this.refreshPane(pane);
            });
            this.updatePaneStatus(pane);
            return;
        }

        if (!state.type) {
            const paneLabel = pane === 'left'
                ? this.t('fm.workspace.leftPane', 'Left side')
                : this.t('fm.workspace.rightPane', 'Right side');
            const openSourceLabel = this.t('fm.workspace.openSource', 'Open source');
            const chooseLabel = this.workspace.layout === 'split'
                ? `${openSourceLabel}: ${paneLabel}`
                : openSourceLabel;
            container.innerHTML = `
                <div class="fm-empty fm-source-empty-state">
                    <span class="fm-empty-icon-shell"><span class="material-icons fm-empty-icon" aria-hidden="true">folder_open</span></span>
                    <strong>${this.escapeHtml(this.t('fm.selectSourceAbove', 'Select a source above'))}</strong>
                    <p>${this.escapeHtml(this.t('fm.workspace.sourceHint', 'Choose an active SSH session or a saved host.'))}</p>
                    <button type="button" class="btn btn-primary fm-empty-source-cta" aria-label="${this.escapeHtml(chooseLabel)}">
                        <span class="material-icons" aria-hidden="true">folder_open</span>
                        <span>${this.escapeHtml(openSourceLabel)}</span>
                    </button>
                </div>
            `;
            container.querySelector('.fm-empty-source-cta')?.addEventListener('click', () => this.openSourceLauncher(pane));
            this.updatePaneStatus(pane);
            return;
        }

        if (state.files.length === 0) {
            container.innerHTML = `
                <div class="fm-empty">
                    <span class="material-icons fm-empty-icon">folder_off</span>
                    <div class="fm-empty-text">${this.t('fm.emptyDirectory', 'Empty directory')}</div>
                </div>
            `;
            this.updatePaneStatus(pane);
            return;
        }

        const sortedFiles = [...state.files].sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });

        const indexMap = new Map();
        sortedFiles.forEach((file, sortedIndex) => {
            const originalIndex = state.files.indexOf(file);
            indexMap.set(sortedIndex, originalIndex);
        });

        let html = '';

        if (state.path !== '/') {
            html += `
                <div class="fm-file-item directory" data-index="-1" data-type="parent">
                    <span class="fm-file-checkbox" aria-hidden="true"></span>
                    <span class="material-icons fm-file-icon parent">arrow_upward</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">..</div>
                    </div>
                    <div class="fm-file-size">-</div>
                    <div class="fm-file-modified">-</div>
                    <div class="fm-file-permissions">${this.t('fm.parentDirectory', 'Parent directory')}</div>
                </div>
            `;
        }

        html += sortedFiles.map((file, sortedIndex) => {
            const originalIndex = indexMap.get(sortedIndex);
            const icon = file.is_dir ? 'folder' : this.getFileIcon(file.name);
            return `
                <div class="fm-file-item ${file.is_dir ? 'directory' : ''} ${state.selected.has(originalIndex) ? 'selected' : ''}"
                     data-index="${originalIndex}"
                     data-type="${file.is_dir ? 'directory' : 'file'}"
                     draggable="true">
                    <button type="button" class="fm-file-checkbox material-icons" role="checkbox"
                            aria-checked="${state.selected.has(originalIndex)}"
                            aria-label="${this.escapeHtml(this.t('fm.workspace.selectItem', 'Select'))}: ${this.escapeHtml(file.name)}">${state.selected.has(originalIndex) ? 'check_box' : 'check_box_outline_blank'}</button>
                    <span class="material-icons fm-file-icon ${file.is_dir ? 'folder' : 'file'}">${icon}</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">${this.escapeHtml(file.name)}</div>
                    </div>
                    <div class="fm-file-size">${file.is_dir ? '-' : this.formatSize(file.size || 0)}</div>
                    <div class="fm-file-modified">${this.escapeHtml(this.formatModified(file.modified))}</div>
                    <div class="fm-file-permissions">${this.escapeHtml(this.formatPermissions(file))}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = html;

        container.querySelectorAll('.fm-file-item').forEach(item => {
            const index = parseInt(item.dataset.index);
            item.addEventListener('click', (e) => this.handleItemClick(e, pane, index));
            item.addEventListener('dblclick', (e) => this.handleItemDoubleClickEvent(e, pane, index));
            item.addEventListener('contextmenu', (e) => this.showContextMenu(e, pane, index));
            item.addEventListener('dragstart', (e) => this.handleDragStart(e, pane, index));
        });

        this.updatePaneStatus(pane);
    }

    handleItemClick(e, pane, index) {
        e.stopPropagation();
        this.setActivePane(pane);

        if (index === -1) return;

        const state = this.panes[pane];

        const checkboxClicked = Boolean(e.target?.closest?.('.fm-file-checkbox'));
        if (checkboxClicked || e.ctrlKey || e.metaKey) {
            if (state.selected.has(index)) {
                state.selected.delete(index);
            } else {
                state.selected.add(index);
            }
        } else if (e.shiftKey && state.lastSelected !== -1) {
            const start = Math.min(state.lastSelected, index);
            const end = Math.max(state.lastSelected, index);
            for (let i = start; i <= end; i++) {
                state.selected.add(i);
            }
        } else {
            state.selected.clear();
            state.selected.add(index);
        }

        state.lastSelected = index;
        this.updateSelectionVisual(pane);
    }

    handleItemDoubleClickEvent(e, pane, index) {
        if (e.target?.closest?.('.fm-file-checkbox')) return;
        e.preventDefault();
        e.stopPropagation();
        this.handleItemDblClick(pane, index);
    }

    handleItemDblClick(pane, index) {
        const state = this.panes[pane];
        if (index === -1) {
            this.navigatePaneUp(pane);
            return;
        }

        const file = state.files[index];
        if (!file) {
            return;
        }

        if (file.is_dir) {
            this.navigateIntoDir(pane, file.name);
        } else {
            if (state.type === 'ssh') {
                const sessionId = state.sessionId || state.connectionId;
                const filePath = this.joinPath(state.path, file.name);
                if (window.FilePreview) {
                    window.FilePreview.open(sessionId, filePath, file.name);
                } else {
                    console.error('[SFTP] FilePreview not available');
                }
            }
        }
    }

    updateSelectionVisual(pane) {
        const state = this.panes[pane];
        const container = document.getElementById(`fm${this.capitalize(pane)}List`);

        container.querySelectorAll('.fm-file-item').forEach(item => {
            const idx = parseInt(item.dataset.index);
            if (idx >= 0) {
                const isSelected = state.selected.has(idx);
                item.classList.toggle('selected', isSelected);
                const checkbox = item.querySelector('.fm-file-checkbox.material-icons');
                if (checkbox) {
                    checkbox.textContent = isSelected ? 'check_box' : 'check_box_outline_blank';
                    checkbox.setAttribute('aria-checked', String(isSelected));
                }
            }
        });

        this.updatePaneStatus(pane);
    }

    setActivePane(pane) {
        if (this.displayMode === 'embedded') pane = 'left';

        this.activePane = pane;
        if (this.displayMode === 'modal' && this.workspace) this.workspace.setActivePane(pane);
        document.getElementById('fmLeftPane')?.classList.toggle('active', pane === 'left');
        document.getElementById('fmRightPane')?.classList.toggle('active', pane === 'right');
        this.updateMobilePaneTabs(pane);
        if (this.displayMode === 'modal') this.renderWorkspaceChrome();
    }

    isMobile() {
        return window.innerWidth < 768;
    }

    updateMobilePaneTabs(pane) {
        document.querySelectorAll('.fm-pane-tab').forEach(tab => {
            const active = tab.dataset.pane === pane;
            tab.classList.toggle('active', active);
            tab.setAttribute('aria-selected', String(active));
        });
    }

    setupLongPress() {
        let longPressTimer = null;
        const longPressDuration = 500;

        ['left', 'right'].forEach(pane => {
            const listEl = document.getElementById(`fm${this.capitalize(pane)}List`);

            listEl.addEventListener('touchstart', (e) => {
                const item = e.target.closest('.fm-file-item');
                if (!item) return;

                longPressTimer = setTimeout(() => {
                    e.preventDefault();
                    const index = parseInt(item.dataset.index);
                    this.setActivePane(pane);
                    this.panes[pane].selected.clear();
                    this.panes[pane].selected.add(index);
                    this.updateSelectionVisual(pane);
                    this.showActionSheet();
                }, longPressDuration);
            }, { passive: false });

            listEl.addEventListener('touchend', () => {
                if (longPressTimer) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                }
            });

            listEl.addEventListener('touchmove', () => {
                if (longPressTimer) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                }
            });
        });
    }

    showActionSheet() {
        const sheet = document.getElementById('fmActionSheet');
        if (sheet) {
            sheet.classList.add('visible');
        }
    }

    hideActionSheet() {
        const sheet = document.getElementById('fmActionSheet');
        if (sheet) {
            sheet.classList.remove('visible');
        }
    }

    handleActionSheetAction(action) {
        this.hideActionSheet();

        switch (action) {
            case 'open':
                const state = this.panes[this.activePane];
                if (state.selected.size === 1) {
                    const index = Array.from(state.selected)[0];
                    this.handleItemDblClick(this.activePane, index);
                }
                break;
            case 'download':
                this.downloadSelected();
                break;
            case 'transfer':
                this.executeTransfer();
                break;
            case 'rename':
                this.renameSelected();
                break;
            case 'newfolder':
                this.createNewFolder();
                break;
            case 'delete':
                this.deleteSelected();
                break;
            case 'cancel':
                break;
        }
    }

    handleMobileUpload(e) {
        const files = e.target.files;
        if (!files || files.length === 0) return;

        const state = this.panes[this.activePane];
        if (!state.type) {
            this.showNotification(this.t('fm.selectConnectionFirst', 'Please select a connection first'), 'warning');
            return;
        }

        if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            if (!sessionId) {
                this.showNotification(this.t('fm.noActiveConnection', 'No active connection'), 'error');
                return;
            }

            this.showNotification(`${this.t('fm.uploading', 'Uploading')} ${files.length} ${this.t('fm.files', 'file(s)')}...`, 'info');
            const batch = this.startUploadBatch(files.length, sessionId, state);

            Array.from(files).forEach(file => {
                const remotePath = this.joinPath(state.path, file.name);
                const transferId = this.getTransferClient().uploadFile(file, remotePath, sessionId);
                this.queueTransfer({
                    id: transferId,
                    type: 'upload',
                    filename: file.name,
                    targetPath: remotePath,
                    size: file.size,
                    sessionId: sessionId,
                    batchId: batch.id
                });
            });
        } else {
            this.showNotification(this.t('fm.uploadSSHOnly', 'Upload only available for SSH connections'), 'warning');
        }

        e.target.value = '';
    }

    selectAll() {
        this.setPaneSelection(this.activePane, true);
    }

    setPaneSelection(pane, selected) {
        this.setActivePane(pane);
        const state = this.panes[pane];
        if (selected) {
            state.files.forEach((_, index) => state.selected.add(index));
        } else {
            state.selected.clear();
        }
        this.updateSelectionVisual(pane);
    }

    createNewFolder() {
        const state = this.panes[this.activePane];

        if (!state.type) {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
            return;
        }

        const name = prompt(this.t('fm.enterFolderName', 'Enter folder name:'));
        if (!name) return;

        if (name.includes('/') || name.includes('\\')) {
            this.showNotification(this.t('fm.invalidFolderName', 'Invalid folder name'), 'error');
            return;
        }

        if (state.type === 'ssh') {
            const path = state.path === '/' ? '/' + name : state.path + '/' + name;
            const sessionId = state.sessionId || state.connectionId;
            this.socket.emit('create_directory', { session_id: sessionId, remote_path: path });
        }
    }

    deleteSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsSelected', 'No items selected'), 'warning');
            return;
        }

        const items = Array.from(state.selected).map(i => state.files[i]).filter(f => f);
        const names = items.map(f => f.name).join(', ');

        if (!confirm(`${this.t('fm.confirmDelete', 'Delete')} ${items.length} ${this.t('fm.items', 'item(s)')}?\n\n${names}\n\n${this.t('fm.cannotBeUndone', 'This cannot be undone!')}`)) {
            return;
        }

        if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            items.forEach(item => {
                const path = state.path === '/' ? '/' + item.name : state.path + '/' + item.name;
                this.socket.emit('delete_item', { session_id: sessionId, path: path });
            });
            state.selected.clear();
        }
    }

    renameSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size !== 1) {
            this.showNotification(this.t('fm.selectOneToRename', 'Select exactly one item to rename'), 'warning');
            return;
        }

        const index = Array.from(state.selected)[0];
        const file = state.files[index];
        if (!file) return;

        const newName = prompt(this.t('fm.enterNewName', 'Enter new name:'), file.name);
        if (!newName || newName === file.name) return;

        if (newName.includes('/') || newName.includes('\\')) {
            this.showNotification(this.t('fm.invalidName', 'Invalid name'), 'error');
            return;
        }

        if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            const oldPath = state.path === '/' ? '/' + file.name : state.path + '/' + file.name;
            const newPath = state.path === '/' ? '/' + newName : state.path + '/' + newName;
            this.socket.emit('rename_file', { session_id: sessionId, old_path: oldPath, new_path: newPath });
        }
    }

    async executeTransfer() {
        if (this.transferExecutionInProgress) return;
        const sourcePane = this.activePane;
        const targetPane = sourcePane === 'left' ? 'right' : 'left';

        const source = this.panes[sourcePane];
        const target = this.panes[targetPane];

        if (!this.canTransferBetweenPanes(sourcePane, targetPane)) {
            const sourceId = source?.sessionId || source?.connectionId;
            const targetId = target?.sessionId || target?.connectionId;
            const message = sourceId && sourceId === targetId
                ? this.t('fm.cannotTransferSameHost', 'Cannot transfer to same host. Use rename instead.')
                : this.t('fm.bothPanesRequired', 'Both panes must have a source selected');
            this.showNotification(message, 'warning');
            return;
        }

        if (!source.type || !target.type) {
            this.showNotification(this.t('fm.bothPanesRequired', 'Both panes must have a source selected'), 'warning');
            return;
        }

        if (source.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsForTransfer', 'No items selected for transfer'), 'warning');
            return;
        }

        const selectedItems = Array.from(source.selected)
            .map(i => source.files[i])
            .filter(f => f);

        if (selectedItems.length === 0) {
            this.showNotification(this.t('fm.noValidItems', 'No valid items selected'), 'warning');
            return;
        }

        const transferType = `${source.type}-to-${target.type}`;
        this.showNotification(`${this.t('fm.startingTransfer', 'Starting transfer of')} ${selectedItems.length} ${this.t('fm.items', 'item(s)')}...`, 'info');
        this.transferExecutionInProgress = true;

        try {
            for (const item of selectedItems) {
                const sourcePath = source.path === '/' ? '/' + item.name : source.path + '/' + item.name;
                const targetPath = target.path === '/' ? '/' + item.name : target.path + '/' + item.name;

                switch (transferType) {
                    case 'ssh-to-ssh':
                        await this.transferSSHtoSSH(sourcePath, source, targetPath, target, item);
                        break;

                    default:
                        this.showNotification(`${this.t('fm.transferNotSupported', 'Transfer type not supported')}: ${transferType}`, 'error');
                }
            }
        } finally {
            this.transferExecutionInProgress = false;
        }
    }

    async transferSSHtoSSH(sourcePath, sourcePane, targetPath, targetPane, item) {
        const sourceSessionId = sourcePane.sessionId || sourcePane.connectionId;
        const targetSessionId = targetPane.sessionId || targetPane.connectionId;
        const connectionIds = [sourceSessionId, targetSessionId];

        if (sourceSessionId === targetSessionId) {
            this.showNotification(this.t('fm.cannotTransferSameHost', 'Cannot transfer to same host. Use rename instead.'), 'warning');
            return;
        }

        this.retainTransferConnections(connectionIds);

        const acknowledgement = await new Promise(resolve => {
            this.socket.emit('transfer_server_to_server', {
                source_session_id: sourceSessionId,
                source_path: sourcePath,
                dest_session_id: targetSessionId,
                dest_path: targetPath,
                is_dir: item.is_dir
            }, response => resolve(response));
        });
        if (!acknowledgement || !acknowledgement.success) {
            this.releaseTransferConnections(connectionIds);
            this.flushPendingQuickDisconnects();
            this.showNotification(this.t('fm.transferFailed', 'Transfer failed'), 'error');
            return;
        }
        const transferId = acknowledgement.transfer_id;
        const terminal = this.waitForS2STerminal(transferId);

        this.queueTransfer({
            id: transferId,
            type: 's2s',
            filename: item.name,
            sourcePath: sourcePath,
            targetPath: targetPath,
            size: item.size || 0,
            connectionIds: connectionIds,
            connectionsRetained: true
        });
        const earlyTerminal = this.s2sEarlyTerminals?.get(transferId);
        if (earlyTerminal) {
            this.s2sEarlyTerminals.delete(transferId);
            this.finalizeTransferById(
                transferId,
                earlyTerminal.status,
                earlyTerminal.error
            );
        }
        await terminal;
    }

    handleDrop(e, targetPane) {
        const files = e.dataTransfer.files;
        const items = e.dataTransfer.items;
        const target = this.panes[targetPane];

        if (this.dragSource && this.dragSource !== targetPane && this.draggedItems.length > 0) {
            this.activePane = this.dragSource;
            this.executeTransfer();
            this.draggedItems = [];
            this.dragSource = null;
            return;
        }

        if (target.type === 'ssh') {
            const sessionId = target.sessionId || target.connectionId;
            if (!sessionId) {
                this.showNotification(this.t('fm.noActiveSession', 'No active SSH session'), 'error');
                return;
            }

            if (items && items.length > 0) {
                const entries = Array.from(items)
                    .filter(item => item.kind === 'file')
                    .map(item => item.webkitGetAsEntry())
                    .filter(entry => entry !== null);

                if (entries.length > 0) {
                    this.uploadDesktopItemsToSSH(entries, target);
                } else if (files && files.length > 0) {
                    this.uploadDesktopFilesToSSH(Array.from(files), target);
                }
            } else if (files && files.length > 0) {
                this.uploadDesktopFilesToSSH(Array.from(files), target);
            }
        } else {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
        }

        this.draggedItems = [];
        this.dragSource = null;
    }

    async uploadDesktopItemsToSSH(entries, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;
        const basePath = targetPane.path;

        const countFiles = async (entry) => {
            if (entry.isFile) {
                return 1;
            } else if (entry.isDirectory) {
                const subEntries = await this.readAllDirectoryEntries(entry);
                let count = 0;
                for (const subEntry of subEntries) {
                    count += await countFiles(subEntry);
                }
                return count;
            }
            return 0;
        };

        let totalFiles = 0;
        for (const entry of entries) {
            totalFiles += await countFiles(entry);
        }

        const batch = this.startUploadBatch(totalFiles, sessionId, targetPane);

        for (const entry of entries) {
            if (entry.isFile) {
                entry.file(file => {
                    this.uploadSingleFileToSSH(file, basePath, sessionId, batch.id);
                });
            } else if (entry.isDirectory) {
                await this.uploadDirectoryToSSH(entry, basePath, sessionId, batch.id);
            }
        }
    }

    uploadSingleFileToSSH(file, basePath, sessionId, batchId = null) {
        const remotePath = this.joinPath(basePath, file.name);
        const transferId = this.getTransferClient().uploadFile(file, remotePath, sessionId);
        this.queueTransfer({
            id: transferId,
            type: 'upload', filename: file.name, targetPath: remotePath,
            size: file.size,
            sessionId: sessionId,
            batchId: batchId
        });
    }

    async readAllDirectoryEntries(directoryEntry) {
        const reader = directoryEntry.createReader();
        const entries = [];
        while (true) {
            const page = await new Promise((resolve, reject) => {
                reader.readEntries(resolve, reject);
            });
            if (!page || page.length === 0) return entries;
            entries.push(...page);
        }
    }

    async uploadDirectoryToSSH(directoryEntry, basePath, sessionId, batchId = null) {
        const dirPath = this.joinPath(basePath, directoryEntry.name);

        this.socket.emit('create_directory', {
            session_id: sessionId,
            remote_path: dirPath
        });

        const entries = await this.readAllDirectoryEntries(directoryEntry);

        const promises = [];
        for (const entry of entries) {
            if (entry.isFile) {
                entry.file(file => {
                    this.uploadSingleFileToSSH(file, dirPath, sessionId, batchId);
                });
            } else if (entry.isDirectory) {
                promises.push(this.uploadDirectoryToSSH(entry, dirPath, sessionId, batchId));
            }
        }

        await Promise.all(promises);
    }

    async uploadDesktopFilesToSSH(files, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;
        const batch = this.startUploadBatch(files.length, sessionId, targetPane);

        for (const file of files) {
            this.uploadSingleFileToSSH(file, targetPane.path, sessionId, batch.id);
        }
    }

    startUploadBatch(total, sessionId, destinationState = null) {
        if (!Number.isInteger(total) || total <= 0) {
            return {
                id: null, total: 0, completed: 0, sessionId: sessionId, destinationState,
            };
        }
        if (!this.uploadBatches) this.uploadBatches = new Map();
        const batch = {
            id: `batch_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
            total: total,
            completed: 0,
            succeeded: 0,
            failed: 0,
            cancelled: 0,
            sessionId: sessionId,
            destinationState,
        };
        this.uploadBatches.set(batch.id, batch);
        this.currentUploadBatch = batch;
        window._currentUploadBatchId = batch.id;
        this.showUploadProgress(batch);
        return batch;
    }

    recordUploadTerminal(transfer, status) {
        if (transfer.type !== 'upload' || transfer.uploadTerminalRecorded) return;
        transfer.uploadTerminalRecorded = true;

        const batch = transfer.batchId && this.uploadBatches
            ? this.uploadBatches.get(transfer.batchId)
            : null;
        if (!batch) {
            this.scheduleUploadRefresh(transfer.sessionId);
            return;
        }

        batch.completed++;
        if (status === 'complete') batch.succeeded++;
        else if (status === 'cancelled') batch.cancelled++;
        else batch.failed++;

        if (this.currentUploadBatch?.id === batch.id) {
            this.showUploadProgress(batch);
        }
        if (batch.completed < batch.total) return;

        this.uploadBatches.delete(batch.id);
        if (this.currentUploadBatch?.id === batch.id) {
            this.showUploadComplete(batch);
            this.currentUploadBatch = null;
            window._currentUploadBatchId = null;
        }
        this.scheduleUploadRefresh(batch.sessionId, batch.destinationState);
    }

    scheduleUploadRefresh(sessionId, destinationState = null) {
        if (!sessionId) return;
        const entry = this.findPaneStateEntry(sessionId, destinationState);
        if (!entry) return;
        if (!this.uploadRefreshes) this.uploadRefreshes = new Map();
        const key = entry.state;
        if (this.uploadRefreshes.has(key)) return;

        const scheduled = Promise.resolve().then(() => {
            this.uploadRefreshes.delete(key);
            const currentEntry = this.findPaneStateEntry(sessionId, entry.state);
            if (!currentEntry) return;
            if (currentEntry.visible) return this.refreshPane(currentEntry.pane);
            currentEntry.state.autoHomeEligible = false;
            return this.requestDirectoryForState(
                currentEntry.pane,
                currentEntry.state,
                currentEntry.state.path,
            );
        }).catch(() => {
            console.error('[FM] Failed to refresh upload destination');
        });
        this.uploadRefreshes.set(key, scheduled);
    }

    findPaneStateEntry(sessionId, destinationState = null) {
        return this.getPaneStateEntries().find(({ state }) => (
            (!destinationState || state === destinationState)
            && (state.sessionId === sessionId || state.connectionId === sessionId)
        )) || null;
    }

    getPaneForSession(sessionId) {
        if (!this.panes) return null;
        if (this.panes.left.sessionId === sessionId || this.panes.left.connectionId === sessionId) {
            return 'left';
        }
        if (this.panes.right.sessionId === sessionId || this.panes.right.connectionId === sessionId) {
            return 'right';
        }
        return null;
    }

    handleDragStart(e, pane, index) {
        this.dragSource = pane;
        const state = this.panes[pane];

        if (!state.selected.has(index)) {
            state.selected.clear();
            state.selected.add(index);
            this.updateSelectionVisual(pane);
        }

        this.draggedItems = Array.from(state.selected).map(i => state.files[i]).filter(f => f);
        e.dataTransfer.effectAllowed = 'copy';
        e.dataTransfer.setData('text/plain', this.draggedItems.map(f => f.name).join(', '));
    }

    queueTransfer(transfer) {
        if (!transfer.id) {
            transfer.id = Date.now() + Math.random();
        }
        if (transfer.type === 'upload') {
            if (!Object.hasOwn(transfer, 'sessionId')) transfer.sessionId = null;
            if (!Object.hasOwn(transfer, 'batchId')) transfer.batchId = null;
        }
        const connectionsRetained = transfer.connectionsRetained === true;
        delete transfer.connectionsRetained;
        transfer.connectionIds = this.getTransferConnectionIds(transfer);
        if (!connectionsRetained) this.retainTransferConnections(transfer.connectionIds);
        transfer.status = 'pending';
        transfer.progress = 0;
        this.transferQueue.push(transfer);
        this.renderTransferQueue();
        this.processTransferQueue();
    }

    async processTransferQueue() {
        if (this.isTransferring) return;

        const pending = this.transferQueue.find(t => t.status === 'pending');
        if (!pending) return;

        this.isTransferring = true;
        pending.status = 'active';
        this.renderTransferQueue();

        if (pending.type === 's2s') {
            this.activeTransfers.set(pending.id, pending);
            return;
        }

        this.activeTransfers.set(pending.id, pending);
    }

    updateTransferProgress(data) {
        const transfer = this.transferQueue.find(t =>
            t.status === 'active' &&
            (t.filename === data.filename || t.id === data.transfer_id)
        );

        if (transfer) {
            transfer.progress = Math.min(100, Math.max(0, Number(data.percent) || 0));
            this.renderTransferQueue();
        }
    }

    updateTransferById(data) {
        const transfer = this.transferQueue.find(t => t.id === data.transferId);
        if (!transfer) return;
        transfer.transferred = data.transferred || 0;
        transfer.total = data.total || transfer.size || 0;
        transfer.progress = Math.min(100, Math.max(0, Number(data.percent) || 0));
        this.renderTransferQueue();
    }

    completeS2STransfer(data) {
        this.finalizeOrBufferS2STerminal(data.transfer_id, 'complete');
    }

    failS2STransfer(data) {
        this.finalizeOrBufferS2STerminal(data.transfer_id, 'error', data.error);
    }

    finalizeOrBufferS2STerminal(transferId, status, error = null) {
        const transfer = this.transferQueue?.find(item => item.id === transferId);
        if (transfer) {
            this.finalizeTransferById(transferId, status, error);
            return;
        }
        if (!this.s2sEarlyTerminals) this.s2sEarlyTerminals = new Map();
        this.s2sEarlyTerminals.set(transferId, { status: status, error: error });
    }

    waitForS2STerminal(transferId) {
        const transfer = this.transferQueue?.find(item => item.id === transferId);
        if (transfer && ['complete', 'error', 'cancelled'].includes(transfer.status)) {
            return Promise.resolve(transfer.status);
        }
        if (!this.s2sTerminalWaiters) this.s2sTerminalWaiters = new Map();
        return new Promise(resolve => {
            this.s2sTerminalWaiters.set(transferId, resolve);
        });
    }

    resolveS2STerminal(transferId, status) {
        const resolve = this.s2sTerminalWaiters?.get(transferId);
        if (!resolve) return;
        this.s2sTerminalWaiters.delete(transferId);
        resolve(status);
    }

    completeTransferById(transferId) {
        this.finalizeTransferById(transferId, 'complete');
    }

    failTransferById(transferId, error) {
        const displayError = error === 'Transfer unavailable'
            ? this.t('fm.transferUnavailable', 'Transfer unavailable')
            : error;
        this.finalizeTransferById(transferId, 'error', displayError);
    }

    cancelTransferById(transferId) {
        this.finalizeTransferById(transferId, 'cancelled');
    }

    cancelQueuedTransfer(transferId) {
        const transfer = this.transferQueue.find(t => String(t.id) === transferId);
        if (!transfer || !['pending', 'active'].includes(transfer.status)) return;
        if (transfer.type === 's2s') {
            this.socket.emit('cancel_transfer', {
                transfer_id: transfer.id
            }, acknowledgement => {
                if (acknowledgement?.success) {
                    this.cancelTransferById(transfer.id);
                }
            });
            return;
        }
        this.getTransferClient().cancelTransfer(transfer.id);
    }

    finalizeTransferById(transferId, status, error = null) {
        const transfer = this.transferQueue.find(t => t.id === transferId);
        if (!transfer) return;
        if (['complete', 'error', 'cancelled'].includes(transfer.status)) return;

        const wasActive = transfer.status === 'active';
        transfer.status = status;
        if (status === 'complete') {
            transfer.progress = 100;
        } else if (error) {
            transfer.error = error;
        }
        this.activeTransfers.delete(transfer.id);
        this.recordUploadTerminal(transfer, status);
        this.releaseTransferConnections(this.getTransferConnectionIds(transfer));
        if (transfer.type === 's2s') {
            this.resolveS2STerminal(transfer.id, status);
        }
        if (wasActive) {
            this.isTransferring = false;
            setTimeout(() => this.processTransferQueue(), 100);
        }
        this.renderTransferQueue();
        this.flushPendingQuickDisconnects();
    }

    downloadSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsSelected', 'No items selected'), 'warning');
            return;
        }

        if (state.type !== 'ssh') {
            this.showNotification(this.t('fm.downloadOnlySSH', 'Download only works for SSH sources'), 'warning');
            return;
        }

        const sessionId = state.sessionId || state.connectionId;
        const items = Array.from(state.selected).map(i => state.files[i]).filter(f => f);

        this.showNotification(`${this.t('fm.downloading', 'Downloading')} ${items.length} ${this.t('fm.items', 'item(s)')}...`, 'info');

        for (const item of items) {
            const filePath = this.joinPath(state.path, item.name);
            if (item.is_dir) {
                this.downloadFolderToBrowser(sessionId, filePath, item.name);
            } else {
                this.downloadFileToBrowser(sessionId, filePath, item.name);
            }
        }
    }

    downloadFileToBrowser(sessionId, remotePath, filename) {
        this.showNotification(`${this.t('fm.downloading', 'Downloading')}: ${filename}...`, 'info');

        const transferId = this.getTransferClient().downloadFile(remotePath, sessionId);
        this.queueTransfer({
            id: transferId,
            type: 'download',
            filename: filename,
            sourcePath: remotePath,
            size: 0,
            sessionId: sessionId
        });

    }

    downloadFolderToBrowser(sessionId, remotePath, folderName) {
        this.showNotification(`${this.t('fm.downloadingFolder', 'Downloading folder')}: ${folderName}...`, 'info');

        const transferId = this.getTransferClient().downloadFolder(remotePath, sessionId);
        this.queueTransfer({
            id: transferId,
            type: 'download',
            filename: `${folderName}.zip`,
            sourcePath: remotePath,
            size: 0,
            sessionId: sessionId
        });
    }

    getTransferClient() {
        if (!this.transferClient) {
            this.transferClient = this.createTransferClient
                ? this.createTransferClient()
                : BinaryTransferClient.forSocket(this.socket);
            this.transferClient.on('progress', data => this.updateTransferById(data));
            this.transferClient.on('complete', data => this.completeTransferById(data.transferId));
            this.transferClient.on('error', data => this.failTransferById(data.transferId, data.error));
            this.transferClient.on('cancel', data => this.cancelTransferById(data.transferId));
        }
        return this.transferClient;
    }

    renderTransferQueue() {
        const container = document.getElementById('fmQueueList');
        const badge = document.getElementById('fmQueueBadge');

        const activeCount = this.transferQueue.filter(t =>
            t.status === 'pending' || t.status === 'active'
        ).length;

        badge.textContent = activeCount;
        badge.style.display = activeCount > 0 ? 'inline' : 'none';

        if (this.transferQueue.length === 0) {
            container.innerHTML = `<div class="fm-empty" style="padding: 20px;">${this.t('fm.noTransfers', 'No transfers')}</div>`;
            return;
        }

        container.innerHTML = this.transferQueue.slice(-20).map(t => `
            <div class="fm-transfer-item ${t.status}">
                <div class="fm-transfer-icon ${t.type}">
                    ${t.type === 'upload' ? '⬆️' : t.type === 'download' ? '⬇️' : '↔️'}
                </div>
                <div class="fm-transfer-info">
                    <div class="fm-transfer-name">${this.escapeHtml(t.filename)}</div>
                    ${t.status === 'active' ? `
                        <div class="fm-transfer-progress-bar">
                            <div class="fm-transfer-progress-fill" style="width: ${t.progress}%"></div>
                        </div>
                    ` : ''}
                </div>
                <div class="fm-transfer-status ${t.status}">${this.getStatusText(t)}</div>
                ${t.status === 'pending' || t.status === 'active' ? `
                    <div class="fm-transfer-actions">
                        <button type="button" class="fm-transfer-btn cancel material-icons"
                                data-transfer-cancel="${this.escapeHtml(String(t.id))}"
                                title="${this.t('common.cancel', 'Cancel')}">close</button>
                    </div>
                ` : ''}
            </div>
        `).join('');
    }

    getStatusText(transfer) {
        switch (transfer.status) {
            case 'pending': return this.t('fm.waiting', 'Waiting...');
            case 'active': return `${transfer.progress}%`;
            case 'complete': return `✓ ${this.t('fm.done', 'Done')}`;
            case 'error': return `✗ ${this.t('fm.failed', 'Failed')}`;
            default: return '';
        }
    }

    toggleQueue() {
        const collapsed = document.getElementById('fmQueue').classList.toggle('collapsed');
        const toggle = document.getElementById('fmQueueToggle');
        toggle.textContent = collapsed ? 'expand_more' : 'expand_less';
        document.getElementById('fmQueueHeader').setAttribute('aria-expanded', String(!collapsed));
    }

    showContextMenu(e, pane, index) {
        e.preventDefault();
        e.stopPropagation();
        this.closeContextMenu();

        const state = this.panes[pane];
        const file = index >= 0 ? state.files[index] : null;

        const menu = document.createElement('div');
        menu.className = 'fm-context-menu';

        const items = this.getContextMenuItems(file, state, pane);

        menu.innerHTML = items.map(item => {
            if (item.divider) {
                return '<div class="fm-context-divider"></div>';
            }
            return `
                <div class="fm-context-item ${item.danger ? 'danger' : ''}" data-action="${item.action}">
                    <span class="fm-context-icon">${item.icon}</span> ${item.text}
                </div>
            `;
        }).join('');

        document.body.appendChild(menu);
        this.contextMenu = menu;

        menu.style.left = `${Math.min(e.clientX, window.innerWidth - 200)}px`;
        menu.style.top = `${Math.min(e.clientY, window.innerHeight - 200)}px`;

        menu.querySelectorAll('.fm-context-item').forEach(item => {
            item.addEventListener('click', (ev) => {
                ev.stopPropagation();
                this.handleContextAction(item.dataset.action, pane, index);
                this.closeContextMenu();
            });
        });
    }

    getContextMenuItems(file, state, pane = this.activePane) {
        const items = [];

        if (file) {
            if (file.is_dir) {
                items.push({ action: 'open', icon: '📂', text: this.t('fm.ctx.open', 'Open') });
                if (state.type === 'ssh' || state.type === 'quick-connect') {
                    items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
                }
            } else if (state.type === 'ssh' || state.type === 'quick-connect') {
                items.push({ action: 'preview', icon: '👁️', text: this.t('fm.ctx.preview', 'Preview') });
                items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
            }
            const otherPane = pane === 'left' ? 'right' : 'left';
            const canTransfer = this.displayMode === 'modal'
                && !this.isMobile()
                && this.canTransferBetweenPanes(pane, otherPane);
            if (canTransfer) {
                items.push({ action: 'transfer', icon: '↔️', text: this.t('fm.ctx.transferToOther', 'Transfer to other pane') });
            }
            items.push({ divider: true });
            items.push({ action: 'rename', icon: '✏️', text: this.t('fm.rename', 'Rename') });
        }

        items.push({ action: 'newfolder', icon: '📁', text: this.t('fm.newFolder', 'New Folder') });
        items.push({ action: 'refresh', icon: '↻', text: this.t('fm.refresh', 'Refresh') });

        if (file) {
            items.push({ divider: true });
            items.push({ action: 'delete', icon: '🗑️', text: this.t('fm.delete', 'Delete'), danger: true });
        }
        return items;
    }

    handleContextAction(action, pane, index) {
        const state = this.panes[pane];
        this.activePane = pane;

        const ensureSelection = () => {
            if (index >= 0 && !state.selected.has(index)) {
                state.selected.clear();
                state.selected.add(index);
                this.updateSelectionVisual(pane);
            }
        };

        switch (action) {
            case 'open':
                this.handleItemDblClick(pane, index);
                break;
            case 'preview':
                if (index >= 0) {
                    const file = state.files[index];
                    if (file && !file.is_dir) {
                        const sessionId = state.sessionId || state.connectionId;
                        const filePath = this.joinPath(state.path, file.name);
                        if (window.FilePreview) {
                            window.FilePreview.open(sessionId, filePath, file.name);
                        }
                    }
                }
                break;
            case 'download':
                ensureSelection();
                this.downloadSelected();
                break;
            case 'transfer':
                ensureSelection();
                this.executeTransfer();
                break;
            case 'rename':
                if (index >= 0) {
                    state.selected.clear();
                    state.selected.add(index);
                    this.renameSelected();
                }
                break;
            case 'newfolder':
                this.createNewFolder();
                break;
            case 'refresh':
                this.refreshPane(pane);
                break;
            case 'delete':
                ensureSelection();
                this.deleteSelected();
                break;
        }
    }

    closeContextMenu() {
        if (this.contextMenu) {
            this.contextMenu.remove();
            this.contextMenu = null;
        }
    }

    updatePaneStatus(pane) {
        const state = this.panes[pane];
        const count = state.files.length;
        const selected = state.selected.size;
        const totalSize = Array.from(state.selected)
            .reduce((sum, i) => sum + (state.files[i]?.size || 0), 0);

        document.getElementById(`fm${this.capitalize(pane)}Count`).textContent =
            `${count} ${this.t('fm.items', 'items')}`;

        document.getElementById(`fm${this.capitalize(pane)}Selected`).textContent = selected > 0
            ? `${selected} ${this.t('fm.selected', 'selected')} (${this.formatSize(totalSize)})`
            : '';
        this.updateWorkspaceActions();
    }

    t(key, fallback = '') {
        if (window.i18n && typeof window.i18n.t === 'function') {
            return window.i18n.t(key) || fallback;
        }
        return fallback;
    }

    applyTranslations() {
        if (!window.i18n || typeof window.i18n.t !== 'function') return;

        this.modal.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = window.i18n.t(key);
            if (translation) el.textContent = translation;
        });

        this.modal.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.getAttribute('data-i18n-title');
            const translation = window.i18n.t(key);
            if (translation) el.title = translation;
        });

        this.modal.querySelectorAll('[data-i18n-label]').forEach(el => {
            const key = el.getAttribute('data-i18n-label');
            const translation = window.i18n.t(key);
            if (translation) el.label = translation;
        });
        this.modal.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
            const key = el.getAttribute('data-i18n-aria-label');
            const translation = window.i18n.t(key);
            if (translation) el.setAttribute('aria-label', translation);
        });
        this.modal.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            const translation = window.i18n.t(key);
            if (translation) el.setAttribute('placeholder', translation);
        });

        if (this.qcModal) {
            this.qcModal.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                const translation = window.i18n.t(key);
                if (translation) el.textContent = translation;
            });

            this.qcModal.querySelectorAll('[data-i18n-title]').forEach(el => {
                const key = el.getAttribute('data-i18n-title');
                const translation = window.i18n.t(key);
                if (translation) el.title = translation;
            });
            this.qcModal.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
                const key = el.getAttribute('data-i18n-aria-label');
                const translation = window.i18n.t(key);
                if (translation) el.setAttribute('aria-label', translation);
            });
        }
    }

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatModified(value) {
        if (!value) return '-';
        const timestamp = Number(value);
        const date = new Date(timestamp < 1e12 ? timestamp * 1000 : timestamp);
        if (Number.isNaN(date.getTime())) return '-';
        const locale = typeof navigator !== 'undefined' ? navigator.language : undefined;
        return new Intl.DateTimeFormat(locale, {
            year: 'numeric', month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit',
        }).format(date);
    }

    formatPermissions(file = {}) {
        if (file.permissions) return String(file.permissions);
        const mode = Number(file.mode);
        if (!Number.isFinite(mode)) return '-';
        const type = file.is_dir ? 'd' : file.is_symlink ? 'l' : '-';
        const masks = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
        const symbols = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'];
        return type + masks.map((mask, index) => (mode & mask) ? symbols[index] : '-').join('');
    }

    joinPath(basePath, filename) {
        if (!basePath || basePath === '/') {
            return '/' + filename;
        }
        const cleanBase = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
        return cleanBase + '/' + filename;
    }

    getFileIcon(filename) {
        const ext = filename.split('.').pop()?.toLowerCase();
        const iconMap = {
            'pdf': 'picture_as_pdf',
            'doc': 'description', 'docx': 'description',
            'xls': 'table_chart', 'xlsx': 'table_chart', 'csv': 'table_chart',
            'ppt': 'slideshow', 'pptx': 'slideshow',
            'txt': 'article', 'md': 'article', 'rtf': 'article',
            'js': 'javascript', 'ts': 'javascript', 'jsx': 'javascript', 'tsx': 'javascript',
            'py': 'code', 'rb': 'code', 'go': 'code', 'rs': 'code', 'c': 'code', 'cpp': 'code', 'h': 'code',
            'java': 'code', 'php': 'code', 'swift': 'code', 'kt': 'code',
            'html': 'html', 'htm': 'html',
            'css': 'css', 'scss': 'css', 'sass': 'css', 'less': 'css',
            'json': 'data_object', 'xml': 'data_object', 'yaml': 'data_object', 'yml': 'data_object',
            'sql': 'storage',
            'sh': 'terminal', 'bash': 'terminal', 'zsh': 'terminal',
            'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image',
            'svg': 'image', 'webp': 'image', 'ico': 'image', 'bmp': 'image',
            'mp3': 'audio_file', 'wav': 'audio_file', 'ogg': 'audio_file', 'flac': 'audio_file',
            'mp4': 'video_file', 'mkv': 'video_file', 'avi': 'video_file', 'mov': 'video_file', 'webm': 'video_file',
            'zip': 'folder_zip', 'tar': 'folder_zip', 'gz': 'folder_zip', 'rar': 'folder_zip', '7z': 'folder_zip',
            'env': 'settings', 'ini': 'settings', 'conf': 'settings', 'config': 'settings',
            'lock': 'lock',
            'log': 'receipt_long',
            'key': 'key', 'pem': 'key', 'pub': 'key',
        };
        return iconMap[ext] || 'insert_drive_file';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showUploadProgress(batch = this.currentUploadBatch) {
        if (!batch) return;

        const { completed, total } = batch;
        const percent = Math.round((completed / total) * 100);

        if (!this.uploadProgressNotification) {
            this.uploadProgressNotification = document.createElement('div');
            this.uploadProgressNotification.className = 'upload-progress-notification';
            this.uploadProgressNotification.innerHTML = `
                <div class="upload-progress-content">
                    <div class="upload-progress-icon">
                        <span class="material-icons spinning">cloud_upload</span>
                    </div>
                    <div class="upload-progress-info">
                        <div class="upload-progress-text">${this.t('fm.uploadingFiles', 'Uploading files')}...</div>
                        <div class="upload-progress-stats">
                            <span class="upload-progress-count">${completed} / ${total}</span>
                            <span class="upload-progress-percent">${percent}%</span>
                        </div>
                        <div class="upload-progress-bar">
                            <div class="upload-progress-fill" style="width: ${percent}%"></div>
                        </div>
                    </div>
                </div>
            `;

            if (!document.getElementById('upload-progress-styles')) {
                const style = document.createElement('style');
                style.id = 'upload-progress-styles';
                style.textContent = `
                    .upload-progress-notification {
                        position: fixed;
                        top: 80px;
                        right: 20px;
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 8px;
                        padding: 16px;
                        min-width: 300px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                        z-index: 10000;
                        animation: slideInRight 0.3s ease;
                    }
                    .upload-progress-notification.success {
                        background: var(--success-bg, #1e4d2b);
                        border-color: var(--success-color, #4ade80);
                    }
                    .upload-progress-content {
                        display: flex;
                        gap: 12px;
                        align-items: flex-start;
                    }
                    .upload-progress-icon {
                        font-size: 32px;
                        color: var(--accent-primary);
                    }
                    .upload-progress-icon.success {
                        color: var(--success-color, #4ade80);
                    }
                    .upload-progress-icon .spinning {
                        animation: spin 1s linear infinite;
                    }
                    .upload-progress-info {
                        flex: 1;
                    }
                    .upload-progress-text {
                        font-weight: 500;
                        margin-bottom: 8px;
                    }
                    .upload-progress-stats {
                        display: flex;
                        justify-content: space-between;
                        font-size: 12px;
                        color: var(--text-secondary);
                        margin-bottom: 8px;
                    }
                    .upload-progress-bar {
                        height: 6px;
                        background: var(--bg-primary);
                        border-radius: 3px;
                        overflow: hidden;
                    }
                    .upload-progress-fill {
                        height: 100%;
                        background: var(--accent-primary);
                        transition: width 0.3s ease;
                    }
                    @keyframes slideInRight {
                        from {
                            transform: translateX(400px);
                            opacity: 0;
                        }
                        to {
                            transform: translateX(0);
                            opacity: 1;
                        }
                    }
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                    @keyframes slideOutRight {
                        from {
                            transform: translateX(0);
                            opacity: 1;
                        }
                        to {
                            transform: translateX(400px);
                            opacity: 0;
                        }
                    }
                `;
                document.head.appendChild(style);
            }

            document.body.appendChild(this.uploadProgressNotification);
        } else {
            const countEl = this.uploadProgressNotification.querySelector('.upload-progress-count');
            const percentEl = this.uploadProgressNotification.querySelector('.upload-progress-percent');
            const fillEl = this.uploadProgressNotification.querySelector('.upload-progress-fill');

            if (countEl) countEl.textContent = `${completed} / ${total}`;
            if (percentEl) percentEl.textContent = `${percent}%`;
            if (fillEl) fillEl.style.width = `${percent}%`;
        }
    }

    showUploadComplete(batch = this.currentUploadBatch) {
        if (!this.uploadProgressNotification) return;

        this.uploadProgressNotification.classList.add('success');
        this.uploadProgressNotification.innerHTML = `
            <div class="upload-progress-content">
                <div class="upload-progress-icon success">
                    <span class="material-icons">check_circle</span>
                </div>
                <div class="upload-progress-info">
                    <div class="upload-progress-text">${this.t('fm.uploadComplete', 'Upload complete')}!</div>
                    <div class="upload-progress-stats">
                        <span>${batch ? batch.succeeded : 0} / ${batch ? batch.total : 0} ${this.t('fm.filesUploaded', 'files uploaded')}</span>
                    </div>
                </div>
            </div>
        `;

        setTimeout(() => {
            if (this.uploadProgressNotification) {
                this.uploadProgressNotification.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => {
                    if (this.uploadProgressNotification) {
                        this.uploadProgressNotification.remove();
                        this.uploadProgressNotification = null;
                    }
                }, 300);
            }
        }, 3000);
    }

    showNotification(message, type = 'info') {
        if (window.showNotification) {
            window.showNotification(message, type);
        }
    }
}

let sftpFileManager = null;

function getSFTPFileManager() {
    if (!sftpFileManager) {
        sftpFileManager = new SFTPFileManager();
        window.sftpFileManager = sftpFileManager;
    }
    return sftpFileManager;
}

function openFileManager() {
    getSFTPFileManager().open();
}

window.SFTPFileManager = SFTPFileManager;
window.getSFTPFileManager = getSFTPFileManager;
window.openFileManager = openFileManager;
