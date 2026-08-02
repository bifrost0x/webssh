
class SFTPFileManager {
    constructor() {
        this.socket = window.socket;
        this.modal = null;
        this.isOpen = false;

        this.browserFS = new BrowserFileSystem();

        this.panes = {
            left: this.createEmptyPaneState(),
            right: this.createEmptyPaneState()
        };
        this.activePane = 'left';

        this.availableSessions = [];
        this.quickConnections = [];

        this.transferQueue = [];
        this.activeTransfers = new Map();
        this.isTransferring = false;
        this.uploadBatches = new Map();
        this.uploadRefreshes = new Map();
        this.s2sTerminalWaiters = new Map();
        this.s2sEarlyTerminals = new Map();

        this.conflictAction = null;
        this.applyToAll = false;

        this.contextMenu = null;

        this.draggedItems = [];
        this.dragSource = null;

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
            error: null
        };
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
                <div class="modal-header">
                    <h2 id="fmModalTitle"><span class="material-icons">folder_open</span> <span data-i18n="fm.title">File Manager</span></h2>
                    <span class="close" id="fmClose" aria-label="Close" data-i18n-aria-label="common.close">&times;</span>
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
                            <button class="btn btn-secondary btn-sm" id="fmDownload" data-i18n-title="fm.download">
                                <span class="material-icons">download</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmRename" data-i18n-title="fm.rename">
                                <span class="material-icons">edit</span>
                            </button>
                            <button class="btn btn-danger btn-sm" id="fmDelete" data-i18n-title="fm.delete">
                                <span class="material-icons">delete</span>
                            </button>
                        </div>
                    </div>

                    <!-- Mobile Pane Tabs -->
                    <div class="fm-pane-tabs" id="fmPaneTabs">
                        <button class="fm-pane-tab active" data-pane="left">
                            <span class="material-icons">folder</span> Left
                        </button>
                        <button class="fm-pane-tab" data-pane="right">
                            <span class="material-icons">folder</span> Right
                        </button>
                    </div>

                    <!-- Dual Pane -->
                    <div class="fm-panes">
                        <!-- Left Pane -->
                        <div class="fm-pane active" id="fmLeftPane" data-pane="left">
                            <div class="fm-pane-header">
                                <select class="fm-source-select form-control" id="fmLeftSource">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmLeftSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ New Connection...</option>
                                </select>
                            </div>
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

                        <!-- Right Pane -->
                        <div class="fm-pane" id="fmRightPane" data-pane="right">
                            <div class="fm-pane-header">
                                <select class="fm-source-select form-control" id="fmRightSource">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmRightSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ New Connection...</option>
                                </select>
                            </div>
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
                    <div class="fm-queue" id="fmQueue">
                        <div class="fm-queue-header" id="fmQueueHeader">
                            <div class="fm-queue-title">
                                <span class="material-icons">sync</span>
                                <span data-i18n="fm.transfers">Transfers</span> <span class="fm-queue-badge" id="fmQueueBadge">0</span>
                            </div>
                            <span class="fm-queue-toggle material-icons" id="fmQueueToggle">expand_more</span>
                        </div>
                        <div class="fm-queue-list" id="fmQueueList"></div>
                    </div>

                    <!-- Mobile Upload Button -->
                    <div class="fm-mobile-upload" id="fmMobileUpload">
                        <span class="material-icons">cloud_upload</span>
                        <span>Tap to upload files</span>
                        <input type="file" id="fmMobileUploadInput" multiple hidden>
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
                    <span class="close" id="fmQcClose" aria-label="Close" data-i18n-aria-label="common.close">&times;</span>
                </div>
                <div class="modal-body">
                    <form id="fmQcForm">
                        <!-- Profile Selector -->
                        <div class="form-group">
                            <label for="fmQcProfile" data-i18n="fm.qc.savedProfiles">Saved Profiles</label>
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
        document.getElementById('fmRename').addEventListener('click', () => this.renameSelected());
        document.getElementById('fmDelete').addEventListener('click', () => this.deleteSelected());

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
        if (mobileUpload && mobileUploadInput) {
            mobileUpload.addEventListener('click', () => mobileUploadInput.click());
            mobileUploadInput.addEventListener('change', (e) => this.handleMobileUpload(e));
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
            if (!this.isOpen) return;

            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id)) {
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.files = data.files || [];
                    state.path = data.path;
                    state.loading = false;
                    state.error = null;
                    this.updatePathInput(pane, data.path);
                    this.renderPane(pane);
                }
            });
        });

        this.socket.on('home_directory', (data) => {
            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id)) {
                    if (!state.homePath) {
                        state.homePath = data.path;
                        if (state.path === '/') {
                            this.navigatePaneTo(pane, data.path);
                        }
                    }
                }
            });
        });

        this.socket.on('directory_created', (data) => {
            if (this.uploadBatches?.size > 0) return;
            this.showNotification(`${this.t('fm.folderCreated', 'Folder created')}: ${data.path}`, 'success');
            this.refreshBothPanes();
        });

        this.socket.on('file_renamed', (data) => {
            this.showNotification(this.t('fm.renamedSuccess', 'Renamed successfully'), 'success');
            this.refreshBothPanes();
        });

        this.socket.on('item_deleted', (data) => {
            this.showNotification(`${this.t('fm.deleted', 'Deleted')}: ${data.path}`, 'success');
            this.refreshBothPanes();
        });

        this.socket.on('s2s_transfer_started', (data) => {
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
            const errorMsg = data.error || data.message || 'Unknown error';
            console.error('[FM] SFTP Error received:', errorMsg, data);

            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.loading && state.type === 'ssh') {
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.loading = false;
                    state.error = errorMsg;
                    this.renderPane(pane);
                }
            });

            this.showNotification(errorMsg, 'error');
        });

        this.socket.on('file_exists_result', (data) => {
            if (this.pendingConflictCheck) {
                this.pendingConflictCheck(data);
                this.pendingConflictCheck = null;
            }
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (!this.isOpen) return;

            if (e.key === 'Escape') {
                this.closeContextMenu();
                if (!this.hasOpenDialogs()) {
                    this.close();
                }
            }

            if (e.key === 'Tab' && !e.target.matches('input, textarea, select')) {
                e.preventDefault();
                this.setActivePane(this.activePane === 'left' ? 'right' : 'left');
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
                this.executeTransfer();
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
        });
    }

    open() {
        this.isOpen = true;
        if (window.ModalManager) {
            window.ModalManager.open(this.modal);
        } else {
            this.modal.classList.add('show');
            this.modal.setAttribute('aria-hidden', 'false');
        }
        this.applyTranslations();
        this.updateSessionLists();

        const currentSession = typeof SessionManager !== 'undefined' ? SessionManager.getActiveSession() : null;

        const isMobileNow = this.isMobile();
        console.log('[FM] Opening file manager, isMobile:', isMobileNow, 'innerWidth:', window.innerWidth);

        if (isMobileNow) {
            this.modal.classList.add('fm-mobile-mode');
            document.getElementById('fmLeftPane').style.display = 'none';
            document.getElementById('fmRightPane').style.display = 'flex';
            document.getElementById('fmRightPane').classList.add('active');
            document.getElementById('fmLeftPane').classList.remove('active');
            this.activePane = 'right';

            if (currentSession) {
                document.getElementById('fmRightSource').value = `ssh:${currentSession}`;
                this.onSourceChange('right', `ssh:${currentSession}`);
            }
        } else {
            this.modal.classList.remove('fm-mobile-mode');
            document.getElementById('fmLeftPane').style.display = '';
            document.getElementById('fmRightPane').style.display = '';
            this.setActivePane('left');
            this.updateMobilePaneTabs('left');

            if (currentSession) {
                document.getElementById('fmRightSource').value = `ssh:${currentSession}`;
                this.onSourceChange('right', `ssh:${currentSession}`);
            }
        }
    }

    close() {
        this.isOpen = false;
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

    handleSessionDisconnected(sessionId) {
        ['left', 'right'].forEach(pane => {
            const state = this.panes[pane];
            if (state.type === 'ssh' &&
                (state.sessionId === sessionId || state.connectionId === sessionId)) {
                this.resetPane(pane);
            }
        });
        this.updateSessionLists();
    }

    hasOpenDialogs() {
        return document.querySelector('.fm-conflict-dialog') !== null ||
               this.qcModal.classList.contains('show');
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

        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
            state.loadingTimeout = null;
        }

        state.files = [];
        state.selected.clear();
        state.loading = true;
        state.error = null;
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

        if (value === 'browser-local') {
            if (!this.browserFS.isSupported) {
                this.showNotification(this.t('fm.fsaNotSupported', 'File System Access API not supported. Use drag & drop instead.'), 'warning');
                state.loading = false;
                this.renderPane(pane);
                return;
            }

            const granted = await this.browserFS.requestAccess();
            if (granted) {
                state.type = 'browser-local';
                state.sessionId = null;
                state.connectionId = null;
                state.path = this.browserFS.getCurrentPath();
                state.hostInfo = { host: this.t('fm.yourComputer', 'Your Computer'), username: '', port: '' };
                await this.refreshBrowserPane(pane);
            } else {
                state.loading = false;
                this.renderPane(pane);
            }
            this.updatePaneBadge(pane);

        } else if (value === 'quick-connect') {
            this.pendingQuickConnectPane = pane;
            this.openQuickConnect();
            const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
            select.value = state.type === 'ssh' ? `ssh:${state.sessionId || state.connectionId}` : '';
            state.loading = false;

        } else if (value.startsWith('ssh:')) {
            const sessionId = value.substring(4);
            state.type = 'ssh';
            state.sessionId = sessionId;
            state.connectionId = null;

            const session = this.availableSessions.find(s => s.id === sessionId);
            if (session) {
                state.hostInfo = { host: session.host, username: session.username, port: session.port };
            }

            this.socket.emit('get_home_directory', { session_id: sessionId });
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: '/' });
            this.updatePaneBadge(pane);

            this.setLoadingTimeout(pane);

        } else if (value.startsWith('qc:')) {
            const connectionId = value.substring(3);
            const qc = this.quickConnections.find(c => c.connectionId === connectionId);

            state.type = 'ssh';
            state.sessionId = null;
            state.connectionId = connectionId;

            if (qc) {
                state.hostInfo = { host: qc.host, username: qc.username, port: qc.port };
            }

            this.socket.emit('get_home_directory', { session_id: connectionId });
            this.socket.emit('list_directory', { session_id: connectionId, remote_path: '/' });
            this.updatePaneBadge(pane);

            this.setLoadingTimeout(pane);
        }
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

        if (state.type === 'browser-local') {
            badge.textContent = this.t('fm.yourComputer', 'Your Computer');
            badge.className = 'fm-host-badge browser';
        } else if (state.hostInfo) {
            badge.textContent = `${state.hostInfo.username}@${state.hostInfo.host}`;
            badge.className = 'fm-host-badge ssh';
        }
    }

    openQuickConnect() {
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

        if (this.pendingQuickConnectPane) {
            const pane = this.pendingQuickConnectPane;
            const state = this.panes[pane];

            state.type = 'ssh';
            state.sessionId = null;
            state.connectionId = data.connection_id;
            state.hostInfo = { host: data.host, username: data.username, port: data.port };

            const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
            select.value = `qc:${data.connection_id}`;

            state.loading = true;
            this.renderPane(pane);
            this.socket.emit('get_home_directory', { session_id: data.connection_id });
            this.socket.emit('list_directory', { session_id: data.connection_id, remote_path: '/' });
            this.setLoadingTimeout(pane);

            this.updatePaneBadge(pane);
        }

        this.closeQuickConnect();
    }

    async navigatePaneTo(pane, path) {
        const state = this.panes[pane];

        if (!state.type) {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
            return;
        }

        state.selected.clear();
        state.loading = true;
        this.renderPane(pane);

        if (state.type === 'browser-local') {
            try {
                await this.browserFS.navigateTo(path);
                state.path = this.browserFS.getCurrentPath();
                state.files = await this.browserFS.listDirectory();
                state.loading = false;
                this.updatePathInput(pane, state.path);
                this.renderPane(pane);
            } catch (e) {
                this.showNotification(`${this.t('fm.cannotNavigate', 'Cannot navigate to')} ${path}`, 'error');
                state.loading = false;
                this.renderPane(pane);
            }
        } else if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: path });
            this.setLoadingTimeout(pane);
        }
    }

    async navigatePaneUp(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'browser-local') {
            const navigated = await this.browserFS.navigateUp();
            if (navigated) {
                await this.refreshBrowserPane(pane);
            }
        } else if (state.type === 'ssh') {
            if (state.path === '/') return;
            const parentPath = state.path.split('/').slice(0, -1).join('/') || '/';
            this.navigatePaneTo(pane, parentPath);
        }
    }

    navigatePaneHome(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'browser-local') {
            this.browserFS.currentHandle = this.browserFS.rootHandle;
            this.browserFS.pathStack = [this.browserFS.rootHandle.name];
            this.refreshBrowserPane(pane);
        } else if (state.type === 'ssh') {
            const homePath = state.homePath || '/';
            this.navigatePaneTo(pane, homePath);
        }
    }

    async navigateIntoDir(pane, dirName) {
        const state = this.panes[pane];

        if (state.type === 'browser-local') {
            try {
                await this.browserFS.navigateInto(dirName);
                await this.refreshBrowserPane(pane);
            } catch (e) {
                this.showNotification(`${this.t('fm.cannotOpen', 'Cannot open')} ${dirName}`, 'error');
            }
        } else if (state.type === 'ssh') {
            const newPath = state.path === '/' ? '/' + dirName : state.path + '/' + dirName;
            this.navigatePaneTo(pane, newPath);
        }
    }

    async refreshPane(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'browser-local') {
            state.loading = true;
            this.renderPane(pane);
            await this.refreshBrowserPane(pane);
        } else if (state.type === 'ssh') {
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

            state.loading = true;
            this.renderPane(pane);
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: state.path });
            this.setLoadingTimeout(pane);
        }
    }

    async refreshBrowserPane(pane) {
        const state = this.panes[pane];
        try {
            state.files = await this.browserFS.listDirectory();
            state.path = this.browserFS.getCurrentPath();
            state.loading = false;
            this.updatePathInput(pane, state.path);
            this.renderPane(pane);
        } catch (e) {
            this.showNotification(this.t('fm.errorReadingDir', 'Error reading directory'), 'error');
            state.loading = false;
            this.renderPane(pane);
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
            container.innerHTML = `
                <div class="fm-empty">
                    <span class="material-icons fm-empty-icon">folder_open</span>
                    <div class="fm-empty-text">${this.t('fm.selectSourceAbove', 'Select a source above')}</div>
                </div>
            `;
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

        if (state.path !== '/' && !(state.type === 'browser-local' && this.browserFS.pathStack.length <= 1)) {
            html += `
                <div class="fm-file-item directory" data-index="-1" data-type="parent">
                    <span class="material-icons fm-file-icon parent">arrow_upward</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">..</div>
                        <div class="fm-file-meta">${this.t('fm.parentDirectory', 'Parent directory')}</div>
                    </div>
                    <div class="fm-file-size">-</div>
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
                    <span class="material-icons fm-file-icon ${file.is_dir ? 'folder' : 'file'}">${icon}</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">${this.escapeHtml(file.name)}</div>
                        <div class="fm-file-meta">${file.permissions || ''}</div>
                    </div>
                    <div class="fm-file-size">${file.is_dir ? '-' : this.formatSize(file.size || 0)}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = html;

        container.querySelectorAll('.fm-file-item').forEach(item => {
            const index = parseInt(item.dataset.index);
            item.addEventListener('click', (e) => this.handleItemClick(e, pane, index));
            item.addEventListener('dblclick', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.handleItemDblClick(pane, index);
            });
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

        if (e.ctrlKey || e.metaKey) {
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

    handleItemDblClick(pane, index) {
        const state = this.panes[pane];
        console.log('[SFTP] handleItemDblClick called:', { pane, index, type: state.type, sessionId: state.sessionId, connectionId: state.connectionId });

        if (index === -1) {
            this.navigatePaneUp(pane);
            return;
        }

        const file = state.files[index];
        if (!file) {
            console.log('[SFTP] No file at index:', index);
            return;
        }

        console.log('[SFTP] File info:', { name: file.name, is_dir: file.is_dir });

        if (file.is_dir) {
            this.navigateIntoDir(pane, file.name);
        } else {
            if (state.type === 'ssh') {
                const sessionId = state.sessionId || state.connectionId;
                const filePath = this.joinPath(state.path, file.name);
                console.log('[SFTP] Opening preview:', { sessionId, filePath, hasFilePreview: !!window.FilePreview });
                if (window.FilePreview) {
                    window.FilePreview.open(sessionId, filePath, file.name);
                } else {
                    console.error('[SFTP] FilePreview not available');
                }
            } else if (state.type === 'browser-local') {
                this.showNotification('Local file preview not yet supported', 'info');
            } else {
                console.log('[SFTP] Unknown state type for preview:', state.type);
            }
        }
    }

    updateSelectionVisual(pane) {
        const state = this.panes[pane];
        const container = document.getElementById(`fm${this.capitalize(pane)}List`);

        container.querySelectorAll('.fm-file-item').forEach(item => {
            const idx = parseInt(item.dataset.index);
            if (idx >= 0) {
                item.classList.toggle('selected', state.selected.has(idx));
            }
        });

        this.updatePaneStatus(pane);
    }

    setActivePane(pane) {
        if (this.isMobile()) {
            pane = 'right';
        }

        this.activePane = pane;
        document.getElementById('fmLeftPane').classList.toggle('active', pane === 'left');
        document.getElementById('fmRightPane').classList.toggle('active', pane === 'right');
        this.updateMobilePaneTabs(pane);
    }

    isMobile() {
        return window.innerWidth < 768;
    }

    updateMobilePaneTabs(pane) {
        document.querySelectorAll('.fm-pane-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.pane === pane);
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
                    const file = state.files[index];
                    if (file && file.is_dir) {
                        this.navigateToFile(this.activePane, file);
                    }
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
        console.log('[FM] Mobile upload - activePane:', this.activePane, 'state:', {
            type: state.type,
            sessionId: state.sessionId,
            connectionId: state.connectionId,
            path: state.path
        });

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

            console.log('[FM] Starting upload of', files.length, 'files to', state.path, 'via session', sessionId);
            this.showNotification(`${this.t('fm.uploading', 'Uploading')} ${files.length} ${this.t('fm.files', 'file(s)')}...`, 'info');
            const batch = this.startUploadBatch(files.length, sessionId);

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
        const state = this.panes[this.activePane];
        state.files.forEach((_, index) => state.selected.add(index));
        this.updateSelectionVisual(this.activePane);
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

        if (state.type === 'browser-local') {
            this.browserFS.createDirectory(name)
                .then(() => {
                    this.showNotification(`${this.t('fm.folderCreated', 'Folder created')}: ${name}`, 'success');
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
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

        if (state.type === 'browser-local') {
            Promise.all(items.map(item => this.browserFS.deleteEntry(item.name)))
                .then(() => {
                    this.showNotification(this.t('fm.itemsDeleted', 'Items deleted'), 'success');
                    state.selected.clear();
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
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

        if (state.type === 'browser-local') {
            this.browserFS.rename(file.name, newName)
                .then(() => {
                    this.showNotification(this.t('fm.renamedSuccess', 'Renamed successfully'), 'success');
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
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
                    case 'browser-local-to-ssh':
                        await this.transferBrowserToSSH(item, targetPath, target);
                        break;

                    case 'ssh-to-browser-local':
                        await this.transferSSHToBrowser(
                            sourcePath,
                            source,
                            item.name,
                            targetPane,
                        );
                        break;

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

    async transferBrowserToSSH(item, targetPath, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;

        if (item.is_dir) {
            await this.uploadBrowserFolderToSSH(item.handle, targetPath, sessionId);
        } else {
            try {
                const file = await item.handle.getFile();
                const transferId = this.getTransferClient().uploadFile(file, targetPath, sessionId);
                this.queueTransfer({
                    id: transferId,
                    type: 'upload',
                    filename: item.name,
                    targetPath: targetPath,
                    size: file.size,
                    sessionId: sessionId,
                    batchId: null
                });
            } catch (e) {
                this.showNotification(`${this.t('fm.failedToRead', 'Failed to read')} ${item.name}: ${e.message}`, 'error');
            }
        }
    }

    async uploadBrowserFolderToSSH(dirHandle, remotePath, sessionId, batchId = null) {
        this.socket.emit('create_directory', { session_id: sessionId, remote_path: remotePath });
        await new Promise(r => setTimeout(r, 100));

        for await (const entry of dirHandle.values()) {
            const entryPath = remotePath + '/' + entry.name;

            if (entry.kind === 'directory') {
                await this.uploadBrowserFolderToSSH(entry, entryPath, sessionId, batchId);
            } else {
                try {
                    const file = await entry.getFile();
                    const transferId = this.getTransferClient().uploadFile(file, entryPath, sessionId);
                    this.queueTransfer({
                        id: transferId,
                        type: 'upload',
                        filename: entry.name,
                        targetPath: entryPath,
                        size: file.size,
                        sessionId: sessionId,
                        batchId: batchId
                    });
                } catch (e) {
                    console.error('Failed to upload:', entry.name, e);
                }
            }
        }
    }

    async transferSSHToBrowser(
        sourcePath,
        sourcePane,
        filename,
        targetPane,
    ) {
        const sessionId = sourcePane.sessionId || sourcePane.connectionId;
        const targetDirectory = this.browserFS.currentHandle;
        const transfer = this.getTransferClient().downloadFileToWritable(
            sourcePath,
            sessionId,
            () => this.browserFS.createWritableSink(
                filename,
                targetDirectory,
            ),
        );

        this.queueTransfer({
            id: transfer.id,
            type: 'download',
            filename: filename,
            sourcePath: sourcePath
        });
        try {
            if (await transfer.done) {
                await this.refreshBrowserPane(targetPane);
            }
        } catch (_error) {
            // BinaryTransferClient reports the bounded transfer error to the queue.
        }
    }

    async transferSSHtoSSH(sourcePath, sourcePane, targetPath, targetPane, item) {
        const sourceSessionId = sourcePane.sessionId || sourcePane.connectionId;
        const targetSessionId = targetPane.sessionId || targetPane.connectionId;

        if (sourceSessionId === targetSessionId) {
            this.showNotification(this.t('fm.cannotTransferSameHost', 'Cannot transfer to same host. Use rename instead.'), 'warning');
            return;
        }

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
            size: item.size || 0
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
        } else if (target.type === 'browser-local') {
            this.showNotification(this.t('fm.useFilesystemForLocal', 'Use your file system to add files to your local folder'), 'info');
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

        const batch = this.startUploadBatch(totalFiles, sessionId);

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
        const batch = this.startUploadBatch(files.length, sessionId);

        for (const file of files) {
            this.uploadSingleFileToSSH(file, targetPane.path, sessionId, batch.id);
        }
    }

    startUploadBatch(total, sessionId) {
        if (!Number.isInteger(total) || total <= 0) {
            return { id: null, total: 0, completed: 0, sessionId: sessionId };
        }
        if (!this.uploadBatches) this.uploadBatches = new Map();
        const batch = {
            id: `batch_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
            total: total,
            completed: 0,
            succeeded: 0,
            failed: 0,
            cancelled: 0,
            sessionId: sessionId
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
        this.scheduleUploadRefresh(batch.sessionId);
    }

    scheduleUploadRefresh(sessionId) {
        if (!sessionId) return;
        const pane = this.getPaneForSession(sessionId);
        if (!pane) return;
        if (!this.uploadRefreshes) this.uploadRefreshes = new Map();
        const key = `${pane}:${sessionId}`;
        if (this.uploadRefreshes.has(key)) return;

        const scheduled = Promise.resolve().then(() => {
            this.uploadRefreshes.delete(key);
            if (this.getPaneForSession(sessionId) !== pane) return;
            return this.refreshPane(pane);
        }).catch(error => {
            console.error('[FM] Failed to refresh upload destination:', error);
        });
        this.uploadRefreshes.set(key, scheduled);
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
        if (transfer.type === 's2s') {
            this.resolveS2STerminal(transfer.id, status);
        }
        if (wasActive) {
            this.isTransferring = false;
            setTimeout(() => this.processTransferQueue(), 100);
        }
        this.renderTransferQueue();
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
            size: 0
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
            size: 0
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
        document.getElementById('fmQueue').classList.toggle('collapsed');
        const toggle = document.getElementById('fmQueueToggle');
        toggle.textContent = toggle.textContent === '▼' ? '▲' : '▼';
    }

    showContextMenu(e, pane, index) {
        e.preventDefault();
        e.stopPropagation();
        this.closeContextMenu();

        const state = this.panes[pane];
        const file = index >= 0 ? state.files[index] : null;

        const menu = document.createElement('div');
        menu.className = 'fm-context-menu';

        let items = [];

        if (file) {
            if (file.is_dir) {
                items.push({ action: 'open', icon: '📂', text: this.t('fm.ctx.open', 'Open') });
                if (state.type === 'ssh' || state.type === 'quick-connect') {
                    items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
                }
            } else {
                if (state.type === 'ssh' || state.type === 'quick-connect') {
                    items.push({ action: 'preview', icon: '👁️', text: this.t('fm.ctx.preview', 'Preview') });
                    items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
                }
            }
            if (!this.isMobile()) {
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
        } else {
            console.log(`[${type}] ${message}`);
        }
    }
}

let sftpFileManager = null;

function openFileManager() {
    if (!sftpFileManager) {
        sftpFileManager = new SFTPFileManager();
        window.sftpFileManager = sftpFileManager;
    }
    sftpFileManager.open();
}

window.SFTPFileManager = SFTPFileManager;
window.openFileManager = openFileManager;
