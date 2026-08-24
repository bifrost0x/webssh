(function exposeSMBSourceDialog(globalScope) {
    'use strict';

    const ERROR_PRESENTATIONS = {
        SMB_DISABLED: ['smb.error.disabled', 'SMB is disabled by the administrator.'],
        RATE_LIMITED: ['smb.error.rateLimited', 'Too many attempts. Please wait and try again.'],
        QUOTA_EXCEEDED: ['smb.error.quota', 'The connection limit has been reached.'],
        TARGET_NOT_ALLOWED: ['smb.error.target', 'This SMB server is not allowed.'],
        AUTHENTICATION_REQUIRED: ['smb.error.authentication', 'Authentication failed. Enter the password again.'],
        ENCRYPTION_REQUIRED: ['smb.error.encryption', 'The server does not support the required SMB encryption.'],
        DIALECT_REQUIRED: ['smb.error.dialect', 'The server does not support SMB 3.1.1.'],
        RUNTIME_SHUTTING_DOWN: ['smb.error.shutdown', 'The server is shutting down.'],
        INVALID_REQUEST: ['smb.error.invalid', 'Check the connection details and try again.'],
        CONNECTION_FAILED: ['smb.error.connection', 'The SMB connection could not be established.'],
    };

    class SMBSourceDialog {
        constructor(options = {}) {
            this.root = options.root || globalScope.document?.getElementById?.('smbSourceModal') || null;
            this.socket = options.socket || globalScope.socket || null;
            this.enabled = options.enabled ?? this.root?.dataset?.enabled === 'true';
            this.t = options.t || ((key, fallback) => globalScope.i18n?.t?.(key) || fallback);
            this.onConnected = options.onConnected || (() => {});
            this.onSharesChanged = options.onSharesChanged || (() => {});
            this.confirmDelete = options.confirmDelete || (message => (
                typeof globalScope.confirm === 'function'
                    ? globalScope.confirm(message)
                    : true
            ));
            this.requestIdFactory = options.requestIdFactory || (() => (
                `smb-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
            ));
            this.connectTimeoutMs = Number.isFinite(options.connectTimeoutMs)
                ? Math.max(1, options.connectTimeoutMs)
                : 30000;
            this.setTimeout = options.setTimeout || globalThis.setTimeout.bind(globalThis);
            this.clearTimeout = options.clearTimeout || globalThis.clearTimeout.bind(globalThis);
            this.openModal = options.openModal || (modal => {
                if (globalScope.ModalManager) globalScope.ModalManager.open(modal);
            });
            this.closeModal = options.closeModal || (modal => {
                if (globalScope.ModalManager) globalScope.ModalManager.close(modal);
            });
            this.elements = options.elements || this.lookupElements();
            this.pending = null;
            this.pendingShareOperation = null;
            this.savedShares = [];
            this.selectedSavedId = null;
            this.pane = null;
            this.returnFocus = null;
            this.bound = false;
            this.bind();
        }

        lookupElements() {
            const byId = id => globalScope.document?.getElementById?.(id) || null;
            return {
                host: byId('smbSourceHost'),
                share: byId('smbSourceShare'),
                domain: byId('smbSourceDomain'),
                username: byId('smbSourceUsername'),
                password: byId('smbSourcePassword'),
                passwordToggle: byId('smbSourcePasswordToggle'),
                passwordIcon: byId('smbSourcePasswordToggle')?.querySelector?.('.material-icons'),
                name: byId('smbSourceName'),
                saved: byId('smbSourceSaved'),
                save: byId('smbSourceSave'),
                deleteSaved: byId('smbSourceDeleteSaved'),
                submit: byId('smbSourceConnect'),
                status: byId('smbSourceStatus'),
                form: byId('smbSourceForm'),
                close: byId('smbSourceClose'),
                cancel: byId('smbSourceCancel'),
            };
        }

        bind() {
            if (this.bound) return;
            this.bound = true;
            this.elements.form?.addEventListener?.('submit', event => {
                event.preventDefault();
                this.submit();
            });
            this.elements.close?.addEventListener?.('click', () => this.close({ cancelAttempt: true }));
            this.elements.cancel?.addEventListener?.('click', () => this.close({ cancelAttempt: true }));
            this.elements.saved?.addEventListener?.('change', event => {
                this.selectSavedShare(event.target.value);
            });
            this.elements.save?.addEventListener?.('click', () => this.saveDefinition());
            this.elements.deleteSaved?.addEventListener?.(
                'click',
                () => this.deleteSelectedDefinition(),
            );
            this.elements.passwordToggle?.addEventListener?.('click', () => {
                if (!this.elements.password) return;
                const visible = this.elements.password.type === 'text';
                this.elements.password.type = visible ? 'password' : 'text';
                if (this.elements.passwordIcon) {
                    this.elements.passwordIcon.textContent = visible
                        ? 'visibility'
                        : 'visibility_off';
                }
                this.elements.password.focus?.();
            });
            this.root?.addEventListener?.('click', event => {
                if (event.target === this.root) this.close({ cancelAttempt: true });
            });
            globalScope.document?.addEventListener?.('keydown', event => {
                if (event.key === 'Escape' && this.root?.classList?.contains('show')) {
                    event.preventDefault();
                    event.stopImmediatePropagation?.();
                    this.close({ cancelAttempt: true });
                }
            }, true);
            this.socket?.on?.('smb_quick_connect_success', payload => this.handleSuccess(payload));
            this.socket?.on?.('smb_quick_connect_error', payload => this.handleError(payload));
            this.socket?.on?.('smb_shares_list', payload => {
                this.setSavedShares(payload?.smb_shares || []);
            });
            this.socket?.on?.('smb_share_saved', payload => this.handleShareSaved(payload));
            this.socket?.on?.('smb_share_deleted', payload => this.handleShareDeleted(payload));
            this.socket?.on?.('smb_share_error', payload => this.handleShareError(payload));
        }

        setValues(values = {}) {
            ['host', 'share', 'domain', 'username', 'password'].forEach(name => {
                if (this.elements[name] && Object.hasOwn(values, name)) {
                    this.elements[name].value = String(values[name] ?? '');
                }
            });
        }

        passwordValue() {
            return this.elements.password?.value || '';
        }

        setBusy(busy) {
            if (this.elements.submit) this.elements.submit.disabled = Boolean(busy);
            ['host', 'share', 'domain', 'username', 'password', 'name', 'saved', 'save', 'deleteSaved', 'passwordToggle'].forEach(name => {
                if (this.elements[name]) this.elements[name].disabled = Boolean(busy);
            });
            if (this.elements.save) {
                this.elements.save.disabled = Boolean(busy) || Boolean(this.pendingShareOperation);
            }
            if (this.elements.deleteSaved) {
                this.elements.deleteSaved.disabled = Boolean(busy)
                    || Boolean(this.pendingShareOperation)
                    || !this.selectedSavedId;
            }
        }

        setShareBusy(busy) {
            if (this.elements.save) this.elements.save.disabled = Boolean(busy);
            if (this.elements.deleteSaved) {
                this.elements.deleteSaved.disabled = Boolean(busy) || !this.selectedSavedId;
            }
        }

        setStatus(message, state = '') {
            if (!this.elements.status) return;
            this.elements.status.textContent = message;
            if (this.elements.status.dataset) this.elements.status.dataset.state = state;
        }

        open({ pane, returnFocus = null, savedShare = null } = {}) {
            if (!this.enabled || !['left', 'right'].includes(pane)) return false;
            this.pane = pane;
            this.returnFocus = returnFocus || globalScope.document?.activeElement || null;
            this.resetForm();
            if (savedShare) {
                if (!this.savedShares.some(item => item.id === savedShare.id)) {
                    this.setSavedShares([...this.savedShares, savedShare]);
                }
                this.selectSavedShare(savedShare.id, { focusPassword: false });
            }
            this.setBusy(false);
            this.setStatus('');
            this.openModal(this.root);
            (savedShare ? this.elements.password : this.elements.host)?.focus?.();
            return true;
        }

        close({ cancelAttempt = true } = {}) {
            if (cancelAttempt) {
                this.cancelPendingAttempt();
            } else {
                this.clearPendingTimeout();
                this.pending = null;
            }
            this.pendingShareOperation = null;
            if (this.elements.password) this.elements.password.value = '';
            this.setBusy(false);
            this.setStatus('');
            this.closeModal(this.root);
            const focusTarget = this.returnFocus;
            this.returnFocus = null;
            this.pane = null;
            if (focusTarget?.isConnected !== false) focusTarget?.focus?.();
            this.resetForm();
        }

        clearPendingTimeout() {
            if (!this.pending || this.pending.timeoutId === null) return;
            this.clearTimeout(this.pending.timeoutId);
            this.pending.timeoutId = null;
        }

        cancelPendingAttempt() {
            const pending = this.pending;
            if (!pending) return false;
            this.clearPendingTimeout();
            this.pending = null;
            if (this.socket?.connected === true && typeof this.socket?.emit === 'function') {
                try {
                    this.socket.emit('smb_quick_connect_cancel', {
                        request_id: pending.requestId,
                    });
                } catch {
                    // Local cleanup must not depend on transport availability.
                }
            }
            return true;
        }

        handleConnectTimeout(requestId) {
            if (!this.pending || this.pending.requestId !== requestId) return false;
            this.cancelPendingAttempt();
            this.setBusy(false);
            this.setStatus(
                this.t('smb.error.connection', 'The SMB connection could not be established.'),
                'error',
            );
            this.elements.password?.focus?.();
            return true;
        }

        resetForm() {
            ['host', 'share', 'domain', 'username', 'password', 'name'].forEach(name => {
                if (this.elements[name]) this.elements[name].value = '';
            });
            if (this.elements.password) this.elements.password.type = 'password';
            if (this.elements.passwordIcon) this.elements.passwordIcon.textContent = 'visibility';
            if (this.elements.saved) this.elements.saved.value = '';
            this.selectedSavedId = null;
            if (this.elements.deleteSaved) this.elements.deleteSaved.disabled = true;
        }

        setSavedShares(shares) {
            this.savedShares = (Array.isArray(shares) ? shares : [])
                .filter(item => (
                    item
                    && typeof item === 'object'
                    && typeof item.id === 'string'
                    && typeof item.name === 'string'
                    && typeof item.host === 'string'
                    && typeof item.share === 'string'
                    && typeof item.domain === 'string'
                    && typeof item.username === 'string'
                    && !Object.hasOwn(item, 'password')
                ))
                .map(item => ({
                    id: item.id,
                    name: item.name,
                    host: item.host,
                    share: item.share,
                    domain: item.domain,
                    username: item.username,
                }));
            this.renderSavedShares();
            this.onSharesChanged([...this.savedShares]);
        }

        renderSavedShares() {
            const select = this.elements.saved;
            const documentRef = select?.ownerDocument || globalScope.document;
            if (!select?.replaceChildren || !documentRef?.createElement) return;
            const manual = documentRef.createElement('option');
            manual.value = '';
            manual.textContent = this.t('smb.enterManually', '-- Enter manually --');
            const options = this.savedShares.map(share => {
                const option = documentRef.createElement('option');
                option.value = share.id;
                option.textContent = `${share.name} (${share.username}@${share.host}/${share.share})`;
                return option;
            });
            select.replaceChildren(manual, ...options);
            select.value = this.savedShares.some(item => item.id === this.selectedSavedId)
                ? this.selectedSavedId
                : '';
        }

        selectSavedShare(shareId, { focusPassword = true } = {}) {
            if (!shareId) {
                this.selectedSavedId = null;
                if (this.elements.saved) this.elements.saved.value = '';
                ['host', 'share', 'domain', 'username', 'name', 'password'].forEach(name => {
                    if (this.elements[name]) this.elements[name].value = '';
                });
                if (this.elements.deleteSaved) this.elements.deleteSaved.disabled = true;
                if (focusPassword) this.elements.host?.focus?.();
                return true;
            }
            const selected = this.savedShares.find(item => item.id === shareId);
            if (!selected) return false;
            this.selectedSavedId = selected.id;
            if (this.elements.saved) this.elements.saved.value = selected.id;
            this.setValues({
                host: selected.host,
                share: selected.share,
                domain: selected.domain,
                username: selected.username,
                password: '',
            });
            if (this.elements.name) this.elements.name.value = selected.name;
            if (this.elements.deleteSaved) this.elements.deleteSaved.disabled = false;
            if (focusPassword) this.elements.password?.focus?.();
            return true;
        }

        definitionValues() {
            const connection = this.values();
            return {
                name: this.elements.name?.value?.trim?.() || '',
                host: connection.host,
                share: connection.share,
                domain: connection.domain,
                username: connection.username,
            };
        }

        definitionIdentity() {
            const definition = this.definitionValues();
            return JSON.stringify([
                this.selectedSavedId || '',
                definition.name,
                definition.host,
                definition.share,
                definition.domain,
                definition.username,
            ]);
        }

        saveDefinition() {
            if (
                !this.enabled
                || !this.socket
                || this.pending
                || this.pendingShareOperation
            ) return false;
            const definition = this.definitionValues();
            const invalid = !definition.name
                ? this.elements.name
                : this.firstInvalid({ ...definition, password: 'not-saved' });
            if (invalid) {
                this.setStatus(
                    this.t('smb.error.saveRequired', 'Enter a name and complete the connection details.'),
                    'error',
                );
                invalid.focus?.();
                return false;
            }
            const requestId = this.requestIdFactory();
            this.pendingShareOperation = {
                action: 'save',
                requestId,
                definitionIdentity: this.definitionIdentity(),
            };
            this.setShareBusy(true);
            this.socket.emit('save_smb_share', {
                request_id: requestId,
                ...(this.selectedSavedId ? { id: this.selectedSavedId } : {}),
                ...definition,
            });
            this.setStatus(this.t('smb.saving', 'Saving SMB share…'), 'pending');
            return true;
        }

        deleteSelectedDefinition() {
            if (
                !this.enabled
                || !this.socket
                || !this.selectedSavedId
                || this.pending
                || this.pendingShareOperation
            ) {
                return false;
            }
            if (!this.confirmDelete(this.t('smb.deleteConfirm', 'Delete this saved SMB share?'))) {
                return false;
            }
            const requestId = this.requestIdFactory();
            this.pendingShareOperation = {
                action: 'delete',
                requestId,
                shareId: this.selectedSavedId,
            };
            this.setShareBusy(true);
            this.socket.emit('delete_smb_share', {
                request_id: requestId,
                share_id: this.selectedSavedId,
            });
            this.setStatus(this.t('smb.deleting', 'Deleting saved SMB share…'), 'pending');
            return true;
        }

        matchingShareOperation(payload, action) {
            const operation = this.pendingShareOperation;
            if (
                !operation
                || operation.action !== action
                || payload?.request_id !== operation.requestId
            ) return null;
            return operation;
        }

        handleShareSaved(payload = {}) {
            const operation = this.matchingShareOperation(payload, 'save');
            const share = payload?.share;
            if (!operation || !share || typeof share !== 'object') return false;
            const formIsUnchanged = this.definitionIdentity()
                === operation.definitionIdentity;
            const password = formIsUnchanged ? this.passwordValue() : '';
            this.pendingShareOperation = null;
            this.setShareBusy(false);
            this.setSavedShares([
                ...this.savedShares.filter(item => item.id !== share.id),
                share,
            ]);
            if (formIsUnchanged) {
                this.selectSavedShare(share.id, { focusPassword: false });
                if (this.elements.password) this.elements.password.value = password;
            }
            this.setStatus(this.t('smb.saved', 'SMB share saved.'), 'success');
            return true;
        }

        handleShareDeleted(payload = {}) {
            const operation = this.matchingShareOperation(payload, 'delete');
            if (!operation || payload?.share_id !== operation.shareId) return false;
            this.pendingShareOperation = null;
            this.setShareBusy(false);
            this.setSavedShares(
                this.savedShares.filter(item => item.id !== payload.share_id)
            );
            if (payload.share_id === this.selectedSavedId) {
                this.selectSavedShare('', { focusPassword: false });
            }
            this.setStatus(this.t('smb.deleted', 'Saved SMB share deleted.'), 'success');
            return true;
        }

        handleShareError(payload = {}) {
            if (payload?.action !== 'list') {
                const operation = this.pendingShareOperation;
                if (!operation || payload?.request_id !== operation.requestId) return false;
                this.pendingShareOperation = null;
                this.setShareBusy(false);
            }
            this.setStatus(
                payload?.error || this.t('smb.error.storage', 'Saved SMB share operation failed.'),
                'error',
            );
            return true;
        }

        values() {
            return {
                host: this.elements.host?.value?.trim?.() || '',
                share: this.elements.share?.value?.trim?.() || '',
                domain: this.elements.domain?.value?.trim?.() || '',
                username: this.elements.username?.value?.trim?.() || '',
                password: this.elements.password?.value || '',
            };
        }

        firstInvalid(values) {
            if (!values.host || values.host.length > 253) return this.elements.host;
            if (
                !values.share
                || values.share.length > 80
                || /[<>:"/\\|?*$\x00-\x1f]/.test(values.share)
                || /[. ]$/.test(values.share)
            ) return this.elements.share;
            if (values.domain.length > 255 || /[\x00-\x1f]/.test(values.domain)) {
                return this.elements.domain;
            }
            if (!values.username || values.username.length > 256 || /[\x00-\x1f]/.test(values.username)) {
                return this.elements.username;
            }
            if (!values.password || values.password.length > 4096 || /[\x00-\x1f]/.test(values.password)) {
                return this.elements.password;
            }
            return null;
        }

        submit() {
            if (!this.enabled || !this.socket || this.pending) return false;
            const values = this.values();
            const invalid = this.firstInvalid(values);
            if (invalid) {
                this.setStatus(
                    this.t('smb.error.required', 'Complete all required fields.'),
                    'error',
                );
                invalid.focus?.();
                return false;
            }

            if (
                this.socket.connected !== true
                || typeof this.socket?.volatile?.emit !== 'function'
            ) {
                this.elements.password.value = '';
                this.setStatus(
                    this.t(
                        'smb.error.disconnected',
                        'Connection to WebSSH was lost. Reconnect and try again.',
                    ),
                    'error',
                );
                this.elements.password.focus?.();
                return false;
            }

            const requestId = this.requestIdFactory();
            this.pending = { requestId, pane: this.pane, timeoutId: null };
            this.setBusy(true);
            this.setStatus(this.t('smb.connecting', 'Connecting securely…'), 'pending');
            this.elements.password.value = '';
            this.pending.timeoutId = this.setTimeout(
                () => this.handleConnectTimeout(requestId),
                this.connectTimeoutMs,
            );
            try {
                this.socket.volatile.emit('smb_quick_connect', {
                    request_id: requestId,
                    ...values,
                });
            } catch {
                this.handleConnectTimeout(requestId);
                return false;
            }
            return true;
        }

        handleSuccess(payload = {}) {
            if (!this.pending || payload.request_id !== this.pending.requestId) return false;
            if (!payload.file_source || typeof payload.file_source !== 'object') {
                return this.handleError({
                    request_id: payload.request_id,
                    code: 'CONNECTION_FAILED',
                });
            }
            const result = {
                pane: this.pending.pane,
                descriptor: payload.file_source,
            };
            this.clearPendingTimeout();
            this.close({ cancelAttempt: false });
            this.onConnected(result);
            return true;
        }

        handleError(payload = {}) {
            if (!this.pending || payload.request_id !== this.pending.requestId) return false;
            const code = Object.hasOwn(ERROR_PRESENTATIONS, payload.code)
                ? payload.code
                : 'CONNECTION_FAILED';
            const [key, fallback] = ERROR_PRESENTATIONS[code];
            this.clearPendingTimeout();
            this.pending = null;
            this.setBusy(false);
            this.setStatus(this.t(key, fallback), 'error');
            if (code === 'AUTHENTICATION_REQUIRED') this.elements.password?.focus?.();
            return true;
        }
    }

    globalScope.SMBSourceDialog = SMBSourceDialog;
})(typeof window !== 'undefined' ? window : globalThis);
