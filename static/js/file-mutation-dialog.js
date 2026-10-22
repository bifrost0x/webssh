/* Explicit file mutations bound to the source and directory shown at open. */
(() => {
    'use strict';

    function validLeaf(name) {
        return typeof name === 'string' && name.length > 0
            && !['.', '..'].includes(name) && !/[\/\\\u0000-\u001f\u007f-\u009f]/u.test(name)
            && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(name)
            && new TextEncoder().encode(name).length <= 255;
    }

    function validMode(value) { return typeof value === 'string' && /^[0-7]{3}$/u.test(value); }

    // Compare the complete server snapshot digest without rounding remote size/mtime.
    // The signed token remains opaque authority: only the backend validates its HMAC.
    function metadataFingerprint(token) {
        if (typeof token !== 'string') return null;
        const match = /^[0-9]{1,12}\.([a-f0-9]{64})\.[a-f0-9]{64}$/u.exec(token);
        return match && match[0] === token ? match[1] : null;
    }

    class FileMutationDialog {
        constructor(manager, pane, file = null) {
            this.manager = manager;
            const state = manager.panes[pane];
            const files = Array.isArray(file) ? file : (file ? [file] : []);
            this.batch = files.length > 1;
            this.targets = files.map(item => ({ path: manager.joinPath(state.path, item.name), name: item.name, outcome: 'pending' }));
            file = files[0] || null;
            this.batchPhase = this.batch ? 'inspecting' : null;
            this.batchIndex = 0;
            this.target = Object.freeze({ pane, state, sourceId: manager.getPaneSourceId(state), parent: state.path,
                version: state.mutationViewVersion || 0, path: file ? manager.joinPath(state.path, file.name) : null });
            this.permissions = Boolean(file);
            this.trigger = document.activeElement;
            this.closed = false;
            this.pending = false;
            this.uncertain = false;
            this.dialog = document.createElement('dialog');
            this.dialog.className = 'fm-mutation-dialog';
            this.dialog.setAttribute('aria-labelledby', 'fmMutationTitle');
            this.dialog.innerHTML = `<form novalidate>
                <h3 id="fmMutationTitle"></h3><p class="fm-mutation-target"></p>
                <label class="fm-mutation-name"><span></span><input name="filename" autocomplete="off" required></label>
                <label class="fm-mutation-edit"><input name="edit" type="checkbox"><span></span></label>
                <fieldset class="fm-permissions"><legend></legend><div class="fm-permission-grid"></div>
                    <label class="fm-mutation-mode"><span></span><input name="mode" inputmode="numeric" maxlength="3" pattern="[0-7]{3}" autocomplete="off"></label>
                </fieldset><p class="fm-mutation-hint"></p><p class="fm-mutation-status" role="status" aria-live="polite"></p>
                <ul class="fm-mutation-results" hidden></ul>
                <div class="fm-mutation-actions"><button type="button" class="btn btn-secondary" data-close></button><button type="submit" class="btn btn-primary"></button></div>
            </form>`;
            const text = (selector, key, fallback) => { this.dialog.querySelector(selector).textContent = manager.t(key, fallback); };
            text('h3', this.permissions ? 'fm.permissions' : 'fm.newFile', this.permissions ? 'Permissions' : 'New file');
            this.dialog.querySelector('.fm-mutation-target').textContent = `${state.source?.label || this.target.sourceId}\n${this.target.path || this.target.parent}`;
            text('.fm-mutation-name span', 'fm.fileName', 'File name');
            text('.fm-mutation-edit span', 'fm.editAfterCreate', 'Open in editor after creation');
            text('legend', 'fm.unixPermissions', 'Unix permissions');
            text('.fm-mutation-mode span', 'fm.octalMode', 'Octal permissions');
            text('[data-close]', 'common.cancel', 'Cancel');
            text('[type="submit"]', this.permissions ? 'fm.applyPermissions' : 'fm.createFile', this.permissions ? 'Apply permissions' : 'Create file');
            text('.fm-mutation-hint', this.permissions ? 'fm.permissionsHint' : 'fm.newFileHint', this.permissions
                ? 'Directory execute means traverse. Removing owner access can lock you out. Unix mode is not a full ACL view.'
                : 'Creates an empty file without replacing existing items. SFTP files start with private permissions.');
            this.name = this.dialog.querySelector('[name="filename"]');
            this.mode = this.dialog.querySelector('[name="mode"]');
            this.button = this.dialog.querySelector('[type="submit"]');
            this.status = this.dialog.querySelector('[role="status"]');
            this.grid = this.dialog.querySelector('.fm-permission-grid');
            this.results = this.dialog.querySelector('.fm-mutation-results');
            this.results.hidden = !this.batch;
            if (this.batch) {
                this.dialog.querySelector('.fm-mutation-target').textContent = `${state.source?.label || this.target.sourceId}\n${this.targets.length} ${manager.t('fm.selectedItems', 'selected items')}`;
                text('.fm-mutation-hint', 'fm.batchPermissionsHint', 'Applies the same mode to each selected item, without recursion. Rechecks each item before applying. Stops on metadata changes or the first error; completed changes remain.');
                this.renderBatch();
            }
            this.onDisconnect = () => {
                if (this.batch && !['done', 'stopped'].includes(this.batchPhase)) this.stopBatch('fm.batchDisconnected', 'Connection lost. Remaining items were not sent.');
            };
            manager.socket.on?.('disconnect', this.onDisconnect);
            this.dialog.querySelector('.fm-permissions').hidden = !this.permissions;
            this.dialog.querySelector('.fm-mutation-name').hidden = this.permissions;
            this.dialog.querySelector('.fm-mutation-edit').hidden = this.permissions;
            this.buildPermissionGrid();
            this.dialog.addEventListener('keydown', event => event.stopPropagation());
            this.dialog.addEventListener('close', () => this.close());
            this.dialog.querySelector('[data-close]').addEventListener('click', () => this.close());
            this.dialog.querySelector('form').addEventListener('submit', event => { event.preventDefault(); this.submit(); });
            this.name.addEventListener('input', () => this.update());
            this.mode.addEventListener('input', () => { this.syncChecks(); this.update(); });
            document.body.appendChild(this.dialog);
            this.dialog.showModal();
            (this.permissions ? this.dialog.querySelector('[data-close]') : this.name).focus();
            this.update();
            if (this.batch) this.advanceBatch();
            else if (this.permissions) this.send('get_file_permissions', { path: this.target.path });
        }

        buildPermissionGrid() {
            const groups = [['owner', 'Owner'], ['group', 'Group'], ['others', 'Others']];
            for (const [groupIndex, [key, fallback]] of groups.entries()) {
                const row = document.createElement('div');
                const heading = document.createElement('span');
                heading.textContent = this.manager.t(`fm.permission.${key}`, fallback);
                row.appendChild(heading);
                for (const [bitIndex, permission] of ['read', 'write', 'execute'].entries()) {
                    const label = document.createElement('label');
                    const check = document.createElement('input');
                    check.type = 'checkbox';
                    check.dataset.bit = String(1 << (8 - groupIndex * 3 - bitIndex));
                    check.setAttribute('aria-label', `${heading.textContent}: ${this.manager.t(`fm.permission.${permission}`, permission)}`);
                    label.append(check, document.createTextNode(['r', 'w', 'x'][bitIndex]));
                    row.appendChild(label);
                    check.addEventListener('change', () => {
                        let mode = 0;
                        this.grid.querySelectorAll('input:checked').forEach(input => { mode |= Number(input.dataset.bit); });
                        this.mode.value = mode.toString(8).padStart(3, '0');
                        this.update();
                    });
                }
                this.grid.appendChild(row);
            }
        }

        isCurrent() {
            const state = this.manager.panes[this.target.pane];
            return this.manager.isOpen !== false && state === this.target.state
                && this.manager.getPaneSourceId(state) === this.target.sourceId && state.path === this.target.parent
                && (state.mutationViewVersion || 0) === this.target.version;
        }

        syncChecks() {
            const mode = validMode(this.mode.value) ? parseInt(this.mode.value, 8) : 0;
            this.grid.querySelectorAll('input').forEach(input => { input.checked = Boolean(mode & Number(input.dataset.bit)); });
        }

        update() {
            if (this.batch) {
                const ready = this.batchPhase === 'ready';
                this.button.disabled = !ready || this.pending || this.uncertain || !this.isCurrent()
                    || !validMode(this.mode.value) || this.targets.every(item => item.originalMode === this.mode.value);
                this.mode.disabled = !ready;
                this.grid.querySelectorAll('input').forEach(input => { input.disabled = !ready; });
                return;
            }
            this.button.disabled = this.pending || this.uncertain || !this.isCurrent()
                || (this.permissions ? !this.metadataToken || this.specialBits !== 0 || !validMode(this.mode.value) || this.mode.value === this.originalMode : !validLeaf(this.name.value));
            const locked = this.pending || this.uncertain || (this.permissions && (!this.metadataToken || this.specialBits !== 0));
            this.name.disabled = locked;
            this.mode.disabled = locked;
            this.grid.querySelectorAll('input').forEach(input => { input.disabled = locked; });
        }

        send(operation, fields) {
            if (this.pending || this.closed || !this.isCurrent() || this.manager.socket.connected === false) return;
            const id = this.manager.registerOperationRequest(this.target.sourceId, operation);
            this.manager.pendingOperationRequests.get(id).mutationDialog = this;
            this.pendingId = id;
            this.pending = true;
            this.update();
            this.timer = setTimeout(() => {
                this.manager.pendingOperationRequests.delete(id);
                this.pending = false;
                this.uncertain = true;
                if (this.batch) {
                    const item = this.targets[this.batchIndex];
                    this.uncertain = operation === 'set_file_permissions';
                    if (this.uncertain) {
                        item.outcome = 'unknown';
                        this.stopBatch('fm.mutationUnknown', 'Result unknown. Close this dialog and refresh before taking further action.');
                    } else {
                        if (this.batchPhase !== 'stopped') item.outcome = 'failed';
                        item.error = this.manager.t('fm.batchInspectionTimeout', 'Permissions inspection timed out. Reopen this dialog.');
                        this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
                    }
                    this.renderBatch();
                    this.refreshBatch();
                    return;
                }
                if (!this.closed) {
                    this.status.textContent = this.manager.t('fm.mutationUnknown', 'Result unknown. Close this dialog and refresh before taking further action.');
                    this.update();
                }
            }, 15000);
            this.manager.socket.emit(operation, { source_id: this.target.sourceId, request_id: id, ...fields });
        }

        submit() {
            this.update();
            if (this.button.disabled) return;
            if (this.batch) {
                const mode = parseInt(this.mode.value, 8);
                if (this.targets.some(item => {
                    const required = item.objectType === 'directory' ? 0o700 : 0o600;
                    return (mode & required) !== required;
                }) && !window.confirm(this.manager.t('fm.permissionLockout', 'This removes owner access. Apply these permissions?'))) return;
                this.applyMode = this.mode.value;
                this.batchPhase = 'applying';
                this.batchIndex = 0;
                this.advanceBatch();
                return;
            }
            if (this.permissions) {
                const mode = parseInt(this.mode.value, 8);
                const required = this.objectType === 'directory' ? 0o700 : 0o600;
                if ((mode & required) !== required && !window.confirm(this.manager.t('fm.permissionLockout', 'This removes owner access. Apply these permissions?'))) return;
                this.send('set_file_permissions', { path: this.target.path, mode: this.mode.value, expected_metadata: this.metadataToken });
            } else {
                this.editAfterCreate = this.dialog.querySelector('[name="edit"]').checked;
                this.createdName = this.name.value;
                this.send('create_file', { parent_path: this.target.parent, name: this.createdName });
            }
        }

        receive(data, operation, failed) {
            if (data.request_id !== this.pendingId) return;
            clearTimeout(this.timer);
            this.pending = false;
            if (this.batch) {
                this.receiveBatch(data, operation, failed);
                // A late GET can finish the last pending request after an earlier
                // write succeeded and the user closed or disconnected the batch.
                this.refreshBatch();
                return;
            }
            if (failed) {
                this.uncertain = ['OUTCOME_UNKNOWN', 'MODE_MISMATCH', 'METADATA_CHANGED'].includes(data.code);
                if (!this.closed) {
                    this.status.textContent = data.error;
                    if (data.code === 'MODE_MISMATCH' && validMode(data.actual_mode)) {
                        this.mode.value = data.actual_mode;
                        this.syncChecks();
                        this.status.textContent += ` ${this.manager.t('fm.octalMode', 'Octal permissions')}: ${data.actual_mode}`;
                    }
                    this.update();
                }
                return;
            }
            if (operation === 'get_file_permissions') {
                if (this.closed || !this.isCurrent()) return;
                this.originalMode = data.mode;
                this.specialBits = data.special_bits;
                this.objectType = data.object_type;
                this.metadataToken = data.metadata_token;
                this.mode.value = data.mode;
                this.syncChecks();
                this.status.textContent = this.specialBits ? this.manager.t('fm.specialPermissions', 'Special permission bits are present. Editing is unavailable.') : '';
                this.update();
                return;
            }
            const mayEdit = operation === 'create_file' && this.editAfterCreate && !this.closed && this.isCurrent();
            if (!this.closed) this.close();
            this.manager.showNotification(this.manager.t(operation === 'create_file' ? 'fm.fileCreated' : 'fm.permissionsChanged', operation === 'create_file' ? 'File created' : 'Permissions changed'), 'success');
            this.target.state.restoreFocusName = operation === 'create_file' ? this.createdName : null;
            this.manager.refreshSource(this.target.sourceId);
            if (mayEdit) window.FilePreview?.openForEditing?.(this.target.sourceId, data.path, this.createdName);
        }

        renderBatch() {
            if (!this.results || this.closed) return;
            this.results.replaceChildren(...this.targets.map(item => {
                const row = document.createElement('li');
                row.dataset.outcome = item.outcome;
                const labels = {
                    'in-flight': ['fm.batchPending', 'Pending'],
                    pending: ['fm.batchPending', 'Pending'], inspected: ['fm.batchInspected', 'Inspected'],
                    completed: ['fm.batchCompleted', 'Changed'], unchanged: ['fm.batchUnchanged', 'Already matches'],
                    failed: ['fm.batchFailed', 'Failed'], unknown: ['fm.batchUnknown', 'Result unknown'],
                    'not-sent': ['fm.batchNotSent', 'Not sent'],
                };
                const [key, fallback] = labels[item.outcome];
                row.textContent = `${item.name}: ${this.manager.t(key, fallback)}${item.error ? ` — ${item.error}` : ''}`;
                return row;
            }));
        }

        refreshBatch() {
            if (!this.pending && !this.batchRefreshed && this.batchStarted) {
                this.batchRefreshed = true;
                this.manager.refreshSource(this.target.sourceId);
            }
        }

        stopBatch(key, fallback) {
            if (this.batchPhase === 'stopped' || this.batchPhase === 'done') return;
            this.batchPhase = 'stopped';
            this.targets.forEach(item => {
                if (item.outcome === 'in-flight') item.outcome = 'unknown';
                else if (['pending', 'inspected'].includes(item.outcome)) item.outcome = 'not-sent';
            });
            if (!this.closed) this.status.textContent = this.manager.t(key, fallback);
            this.renderBatch();
            this.update();
            this.refreshBatch();
        }

        advanceBatch() {
            if (this.closed || !this.isCurrent() || this.manager.socket?.connected === false) {
                this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
                return;
            }
            if (!['inspecting', 'applying'].includes(this.batchPhase)) return;
            if (this.batchIndex === this.targets.length) {
                if (this.batchPhase === 'inspecting') {
                    this.batchPhase = 'ready';
                    const first = this.targets[0].originalMode;
                    this.mode.value = this.targets.every(item => item.originalMode === first) ? first : '';
                    this.syncChecks();
                    this.status.textContent = this.mode.value ? '' : this.manager.t('fm.batchMixedModes', 'Permissions differ. Enter a mode to apply to all selected items.');
                } else {
                    this.batchPhase = 'done';
                    this.status.textContent = this.manager.t('fm.batchFinished', 'Finished. Review the result for each item.');
                    this.refreshBatch();
                }
                this.renderBatch();
                this.update();
                return;
            }
            const item = this.targets[this.batchIndex];
            // Freshly inspect every target, including ones whose mode already matched.
            this.send('get_file_permissions', { path: item.path });
            this.renderBatch();
            this.update();
        }

        receiveBatch(data, operation, failed) {
            const item = this.targets[this.batchIndex];
            if (!item) return;
            if (failed) {
                item.outcome = ['OUTCOME_UNKNOWN', 'MODE_MISMATCH'].includes(data.code) ? 'unknown' : 'failed';
                item.error = data.error;
                if (data.code === 'MODE_MISMATCH' && validMode(data.actual_mode)) item.error += ` (${data.actual_mode})`;
                this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
                this.renderBatch();
                this.refreshBatch();
                return;
            }
            if (operation === 'get_file_permissions') {
                if (this.closed || !this.isCurrent() || this.manager.socket?.connected === false) {
                    this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
                    return;
                }
                if (!['inspecting', 'applying'].includes(this.batchPhase)) return;
                const fingerprint = metadataFingerprint(data.metadata_token);
                if (!fingerprint || (this.batchPhase === 'applying' && fingerprint !== item.metadataFingerprint)) {
                    item.outcome = 'failed';
                    item.error = this.manager.t('fm.batchMetadataChanged', 'The file metadata changed. Reopen the permissions dialog.');
                    this.stopBatch('fm.batchMetadataChanged', 'The file metadata changed. Reopen the permissions dialog.');
                    return;
                }
                if (!validMode(data.mode) || data.special_bits !== 0 || !['file', 'directory'].includes(data.object_type)) {
                    item.outcome = 'failed';
                    item.error = this.manager.t('fm.specialPermissions', 'Special permission bits are present. Editing is unavailable.');
                    this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
                    return;
                }
                if (this.batchPhase === 'inspecting') {
                    Object.assign(item, { originalMode: data.mode, objectType: data.object_type,
                        metadataToken: data.metadata_token, metadataFingerprint: fingerprint, outcome: 'inspected' });
                } else if (data.mode === this.applyMode) {
                    item.outcome = 'unchanged';
                } else {
                    this.batchStarted = true;
                    item.outcome = 'in-flight';
                    this.send('set_file_permissions', { path: item.path, mode: this.applyMode, expected_metadata: data.metadata_token });
                    this.renderBatch();
                    this.update();
                    return;
                }
            } else {
                item.outcome = 'completed';
            }
            this.renderBatch();
            if (this.batchPhase === 'stopped') { this.refreshBatch(); return; }
            this.batchIndex++;
            this.advanceBatch();
        }

        close() {
            if (this.closed) return;
            if (this.batch) this.stopBatch('fm.batchStopped', 'Stopped. Remaining items were not sent.');
            this.closed = true;
            this.manager.socket.off?.('disconnect', this.onDisconnect);
            this.dialog.close();
            this.dialog.remove();
            this.trigger?.isConnected && this.trigger.focus();
            if (this.manager.mutationDialog === this) this.manager.mutationDialog = null;
        }

        static handle(manager, data, operation, failed = false) {
            const pending = manager.pendingOperationRequests?.get(data?.request_id);
            if (!pending?.mutationDialog || pending.sourceId !== data.source_id || pending.operation !== operation) return false;
            manager.consumeOperationResponse(data, operation);
            pending.mutationDialog.receive(data, operation, failed);
            return true;
        }
    }

    window.FileMutationDialog = FileMutationDialog;
    if (typeof module !== 'undefined') module.exports = { validLeaf, validMode, FileMutationDialog };
})();
