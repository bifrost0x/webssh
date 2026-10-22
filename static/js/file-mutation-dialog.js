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

    class FileMutationDialog {
        constructor(manager, pane, file = null) {
            this.manager = manager;
            const state = manager.panes[pane];
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
            if (this.permissions) this.send('get_file_permissions', { path: this.target.path });
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

        close() {
            if (this.closed) return;
            this.closed = true;
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
