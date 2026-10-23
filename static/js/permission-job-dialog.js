/* Immutable, server-owned permission plans bound to the visible source. */
(() => {
    'use strict';
    const validMode = value => typeof value === 'string' && /^[0-7]{3}$/u.test(value);
    const dangerousModes = (file, directory) => validMode(file) && validMode(directory)
        && ((parseInt(file, 8) & 0o600) !== 0o600 || (parseInt(directory, 8) & 0o700) !== 0o700);
    function initialModes(files) {
        const modes = { file: '644', directory: '755' };
        if (files.length === 1 && Number.isSafeInteger(files[0].mode) && files[0].mode >= 0 && files[0].mode <= 0xffff) modes[files[0].is_dir ? 'directory' : 'file'] = (files[0].mode & 0o777).toString(8).padStart(3, '0');
        return modes;
    }
    const activeStates = new Set(['scanning', 'running']);
    const terminalStates = new Set(['completed', 'cancelled', 'failed']);

    class PermissionJobDialog {
        constructor(manager, pane, files) {
            this.manager = manager;
            const state = manager.panes[pane];
            this.target = Object.freeze({ pane, state, sourceId: manager.getPaneSourceId(state), parent: state.path, version: state.mutationViewVersion || 0 });
            this.paths = Object.freeze(files.map(file => manager.joinPath(state.path, file.name)));
            this.state = 'editing';
            this.closed = false;
            this.pending = false;
            this.trigger = document.activeElement;
            this.dialog = document.createElement('dialog');
            this.dialog.className = 'fm-permission-job-dialog';
            this.dialog.setAttribute('aria-labelledby', 'fmPermissionJobTitle');
            this.dialog.innerHTML = `<form novalidate><header><h3 id="fmPermissionJobTitle"></h3><p class="fm-job-target"></p></header>
                <div class="fm-job-modes"></div>
                <label class="fm-job-recursion"><input name="recursive" type="checkbox"><span></span></label>
                <p class="fm-job-hint"></p><section class="fm-job-preview" hidden><h4></h4><p class="fm-job-counts"></p><p class="fm-job-plan"></p><p class="fm-job-current"></p></section>
                <label class="fm-job-ack" hidden><input name="acknowledge" type="checkbox"><span></span></label>
                <p class="fm-job-status" role="status" aria-live="polite"></p><progress hidden></progress>
                <p class="fm-job-partial"></p><footer><button type="button" class="btn btn-secondary" data-close></button><button type="button" class="btn btn-secondary" data-stop hidden></button><button type="button" class="btn btn-secondary" data-edit hidden></button><button type="submit" class="btn btn-primary"></button></footer></form>`;
            this.text('h3', 'fm.permissions', 'Permissions');
            this.dialog.querySelector('.fm-job-target').textContent = `${state.source?.label || this.target.sourceId}\n${state.path}\n${files.length} ${this.t('fm.selectedItems', 'selected items')}`;
            this.text('.fm-job-recursion span', 'fm.jobRecursive', 'Include contents of selected folders (recursive)');
            this.text('.fm-job-hint', 'fm.jobHint', 'Recursion is off by default. Symbolic links are skipped. Folder execute permission means entering the folder. Unix mode does not show all ACLs.');
            this.text('.fm-job-preview h4', 'fm.jobPreview', 'Review permission changes');
            this.text('.fm-job-ack span', 'fm.jobLockout', 'I understand that these permissions can prevent me from reading, editing or entering these items.');
            this.text('.fm-job-partial', 'fm.jobPartial', 'Cancellation stops remaining work. Changes already completed remain; this operation cannot roll them back.');
            this.text('[data-close]', 'common.cancel', 'Cancel');
            this.text('[data-stop]', 'fm.jobStop', 'Stop remaining work');
            this.text('[data-edit]', 'fm.jobEdit', 'Change settings');
            this.recursive = this.dialog.querySelector('[name="recursive"]');
            this.acknowledgment = this.dialog.querySelector('[name="acknowledge"]');
            this.status = this.dialog.querySelector('[role="status"]');
            this.button = this.dialog.querySelector('[type="submit"]');
            this.stopButton = this.dialog.querySelector('[data-stop]');
            this.editButton = this.dialog.querySelector('[data-edit]');
            this.modeInputs = {};
            const modes = initialModes(files);
            this.buildMode('file', modes.file, 'fm.jobFiles', 'Files');
            this.buildMode('directory', modes.directory, 'fm.jobDirectories', 'Folders');
            this.dialog.querySelector('form').addEventListener('submit', event => { event.preventDefault(); this.state === 'ready' ? this.apply() : this.prepare(); });
            this.dialog.querySelector('[data-close]').addEventListener('click', () => this.close());
            this.stopButton.addEventListener('click', () => this.stop());
            this.editButton.addEventListener('click', () => this.edit());
            this.acknowledgment.addEventListener('change', () => this.update());
            this.dialog.addEventListener('keydown', event => event.stopPropagation());
            this.dialog.addEventListener('cancel', event => { event.preventDefault(); this.close(); });
            this.dialog.addEventListener('close', () => this.close());
            this.onDisconnect = () => { this.disconnected = true; this.state = 'unknown'; this.pending = false; this.status.textContent = this.t('fm.jobDisconnected', 'Connection lost. The final result is unknown. Refresh before another change.'); this.update(); };
            manager.socket.on?.('disconnect', this.onDisconnect);
            document.body.appendChild(this.dialog);
            this.dialog.showModal();
            this.modeInputs.file.focus();
            this.monitor = setInterval(() => {
                if (!this.isCurrent()) { this.close(); return; }
                this.expire();
                if (this.jobId && activeStates.has(this.state) && !this.pending) this.send('get_file_permissions_job', { job_id: this.jobId });
            }, 1000);
            this.update();
        }

        t(key, fallback) { return this.manager.t(key, fallback); }
        text(selector, key, fallback) { this.dialog.querySelector(selector).textContent = this.t(key, fallback); }
        buildMode(kind, value, key, fallback) {
            const fieldset = document.createElement('fieldset');
            fieldset.dataset.modeKind = kind;
            const legend = document.createElement('legend');
            legend.textContent = this.t(key, fallback);
            const label = document.createElement('label');
            label.className = 'fm-job-octal';
            label.append(document.createTextNode(this.t('fm.octalMode', 'Octal permissions')));
            const input = document.createElement('input');
            Object.assign(input, { name: `${kind}_mode`, value, inputMode: 'numeric', maxLength: 3, autocomplete: 'off' });
            input.pattern = '[0-7]{3}';
            label.appendChild(input);
            fieldset.append(legend, label);
            const grid = document.createElement('div');
            grid.className = 'fm-job-grid';
            for (const [groupIndex, [group, title]] of [['owner', 'Owner'], ['group', 'Group'], ['others', 'Others']].entries()) {
                const heading = document.createElement('span');
                heading.textContent = this.t(`fm.permission.${group}`, title);
                grid.appendChild(heading);
                for (const [bitIndex, permission] of ['read', 'write', 'execute'].entries()) {
                    const checkLabel = document.createElement('label');
                    const check = document.createElement('input');
                    check.type = 'checkbox';
                    check.dataset.bit = String(1 << (8 - groupIndex * 3 - bitIndex));
                    check.setAttribute('aria-label', `${legend.textContent}: ${heading.textContent}: ${this.t(`fm.permission.${permission}`, permission)}`);
                    checkLabel.append(check, document.createTextNode(['r', 'w', 'x'][bitIndex]));
                    grid.appendChild(checkLabel);
                    check.addEventListener('change', () => {
                        let mode = 0;
                        grid.querySelectorAll('input:checked').forEach(item => { mode |= Number(item.dataset.bit); });
                        input.value = mode.toString(8).padStart(3, '0');
                        this.update();
                    });
                }
            }
            const sync = () => { grid.querySelectorAll('input').forEach(check => { check.checked = validMode(input.value) && Boolean(parseInt(input.value, 8) & Number(check.dataset.bit)); }); this.update(); };
            input.addEventListener('input', sync);
            fieldset.appendChild(grid);
            this.dialog.querySelector('.fm-job-modes').appendChild(fieldset);
            this.modeInputs[kind] = input;
            sync();
        }

        isCurrent() {
            const state = this.manager.panes[this.target.pane];
            return this.manager.isOpen !== false && state === this.target.state && this.manager.getPaneSourceId(state) === this.target.sourceId
                && state.path === this.target.parent && (state.mutationViewVersion || 0) === this.target.version;
        }

        prepare() {
            if (this.state !== 'editing' || this.pending || this.manager.socket.connected === false || !this.isCurrent() || !validMode(this.modeInputs.file.value) || !validMode(this.modeInputs.directory.value)) return;
            this.plan = Object.freeze({ file_mode: this.modeInputs.file.value, directory_mode: this.modeInputs.directory.value, recursive: this.recursive.checked });
            this.state = 'scanning';
            this.status.textContent = this.t('fm.jobState.scanning', 'Scanning selected items...');
            this.send('prepare_file_permissions', { paths: [...this.paths], ...this.plan });
        }

        expire() {
            if (this.state !== 'ready' || !this.readyUntil || Date.now() < this.readyUntil) return;
            this.state = 'expired';
            this.status.textContent = this.t('fm.jobExpired', 'The preview expired. Close and create a new preview.');
            this.update();
        }

        needsAcknowledgment() {
            const files = this.counts ? this.counts.files > 0 : true;
            const directories = this.counts ? this.counts.directories > 0 : true;
            return dangerousModes(files ? this.plan.file_mode : '600', directories ? this.plan.directory_mode : '700');
        }

        apply() {
            this.expire();
            if (this.state !== 'ready' || this.pending || this.closed || this.manager?.socket?.connected === false || !this.isCurrent() || (this.needsAcknowledgment() && !this.acknowledgment.checked)) return;
            this.state = 'running';
            this.status.textContent = this.t('fm.jobState.running', 'Applying permissions...');
            this.send('apply_file_permissions_job', { job_id: this.jobId });
        }

        stop() {
            if (!activeStates.has(this.state) || this.pending || !this.jobId || this.closed) return;
            this.send('cancel_file_permissions_job', { job_id: this.jobId });
        }

        edit() {
            if (this.state !== 'ready' || this.pending) return;
            this.restarting = true;
            this.send('cancel_file_permissions_job', { job_id: this.jobId });
        }

        send(operation, fields) {
            if (this.pending || this.closed || !this.isCurrent() || this.manager.socket.connected === false) return;
            const id = this.manager.registerOperationRequest(this.target.sourceId, operation);
            this.manager.pendingOperationRequests.get(id).permissionJobDialog = this;
            this.pendingId = id;
            this.pending = true;
            this.timer = setTimeout(() => {
                this.manager.pendingOperationRequests.delete(id);
                this.pendingId = null;
                this.pending = false;
                this.state = 'unknown';
                this.status.textContent = this.t('fm.jobTimeout', 'No confirmed response. Close and refresh before another change.');
                this.update();
            }, 20000);
            this.manager.socket.emit(operation, { source_id: this.target.sourceId, request_id: id, ...fields });
            this.update();
        }

        receive(data, failed = false) {
            clearTimeout(this.timer);
            this.pending = false;
            this.pendingId = null;
            if (typeof data.job_id === 'string') {
                if (this.jobId && this.jobId !== data.job_id) return;
                this.jobId = data.job_id;
            }
            if (this.closed || !this.isCurrent()) {
                if ((Number.isSafeInteger(data.changed) && data.changed > 0) || data.state === 'completed' || ['OUTCOME_UNKNOWN', 'MODE_MISMATCH'].includes(data.code)) this.refreshBoundSource();
                this.cancelOwnedJob();
                return;
            }
            if (this.disconnected) return;
            if (failed) {
                this.state = 'failed';
                this.status.textContent = typeof data.error === 'string' ? data.error : this.t('fm.jobFailed', 'Permission operation failed. Refresh before another change.');
            } else if (activeStates.has(data.state) || terminalStates.has(data.state) || data.state === 'ready') {
                if (data.state === 'ready' && this.state !== 'ready') this.readyUntil = Date.now() + Math.min(120, typeof data.expires_in === 'number' && Number.isFinite(data.expires_in) ? Math.max(0, data.expires_in) : 120) * 1000;
                this.state = data.state;
                this.counts = data;
                this.renderCounts();
                this.status.textContent = typeof data.error === 'string' && data.error ? data.error : this.t(`fm.jobState.${this.state}`, this.state);
                if (this.restarting && terminalStates.has(this.state)) {
                    this.restarting = false;
                    this.jobId = null;
                    this.state = 'editing';
                    this.acknowledgment.checked = false;
                    this.dialog.querySelector('.fm-job-preview').hidden = true;
                }
            } else {
                this.state = 'unknown';
                this.status.textContent = this.t('fm.jobFailed', 'Permission operation failed. Refresh before another change.');
            }
            if (terminalStates.has(this.state)) this.refreshBoundSource();
            this.update();
        }

        refreshBoundSource() {
            if (this.refreshed) return;
            this.refreshed = true;
            this.manager.refreshSource?.(this.target.sourceId);
        }

        renderCounts() {
            const number = key => Number.isSafeInteger(this.counts[key]) && this.counts[key] >= 0 ? this.counts[key] : 0;
            this.dialog.querySelector('.fm-job-preview').hidden = false;
            this.dialog.querySelector('.fm-job-counts').textContent = `${this.t('fm.jobFiles', 'Files')}: ${number('files')} · ${this.t('fm.jobDirectories', 'Folders')}: ${number('directories')} · ${this.t('fm.jobSkipped', 'Skipped links')}: ${number('skipped')} · ${this.t('fm.jobChanged', 'Changed')}: ${number('changed')} / ${number('total')}`;
            this.dialog.querySelector('.fm-job-plan').textContent = `${this.t('fm.jobFiles', 'Files')}: ${this.plan.file_mode} · ${this.t('fm.jobDirectories', 'Folders')}: ${this.plan.directory_mode} · ${this.t(this.plan.recursive ? 'fm.jobRecursiveOn' : 'fm.jobRecursiveOff', this.plan.recursive ? 'Including folder contents' : 'Selected items only')}`;
            const modes = data => data && typeof data === 'object' ? Object.entries(data).filter(([mode, count]) => validMode(mode) && Number.isSafeInteger(count) && count > 0).map(([mode, count]) => `${mode} × ${count}`).join(', ') : '';
            const current = this.counts.current_modes;
            this.dialog.querySelector('.fm-job-current').textContent = current ? `${this.t('fm.jobCurrent', 'Current permissions')}: ${this.t('fm.jobFiles', 'Files')} ${modes(current.files) || '—'} · ${this.t('fm.jobDirectories', 'Folders')} ${modes(current.directories) || '—'}` : '';
            const progress = this.dialog.querySelector('progress');
            progress.hidden = this.state !== 'running';
            progress.max = Math.max(1, number('total'));
            progress.value = Math.min(number('processed'), progress.max);
        }

        update() {
            if (!this.modeInputs?.directory) return;
            const editing = this.state === 'editing';
            this.dialog.dataset.phase = editing ? 'editing' : 'review';
            this.dialog.querySelectorAll('.fm-job-modes input').forEach(input => { input.disabled = !editing; });
            this.recursive.disabled = !editing;
            const danger = this.plan && this.needsAcknowledgment();
            this.dialog.querySelector('.fm-job-ack').hidden = this.state !== 'ready' || !danger;
            this.stopButton.hidden = !activeStates.has(this.state);
            this.stopButton.disabled = this.pending || !this.jobId;
            this.editButton.hidden = this.state !== 'ready';
            this.editButton.disabled = this.pending;
            this.button.textContent = this.t(this.state === 'ready' ? 'fm.applyPermissions' : 'fm.jobPrepare', this.state === 'ready' ? 'Apply permissions' : 'Preview changes');
            this.button.disabled = this.pending || !this.isCurrent() || (editing ? !validMode(this.modeInputs.file.value) || !validMode(this.modeInputs.directory.value) : this.state !== 'ready' || (danger && !this.acknowledgment.checked));
        }

        cancelOwnedJob() {
            if (!this.jobId || this.cancelSent || terminalStates.has(this.state) || this.manager.socket.connected === false) return;
            this.cancelSent = true;
            this.manager.socket.emit('cancel_file_permissions_job', { source_id: this.target.sourceId, request_id: this.manager.nextRequestId('workspace', 'cancel_file_permissions_job'), job_id: this.jobId });
        }

        close() {
            if (this.closed) return;
            this.closed = true;
            this.cancelOwnedJob();
            clearInterval(this.monitor);
            this.manager.socket.off?.('disconnect', this.onDisconnect);
            if (!this.pending) clearTimeout(this.timer);
            this.dialog.close();
            this.dialog.remove();
            if (this.manager.mutationDialog === this) this.manager.mutationDialog = null;
            this.trigger?.focus?.();
        }

        static handle(manager, data, failed = false) {
            const pending = manager.pendingOperationRequests?.get(data?.request_id);
            if (!pending?.permissionJobDialog || pending.sourceId !== data.source_id || pending.operation !== data.operation) return false;
            manager.consumeOperationResponse(data, pending.operation);
            pending.permissionJobDialog.receive(data, failed);
            return true;
        }
    }
    window.PermissionJobDialog = PermissionJobDialog;
    if (typeof module !== 'undefined' && module.exports) module.exports = { PermissionJobDialog, validMode, dangerousModes, initialModes };
})();
