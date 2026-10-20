(function () {
    'use strict';
    const t = (key) => window.i18n?.t(key) || key;
    const element = (tag, text, className) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    };
    const api = async (path, body) => {
        const root = document.querySelector('meta[name="app-root"]')?.content || '';
        const response = await fetch(root + path, {
            method: body ? 'POST' : 'GET',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
            },
            ...(body ? {body: JSON.stringify(body)} : {})
        });
        if (response.ok && response.headers.get('Content-Type')?.includes('application/zip')) {
            return response.blob();
        }
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || t('exchange.failed'));
        return data;
    };
    function download(documentData) {
        const archive = documentData instanceof Blob;
        const url = URL.createObjectURL(archive ? documentData : new Blob([JSON.stringify(documentData)], {type: 'application/json'}));
        const link = element('a');
        link.href = url;
        link.download = archive ? 'webssh-hosts.zip' : 'webssh-hosts.json';
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    function openImport() {
        const modal = element('div', undefined, 'modal');
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-label', t('exchange.import'));
        const content = element('div', undefined, 'modal-content');
        const heading = element('div', undefined, 'modal-header');
        heading.append(element('h2', t('exchange.import')));
        const close = element('button', 'close', 'close material-icons');
        close.type = 'button';
        close.setAttribute('aria-label', t('exchange.close'));
        heading.append(close);
        const body = element('div', undefined, 'modal-body');
        body.append(element('p', t('exchange.hint')));
        const format = element('select', undefined, 'form-control');
        format.setAttribute('aria-label', t('exchange.format'));
        for (const [value, name] of [['openssh', 'OpenSSH config'], ['json', 'WebSSH JSON']]) {
            const option = element('option', name);
            option.value = value;
            format.append(option);
        }
        const source = element('textarea', undefined, 'form-control');
        source.rows = 8;
        source.maxLength = 65536;
        source.spellcheck = false;
        source.setAttribute('aria-label', t('exchange.source'));
        const file = element('input', undefined, 'form-control');
        file.type = 'file';
        file.setAttribute('aria-label', t('exchange.file'));
        const status = element('p');
        status.setAttribute('role', 'status');
        const preview = element('button', t('exchange.preview'), 'btn btn-secondary');
        const submit = element('button', t('exchange.selected'), 'btn btn-primary');
        submit.disabled = true;
        const rows = element('div');
        const actions = element('div', undefined, 'form-actions');
        actions.append(preview, submit);
        body.append(format, file, source, status, rows, actions);
        content.append(heading, body);
        modal.append(content);
        document.body.append(modal);
        let generation = 0;
        let busy = false;
        let snapshot = null;
        let controls = [];
        const invalidate = () => {
            generation++;
            snapshot = null;
            controls = [];
            submit.disabled = true;
            rows.replaceChildren();
        };
        const dismiss = () => {
            generation++;
            window.ModalManager.close(modal);
            modal.remove();
            document.removeEventListener('keydown', escape, true);
        };
        const escape = (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                event.stopImmediatePropagation();
                dismiss();
            }
        };
        close.addEventListener('click', dismiss);
        document.addEventListener('keydown', escape, true);
        source.addEventListener('input', invalidate);
        format.addEventListener('change', invalidate);
        file.addEventListener('change', async () => {
            invalidate();
            const selected = file.files[0];
            if (!selected) return;
            if (selected.size > 65536) { status.textContent = t('exchange.size'); return; }
            const current = generation;
            const text = await selected.text();
            if (current === generation && modal.isConnected) source.value = text;
        });
        function mapping(labelText, items, optional) {
            const label = element('label', labelText);
            const select = element('select', undefined, 'form-control');
            const empty = element('option', optional ? t('exchange.password') : t('exchange.choose'));
            empty.value = '';
            select.append(empty);
            for (const item of items) {
                const option = element('option', item.name);
                option.value = item.id;
                select.append(option);
            }
            label.append(select);
            return {label, select};
        }
        preview.addEventListener('click', async () => {
            if (busy) return;
            invalidate();
            const current = generation;
            const request = {source: source.value, format: format.value};
            busy = true;
            preview.disabled = true;
            status.textContent = t('exchange.loading');
            try {
                const result = await api('/api/profiles/exchange/preview', request);
                if (current !== generation || !modal.isConnected) return;
                snapshot = request;
                status.textContent = result.warnings.join('\n') || t('exchange.review');
                controls = result.records.map((row, index) => {
                    const section = element('fieldset');
                    const selectLabel = element('label');
                    const selected = element('input');
                    selected.type = 'checkbox';
                    selected.disabled = row.blocked;
                    selected.checked = !row.blocked;
                    selectLabel.append(selected, document.createTextNode(` ${row.name}: ${row.username || '?'}@${row.host}:${row.port}`));
                    section.append(selectLabel, element('p', row.warnings.join(' ')));
                    const userLabel = element('label', t('exchange.username'));
                    const username = element('input', undefined, 'form-control');
                    username.value = row.username;
                    username.maxLength = 128;
                    userLabel.append(username);
                    const key = mapping(t('exchange.key'), result.keys || [], !row.requires_key);
                    const jump = mapping(`${t('exchange.jump')} ${row.jump_alias || ''}`, result.jump_hosts || [], !row.requires_jump);
                    if (row.auth_type === 'tailscale') {
                        key.select.disabled = true;
                        jump.select.disabled = true;
                        section.append(element('p', 'Tailscale SSH'));
                    }
                    section.append(userLabel, key.label, jump.label);
                    rows.append(section);
                    return {index, selected, username, key: key.select, jump: jump.select};
                });
                submit.disabled = !controls.some(item => !item.selected.disabled);
            } catch (error) {
                if (current === generation) status.textContent = error.message || t('exchange.failed');
            } finally {
                busy = false;
                preview.disabled = false;
            }
        });
        submit.addEventListener('click', async () => {
            if (busy || !snapshot) return;
            const current = generation;
            const selections = controls.filter(item => item.selected.checked && !item.selected.disabled).map(item => ({
                index: item.index, username: item.username.value, key_id: item.key.value, jump_host_id: item.jump.value
            }));
            if (!selections.length) return;
            busy = true;
            submit.disabled = true;
            preview.disabled = true;
            try {
                const result = await api('/api/profiles/exchange', {...snapshot, selections});
                window.socket?.emit('list_profiles');
                if (current !== generation || !modal.isConnected) return;
                status.textContent = result.results.map(item =>
                    `${item.index + 1}: ${t(`exchange.${item.status}`)}${item.error ? ` (${item.error})` : ''}`
                ).join('\n');
            } catch (error) {
                if (current === generation) status.textContent = error.message || t('exchange.failed');
            } finally {
                busy = false;
                preview.disabled = false;
                // Refresh the preview before another submission, including uncertain results.
                snapshot = null;
                submit.disabled = true;
            }
        });
        window.ModalManager.open(modal);
    }
    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('importProfilesBtn')?.addEventListener('click', openImport);
        document.getElementById('exportProfilesBtn')?.addEventListener('click', async event => {
            const button = event.currentTarget;
            button.disabled = true;
            try { download(await api('/api/profiles/exchange')); }
            catch { window.showNotification?.(t('exchange.failed'), 'error'); }
            finally { button.disabled = false; }
        });
    });
})();
